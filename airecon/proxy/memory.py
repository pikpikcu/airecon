import json
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("airecon.memory")

MEMORY_DIR = Path.home() / ".airecon" / "memory"
MEMORY_DB = MEMORY_DIR / "airecon.db"

_VALID_JOURNAL_MODES = {"WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"}
_VALID_SYNCHRONOUS = {"OFF", "NORMAL", "FULL", "EXTRA"}


def _coerce_float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _coerce_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


_DB_TIMEOUT_SECONDS = _coerce_float_env("AIRECON_DB_TIMEOUT_SECONDS", 10.0)
_DB_BUSY_TIMEOUT_MS = _coerce_int_env("AIRECON_DB_BUSY_TIMEOUT_MS", 5000)
_DB_JOURNAL_MODE = os.getenv("AIRECON_DB_JOURNAL_MODE", "WAL").upper()
_DB_SYNCHRONOUS = os.getenv("AIRECON_DB_SYNCHRONOUS", "NORMAL").upper()


_MEMORY_CONN: sqlite3.Connection | None = None
_MEMORY_CONN_LOCK = threading.Lock()


def get_sqlite_timeout_seconds() -> float:
    return _DB_TIMEOUT_SECONDS


def configure_sqlite_connection(conn: sqlite3.Connection) -> None:
    journal = _DB_JOURNAL_MODE if _DB_JOURNAL_MODE in _VALID_JOURNAL_MODES else "WAL"
    synchronous = (
        _DB_SYNCHRONOUS if _DB_SYNCHRONOUS in _VALID_SYNCHRONOUS else "NORMAL"
    )
    try:
        conn.execute(f"PRAGMA journal_mode={journal}")
    except sqlite3.Error as exc:
        logger.debug("SQLite journal_mode pragma failed: %s", exc)
    try:
        conn.execute(f"PRAGMA synchronous={synchronous}")
    except sqlite3.Error as exc:
        logger.debug("SQLite synchronous pragma failed: %s", exc)
    try:
        conn.execute(f"PRAGMA busy_timeout={_DB_BUSY_TIMEOUT_MS}")
    except sqlite3.Error as exc:
        logger.debug("SQLite busy_timeout pragma failed: %s", exc)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
    except sqlite3.Error as exc:
        logger.debug("SQLite foreign_keys pragma failed: %s", exc)


def get_memory_db() -> sqlite3.Connection:
    global _MEMORY_CONN
    if _MEMORY_CONN is not None:
        try:
            _MEMORY_CONN.execute("SELECT 1")
            return _MEMORY_CONN
        except sqlite3.Error:
            _MEMORY_CONN = None

    with _MEMORY_CONN_LOCK:
        if _MEMORY_CONN is not None:
            return _MEMORY_CONN

        if not MEMORY_DIR.exists():
            MEMORY_DIR.mkdir(parents=True, exist_ok=True)
            logger.info("Created memory directory: %s", MEMORY_DIR)

        db_exists = MEMORY_DB.exists()

        conn = sqlite3.connect(
            str(MEMORY_DB),
            check_same_thread=False,
            timeout=_DB_TIMEOUT_SECONDS,
        )
        conn.row_factory = sqlite3.Row
        configure_sqlite_connection(conn)

        if not db_exists:
            logger.info("Created new memory database: %s", MEMORY_DB)
            _init_schema(conn)
        else:
            _init_schema(conn)

        _MEMORY_CONN = conn
        return conn


def _tool_usage_row_get(row: sqlite3.Row | dict[str, Any], key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        if isinstance(row, dict):
            return row.get(key, default)
        return default


def _tool_usage_total(row: sqlite3.Row | dict[str, Any]) -> int:
    return int(_tool_usage_row_get(row, "success_count", 0) or 0) + int(
        _tool_usage_row_get(row, "failure_count", 0) or 0
    )


def rollup_tool_usage_rows(rows: list[sqlite3.Row | dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse per-target tool rows into one cross-session stat row per tool.

    If a global aggregate row exists (`target=''` or NULL), prefer it over
    summing target-scoped rows. This avoids double-counting when adaptive
    learning syncs an aggregate snapshot back into SQLite.
    """
    grouped: dict[str, list[sqlite3.Row | dict[str, Any]]] = {}
    for row in rows:
        tool_name = str(_tool_usage_row_get(row, "tool_name", "") or "").strip()
        if not tool_name:
            continue
        grouped.setdefault(tool_name, []).append(row)

    rolled: list[dict[str, Any]] = []
    for tool_name, tool_rows in grouped.items():
        global_rows = [
            row for row in tool_rows if not str(_tool_usage_row_get(row, "target", "") or "").strip()
        ]
        if global_rows:
            chosen = max(
                global_rows,
                key=lambda row: (
                    _tool_usage_total(row),
                    str(_tool_usage_row_get(row, "last_used", "") or ""),
                    int(_tool_usage_row_get(row, "id", 0) or 0),
                ),
            )
            success_count = int(_tool_usage_row_get(chosen, "success_count", 0) or 0)
            failure_count = int(_tool_usage_row_get(chosen, "failure_count", 0) or 0)
            avg_duration = float(_tool_usage_row_get(chosen, "avg_duration_sec", 0.0) or 0.0)
            typical_output_size = int(
                _tool_usage_row_get(chosen, "typical_output_size", 0) or 0
            )
            last_used = str(_tool_usage_row_get(chosen, "last_used", "") or "")
        else:
            success_count = sum(
                int(_tool_usage_row_get(row, "success_count", 0) or 0) for row in tool_rows
            )
            failure_count = sum(
                int(_tool_usage_row_get(row, "failure_count", 0) or 0) for row in tool_rows
            )
            total_calls = max(success_count + failure_count, 1)
            weighted_duration = sum(
                float(_tool_usage_row_get(row, "avg_duration_sec", 0.0) or 0.0)
                * max(_tool_usage_total(row), 1)
                for row in tool_rows
            )
            avg_duration = weighted_duration / total_calls
            typical_output_size = max(
                int(_tool_usage_row_get(row, "typical_output_size", 0) or 0)
                for row in tool_rows
            )
            last_used = max(str(_tool_usage_row_get(row, "last_used", "") or "") for row in tool_rows)

        total_calls = success_count + failure_count
        rolled.append(
            {
                "tool_name": tool_name,
                "success_count": success_count,
                "failure_count": failure_count,
                "avg_duration_sec": avg_duration,
                "typical_output_size": typical_output_size,
                "last_used": last_used,
                "total_calls": total_calls,
                "success_rate": round(success_count / max(total_calls, 1), 2),
            }
        )

    rolled.sort(key=lambda row: str(row.get("last_used", "")), reverse=True)
    return rolled


def _init_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            phase TEXT DEFAULT 'RECON',
            subdomains_count INTEGER DEFAULT 0,
            live_hosts_count INTEGER DEFAULT 0,
            vulnerabilities_count INTEGER DEFAULT 0,
            attack_chains_count INTEGER DEFAULT 0,
            token_total INTEGER DEFAULT 0,
            model_used TEXT,
            status TEXT DEFAULT 'completed'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            target TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            url TEXT,
            parameter TEXT,
            description TEXT,
            evidence TEXT,
            cwe_id TEXT,
            cvss_score REAL,
            remediation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT NOT NULL,  -- 'recon' or 'exploit'
            target_tech TEXT,
            technique_name TEXT NOT NULL,  -- Specific technique name
            description TEXT NOT NULL,
            success_rate REAL DEFAULT 0.0,  -- Must be >= 0.70 to be saved
            times_used INTEGER DEFAULT 1,
            times_successful INTEGER DEFAULT 1,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            payload_template TEXT,
            commands_used TEXT,  -- JSON array of actual commands
            prerequisites TEXT,  -- JSON array of required conditions
            detection_evasion TEXT,  -- Notes on avoiding detection
            effectiveness_score REAL DEFAULT 0.0,  -- 0-100 scale
            notes TEXT,
            source_session TEXT,
            validated INTEGER DEFAULT 0  -- 1 = validated by human, 0 = auto-learned
        )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_patterns_success_rate ON patterns(success_rate DESC)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_patterns_effectiveness ON patterns(effectiveness_score DESC)"
    )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_domain TEXT NOT NULL UNIQUE,
            subdomains TEXT,  -- JSON array
            open_ports TEXT,  -- JSON object {port: service}
            technologies TEXT,  -- JSON object {tech: version}
            waf_detected TEXT,
            auth_methods TEXT,  -- JSON array
            interesting_endpoints TEXT,  -- JSON array
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scan_count INTEGER DEFAULT 1
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            source_session TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT  -- JSON array
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chain_discoveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id TEXT NOT NULL,
            name TEXT NOT NULL,
            combined_severity INTEGER DEFAULT 1,
            attack_path TEXT,
            reasoning TEXT,
            findings TEXT,  -- JSON array of finding IDs
            relation_types TEXT,  -- JSON array of relationship types
            target TEXT DEFAULT '',
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_chain_severity ON chain_discoveries(combined_severity DESC)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_chain_target ON chain_discoveries(target)"
    )

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_patterns_type ON patterns(pattern_type)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(target_domain)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge(category)"
    )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            target TEXT,
            success_count INTEGER DEFAULT 0,
            failure_count INTEGER DEFAULT 0,
            avg_duration_sec REAL DEFAULT 0.0,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            typical_output_size INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL,
            task_type TEXT,
            avg_response_time_sec REAL DEFAULT 0.0,
            success_rate REAL DEFAULT 1.0,
            total_requests INTEGER DEFAULT 0,
            context_size_used INTEGER DEFAULT 0,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_tool_usage_name ON tool_usage(tool_name)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_model_performance_name ON model_performance(model_name)"
    )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS skill_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_name TEXT NOT NULL,
            target TEXT NOT NULL,
            phase TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            effectiveness_score REAL DEFAULT 0.0,
            tokens_saved INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_skill_usage_skill ON skill_usage(skill_name)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_skill_usage_target ON skill_usage(target)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_skill_usage_timestamp ON skill_usage(timestamp)"
    )

    conn.commit()
    logger.info("Memory database initialized at %s", MEMORY_DB)


class MemoryManager:
    def __init__(self):
        self.conn = None

    def connect(self) -> None:
        self.conn = get_memory_db()
        logger.debug("Memory manager connected")

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def save_session(self, session_data: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO sessions
            (session_id, target, updated_at, phase, subdomains_count,
             live_hosts_count, vulnerabilities_count, attack_chains_count,
             token_total, model_used)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                session_data.get("session_id"),
                session_data.get("target"),
                session_data.get("current_phase", "RECON"),
                len(session_data.get("subdomains", [])),
                len(session_data.get("live_hosts", [])),
                len(session_data.get("vulnerabilities", [])),
                len(session_data.get("attack_chains", [])),
                session_data.get("token_total", 0),
                session_data.get("model_used"),
            ),
        )
        self.conn.commit()

    def get_past_sessions(
        self, target: str | None = None, limit: int = 10
    ) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if target:
            cursor.execute(
                """
                SELECT * FROM sessions
                WHERE target LIKE ?
                ORDER BY updated_at DESC
                LIMIT ?
            """,
                (f"%{target}%", limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM sessions
                ORDER BY updated_at DESC
                LIMIT ?
            """,
                (limit,),
            )

        return [dict(row) for row in cursor.fetchall()]

    def save_finding(self, finding: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        session_id = str(finding.get("session_id") or "").strip()
        target = str(finding.get("target") or "").strip()
        if not session_id or not target:
            return
        cursor.execute(
            """
            INSERT OR IGNORE INTO sessions (session_id, target)
            VALUES (?, ?)
            """,
            (session_id, target),
        )
        cursor.execute(
            """
            INSERT INTO findings
            (session_id, target, finding_type, severity, url, parameter,
             description, evidence, cwe_id, cvss_score, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                session_id,
                target,
                finding.get("type", "vulnerability"),
                finding.get("severity", "Medium"),
                finding.get("url"),
                finding.get("parameter"),
                finding.get("description", ""),
                json.dumps(finding.get("evidence", [])),
                finding.get("cwe_id"),
                finding.get("cvss_score"),
                finding.get("remediation", ""),
            ),
        )
        self.conn.commit()

    def get_similar_findings(
        self, target: str, finding_type: str | None = None, limit: int = 20
    ) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if finding_type:
            cursor.execute(
                """
                SELECT * FROM findings
                WHERE (target = ? OR target LIKE ?) AND finding_type = ?
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (target, f"%.{target}", finding_type, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM findings
                WHERE target = ? OR target LIKE ?
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (target, f"%.{target}", limit),
            )

        findings = []
        for row in cursor.fetchall():
            finding = dict(row)

            if finding.get("evidence"):
                try:
                    finding["evidence"] = json.loads(finding["evidence"])
                except Exception as e:
                    logger.debug("Expected failure parsing evidence JSON: %s", e)
            findings.append(finding)

        return findings

    def save_pattern(self, pattern: dict[str, Any]) -> None:
        if not self.conn:
            return

        success_rate = float(pattern.get("success_rate", 0.0))
        if success_rate < 0.50:
            logger.debug(
                "Pattern rejected: success_rate %.2f < 0.50 threshold | %s",
                success_rate,
                pattern.get("technique_name", "unknown"),
            )
            return

        times_used = int(pattern.get("times_used", 0))
        if times_used < 2:
            logger.debug(
                "Pattern rejected: times_used %d < 2 minimum | %s",
                times_used,
                pattern.get("technique_name", "unknown"),
            )
            return

        technique_name = pattern.get("technique_name", "").strip()
        if not technique_name or len(technique_name) < 3:
            logger.debug("Pattern rejected: technique_name too short/generic")
            return

        #if not pattern.get("tech"):
        #    logger.debug("Pattern rejected: missing target tech")
        #    return

        description = pattern.get("description", "").strip()
        payload = pattern.get("payload_template", "").strip()
        commands = pattern.get("commands_used", [])
        if isinstance(commands, str):
            try:
                commands = json.loads(commands)
            except Exception:
                commands = [commands] if commands else []

        if not description and not payload and not commands:
            logger.debug("Pattern rejected: no actionable content")
            return

        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT id, times_used, times_successful FROM patterns
            WHERE technique_name = ? AND (target_tech = ? OR target_tech IS ?)
        """,
            (technique_name, pattern.get("tech"), pattern.get("tech")),
        )

        existing = cursor.fetchone()
        if existing:
            new_times_used = existing["times_used"] + times_used
            new_times_successful = existing["times_successful"] + int(
                times_used * success_rate
            )
            new_success_rate = new_times_successful / max(new_times_used, 1)

            cursor.execute(
                """
                UPDATE patterns SET
                    success_rate = ?, times_used = ?, times_successful = ?,
                    last_used = CURRENT_TIMESTAMP,
                    effectiveness_score = ?,
                    notes = COALESCE(?, notes),
                    source_session = ?
                WHERE id = ?
            """,
                (
                    new_success_rate,
                    new_times_used,
                    new_times_successful,
                    pattern.get("effectiveness_score", new_success_rate * 100),
                    pattern.get("notes"),
                    pattern.get("source_session"),
                    existing["id"],
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO patterns (
                    pattern_type, target_tech, technique_name, description,
                    success_rate, times_used, times_successful,
                    payload_template, commands_used, prerequisites,
                    detection_evasion, effectiveness_score, notes, source_session
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    pattern.get("type", "recon"),
                    pattern.get("tech"),
                    technique_name,
                    description,
                    success_rate,
                    times_used,
                    int(times_used * success_rate),
                    payload,
                    json.dumps(commands) if commands else None,
                    json.dumps(pattern.get("prerequisites", [])),
                    pattern.get("detection_evasion"),
                    pattern.get("effectiveness_score", success_rate * 100),
                    pattern.get("notes"),
                    pattern.get("source_session"),
                ),
            )

        self.conn.commit()
        logger.info(
            "✓ High-quality pattern saved: %s (success=%.0f%%, used=%dx)",
            technique_name,
            success_rate * 100,
            times_used,
        )

    def get_patterns(
        self,
        target_tech: str | None = None,
        limit: int = 20,
        min_success_rate: float = 0.50,
    ) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if target_tech:
            cursor.execute(
                """
                SELECT * FROM patterns
                WHERE (target_tech = ? OR target_tech IS NULL)
                  AND success_rate >= ?
                  AND times_used >= 2
                ORDER BY effectiveness_score DESC, success_rate DESC
                LIMIT ?
            """,
                (target_tech, min_success_rate, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM patterns
                WHERE success_rate >= ?
                  AND times_used >= 2
                ORDER BY effectiveness_score DESC, success_rate DESC
                LIMIT ?
            """,
                (min_success_rate, limit),
            )

        patterns = []
        for row in cursor.fetchall():
            pattern = dict(row)

            if pattern.get("commands_used"):
                try:
                    pattern["commands_used"] = json.loads(pattern["commands_used"])
                except Exception:
                    pattern["commands_used"] = []
            if pattern.get("prerequisites"):
                try:
                    pattern["prerequisites"] = json.loads(pattern["prerequisites"])
                except Exception:
                    pattern["prerequisites"] = []
            patterns.append(pattern)

        logger.debug(
            "Retrieved %d patterns (min_success=%.0f%%, min_used=%dx)",
            len(patterns),
            min_success_rate * 100,
            2,
        )
        return patterns

    def save_target_intel(self, intel: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO targets
            (target_domain, subdomains, open_ports, technologies, waf_detected,
             auth_methods, interesting_endpoints, last_seen, scan_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP,
                    COALESCE((SELECT scan_count FROM targets WHERE target_domain = ?), 0) + 1)
        """,
            (
                intel.get("target"),
                json.dumps(intel.get("subdomains", [])),
                json.dumps(intel.get("ports", {})),
                json.dumps(intel.get("technologies", {})),
                intel.get("waf"),
                json.dumps(intel.get("auth_methods", [])),
                json.dumps(intel.get("interesting_endpoints", [])),
                intel.get("target"),
            ),
        )
        self.conn.commit()

    def get_target_intel(self, target: str) -> dict | None:
        if not self.conn:
            return None

        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM targets WHERE target_domain = ?
        """,
            (target,),
        )

        row = cursor.fetchone()
        if not row:
            return None

        intel = dict(row)

        for field in [
            "subdomains",
            "open_ports",
            "technologies",
            "auth_methods",
            "interesting_endpoints",
        ]:
            if intel.get(field):
                try:
                    intel[field] = json.loads(intel[field])
                except Exception:
                    intel[field] = []

        return intel

    def save_knowledge(self, knowledge: dict[str, Any]) -> None:
        if not self.conn:
            return

        category = str(knowledge.get("category") or "general").strip().lower()
        title = str(knowledge.get("title") or "").strip()
        content = str(knowledge.get("content") or "").strip()
        if not title or not content:
            return

        confidence = max(0.0, min(float(knowledge.get("confidence", 1.0)), 1.0))
        source_session = str(knowledge.get("source_session") or "").strip() or None
        raw_tags = knowledge.get("tags", [])
        tags: list[str] = []
        seen_tags: set[str] = set()
        if isinstance(raw_tags, list):
            for item in raw_tags:
                tag = str(item or "").strip().lower()
                if not tag or tag in seen_tags:
                    continue
                seen_tags.add(tag)
                tags.append(tag)

        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, content, confidence, source_session, tags
            FROM knowledge
            WHERE category = ? AND title = ?
            ORDER BY confidence DESC, created_at DESC
            LIMIT 1
        """,
            (category, title),
        )

        existing = cursor.fetchone()
        if existing:
            merged_tags: list[str] = []
            merged_seen: set[str] = set()
            try:
                existing_tags = json.loads(existing["tags"] or "[]")
            except Exception:
                existing_tags = []
            for item in [*existing_tags, *tags]:
                tag = str(item or "").strip().lower()
                if not tag or tag in merged_seen:
                    continue
                merged_seen.add(tag)
                merged_tags.append(tag)

            merged_content = content
            existing_content = str(existing["content"] or "").strip()
            if existing_content and len(existing_content) > len(merged_content):
                merged_content = existing_content

            cursor.execute(
                """
                UPDATE knowledge
                SET content = ?, confidence = ?, source_session = ?, tags = ?
                WHERE id = ?
            """,
                (
                    merged_content,
                    max(confidence, float(existing["confidence"] or 0.0)),
                    source_session or existing["source_session"],
                    json.dumps(merged_tags),
                    existing["id"],
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO knowledge
                (category, title, content, confidence, source_session, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    category,
                    title,
                    content,
                    confidence,
                    source_session,
                    json.dumps(tags),
                ),
            )
        self.conn.commit()

    def get_knowledge(self, category: str | None = None, limit: int = 50) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if category:
            cursor.execute(
                """
                SELECT * FROM knowledge
                WHERE category = ?
                ORDER BY confidence DESC, created_at DESC
                LIMIT ?
            """,
                (category, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM knowledge
                ORDER BY confidence DESC, created_at DESC
                LIMIT ?
            """,
                (limit,),
            )

        knowledge_entries = []
        for row in cursor.fetchall():
            entry = dict(row)
            if entry.get("tags"):
                try:
                    entry["tags"] = json.loads(entry["tags"])
                except Exception:
                    entry["tags"] = []
            knowledge_entries.append(entry)

        return knowledge_entries

    def get_context_for_small_model(
        self,
        target: str,
        current_phase: str,
        max_tokens: int = 4096,
    ) -> str:
        """Build comprehensive context including memory, patterns, and tool insights."""
        context_parts = []
        tokens_used = 0

        intel = self.get_target_intel(target)
        if intel:
            context_parts.append("## TARGET INTELLIGENCE")
            if intel.get("subdomains"):
                subs = ", ".join(intel["subdomains"][:30])  # Increased from 20
                context_parts.append(
                    f"Subdomains ({len(intel['subdomains'])} total): {subs}"
                )
                tokens_used += len(subs) // 4
            if intel.get("open_ports"):
                ports = intel["open_ports"]
                ports_str = ", ".join(
                    f"{p}:{s}" for p, s in list(ports.items())[:15]
                ) 
                context_parts.append(f"Open Ports ({len(ports)} total): {ports_str}")
                tokens_used += len(ports_str) // 4
            if intel.get("technologies"):
                tech = intel["technologies"]
                tech_str = ", ".join(
                    f"{t}:{v}" for t, v in list(tech.items())[:15]
                ) 
                context_parts.append(f"Technologies ({len(tech)} total): {tech_str}")
                tokens_used += len(tech_str) // 4

        findings = self.get_similar_findings(target, limit=15)  
        if findings and tokens_used < max_tokens * 0.7:
            context_parts.append("\n## PAST FINDINGS")
            for f in findings[:7]: 
                line = (
                    f"- [{f['severity']}] {f['finding_type']}: {f['description'][:120]}"
                )
                context_parts.append(line)
                tokens_used += len(line) // 4

        patterns = self.get_patterns(limit=10) 
        if patterns and tokens_used < max_tokens * 0.8:
            context_parts.append("\n## LEARNED PATTERNS (Success Rate & Effectiveness)")
            for p in patterns[:5]:  
                effectiveness = p.get(
                    "effectiveness_score", p.get("success_rate", 0) * 100
                )
                line = f"- {p['description'][:120]} (success: {p['success_rate']:.0%}, effectiveness: {effectiveness:.0f})"
                context_parts.append(line)
                tokens_used += len(line) // 4

        learned_chains = self.get_learned_chains(target=target, limit=5)
        if learned_chains and tokens_used < max_tokens * 0.78:
            context_parts.append("\n## LEARNED ATTACK CHAINS")
            for chain in learned_chains[:3]:
                path = str(chain.get("attack_path", "") or "").strip()
                reasoning = str(chain.get("reasoning", "") or "").strip()
                line = f"- {chain.get('name', 'chain')}: {(path or reasoning or 'historical chain')[:140]}"
                context_parts.append(line)
                tokens_used += len(line) // 4

        if tokens_used < max_tokens * 0.6:
            tool_stats = self.get_tool_statistics()
            if isinstance(tool_stats, list) and tool_stats:
                context_parts.append("\n## TOOL USAGE INSIGHTS")
                for t in tool_stats[:6]:
                    sr = t.get("success_rate", 0) * 100
                    total = t.get(
                        "total_calls",
                        t.get("success_count", 0) + t.get("failure_count", 0),
                    )
                    line = f"- {t.get('tool_name', 'unknown')}: {sr:.0f}% success ({total} runs)"
                    context_parts.append(line)
                    tokens_used += len(line) // 4

                weak_tools = [
                    t
                    for t in tool_stats
                    if t.get("total_calls", 0) >= 3 and t.get("success_rate", 1.0) <= 0.35
                ]
                if weak_tools and tokens_used < max_tokens * 0.72:
                    context_parts.append("\n## TOOL PITFALLS")
                    for t in weak_tools[:4]:
                        line = (
                            f"- Avoid repeating {t.get('tool_name', 'unknown')} blindly: "
                            f"{t.get('success_rate', 0.0) * 100:.0f}% success over {t.get('total_calls', 0)} runs"
                        )
                        context_parts.append(line)
                        tokens_used += len(line) // 4

        phase_knowledge_map = {
            "RECON": ("reconnaissance", "## RECONNAISSANCE LESSONS"),
            "ANALYSIS": ("analysis", "## ANALYSIS LESSONS"),
            "EXPLOIT": ("exploitation", "## EXPLOITATION TIPS (From Past Successes)"),
            "REPORT": ("reporting", "## REPORTING LESSONS"),
        }
        phase_norm = str(current_phase or "").strip().upper()
        knowledge_category, knowledge_header = phase_knowledge_map.get(
            phase_norm,
            ("", ""),
        )
        if knowledge_category and tokens_used < max_tokens * 0.85:
            phase_knowledge = self.get_knowledge(knowledge_category, limit=10)
            if phase_knowledge:
                context_parts.append(f"\n{knowledge_header}")
                for k in phase_knowledge[:5]:
                    line = f"- {k['title']}: {k['content'][:140]}"
                    context_parts.append(line)
                    tokens_used += len(line) // 4

        if tokens_used < max_tokens * 0.5:
            baseline = self.get_knowledge(limit=15) 
            if baseline:
                context_parts.append("\n## SECURITY KNOWLEDGE BASE")
                for k in baseline[:8]:
                    line = f"- [{k['category']}] {k['title']}: {k['content'][:100]}"
                    context_parts.append(line)
                    tokens_used += len(line) // 4

        return "\n".join(context_parts)

    def get_similar_targets(self, target: str, limit: int = 5) -> list[dict]:
        if not self.conn:
            return []

        intel = self.get_target_intel(target)
        if not intel or not intel.get("technologies"):
            return []

        current_techs = set(intel["technologies"].keys())

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM targets WHERE target_domain != ?", (target,))

        similar = []
        for row in cursor.fetchall():
            target_data = None
            try:
                techs = json.loads(row["technologies"]) if row["technologies"] else {}
                overlap = current_techs.intersection(set(techs.keys()))
                if overlap:
                    target_data = dict(row)
                    target_data["tech_overlap"] = list(overlap)
                    target_data["similarity_score"] = len(overlap) / max(
                        len(current_techs), 1
                    )
            except Exception as e:
                logger.debug("Failed to parse similar target row: %s", e)
            if target_data is not None:
                similar.append(target_data)

        similar.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
        return similar[:limit]

    def get_tool_statistics(
        self, tool_name: str | None = None
    ) -> dict[str, Any] | list[dict[str, Any]]:
        if not self.conn:
            return {}

        cursor = self.conn.cursor()
        if tool_name:
            cursor.execute(
                """
                SELECT tool_name, target, success_count, failure_count,
                       avg_duration_sec, typical_output_size, last_used
                FROM tool_usage WHERE tool_name = ?
            """,
                (tool_name,),
            )
            rows = cursor.fetchall()
            rolled = rollup_tool_usage_rows(rows)
            return rolled[0] if rolled else {}

        cursor.execute("""
            SELECT tool_name, target, success_count, failure_count,
                   avg_duration_sec, typical_output_size, last_used
            FROM tool_usage
        """)
        return rollup_tool_usage_rows(cursor.fetchall())[:20]

    def get_tool_insights(self) -> dict[str, Any]:

        if not self.conn:
            return {}

        stats = self.get_tool_statistics()
        if not isinstance(stats, list):
            return {}
        ranked = [row for row in stats if row.get("total_calls", 0) >= 2]
        top_tools = []
        for tool in sorted(
            ranked,
            key=lambda row: (
                float(row.get("success_rate", 0.0)),
                int(row.get("total_calls", 0)),
            ),
            reverse=True,
        )[:15]:
            tool = dict(tool)
            tool["success_rate"] = round(float(tool.get("success_rate", 0.0)), 1)
            top_tools.append(tool)

        slow_tools = sorted(
            (dict(row) for row in stats),
            key=lambda row: float(row.get("avg_duration_sec", 0.0)),
            reverse=True,
        )[:5]

        reliable_tools = sorted(
            (
                dict(row)
                for row in stats
                if int(row.get("total_calls", 0)) >= 3
            ),
            key=lambda row: (
                float(row.get("success_rate", 0.0)),
                int(row.get("total_calls", 0)),
            ),
            reverse=True,
        )[:10]

        return {
            "top_performing_tools": top_tools,
            "tools_by_speed": slow_tools,
            "most_reliable_tools": reliable_tools,
            "total_tools_tracked": len(stats),
        }

    def get_model_performance_insights(self) -> dict[str, Any]:
        """
        Get model performance insights to help the agent choose the right model.
        """
        if not self.conn:
            return {}

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT model_name, task_type, success_rate, avg_response_time_sec, total_requests
            FROM model_performance
            ORDER BY success_rate DESC, avg_response_time_sec ASC
        """)

        results = [dict(row) for row in cursor.fetchall()]

        by_task = {}
        for r in results:
            task = r.get("task_type") or "unknown"
            if task not in by_task:
                by_task[task] = []
            by_task[task].append(r)

        return {
            "all_models": results,
            "models_by_task": by_task,
            "total_records": len(results),
        }

    def health_snapshot(self, target: str | None = None) -> dict[str, Any]:
        if not self.conn:
            return {"ok": False, "error": "memory_db_not_connected"}

        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) AS c FROM sessions")
            sessions_total = int(cursor.fetchone()["c"])

            cursor.execute("SELECT COUNT(*) AS c FROM findings")
            findings_total = int(cursor.fetchone()["c"])

            cursor.execute("SELECT COUNT(*) AS c FROM patterns")
            patterns_total = int(cursor.fetchone()["c"])

            cursor.execute(
                "SELECT COUNT(*) AS c FROM patterns WHERE success_rate >= 0.60 AND times_used >= 2"
            )
            high_quality_patterns = int(cursor.fetchone()["c"])

            target_sessions = 0
            target_findings = 0
            if target:
                cursor.execute(
                    "SELECT COUNT(*) AS c FROM sessions WHERE target = ? OR target LIKE ?",
                    (target, f"%.{target}"),
                )
                target_sessions = int(cursor.fetchone()["c"])

                cursor.execute(
                    "SELECT COUNT(*) AS c FROM findings WHERE target = ? OR target LIKE ?",
                    (target, f"%.{target}"),
                )
                target_findings = int(cursor.fetchone()["c"])

            return {
                "ok": True,
                "target": target or "",
                "sessions_total": sessions_total,
                "findings_total": findings_total,
                "patterns_total": patterns_total,
                "high_quality_patterns": high_quality_patterns,
                "target_sessions": target_sessions,
                "target_findings": target_findings,
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _normalize_skill_target(self, target: str) -> str:
        raw = str(target or "").strip().lower()
        if not raw:
            return ""
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.netloc or parsed.path
        host = host.split("/", 1)[0]
        host = host.split("@", 1)[-1]
        if ":" in host:
            host = host.split(":", 1)[0]
        return host.strip().strip(".")

    def _normalize_skill_name(self, skill_name: str) -> str:
        value = str(skill_name or "").strip().replace("\\", "/")
        if value.startswith("skills/"):
            value = value[7:]
        return value

    def _skill_target_matches(self, stored_target: str, requested_target: str) -> bool:
        stored = self._normalize_skill_target(stored_target)
        requested = self._normalize_skill_target(requested_target)
        if not stored or not requested:
            return False
        return (
            stored == requested
            or stored.endswith(f".{requested}")
            or requested.endswith(f".{stored}")
        )

    def get_skill_recommendations(
        self, target: str, current_phase: str
    ) -> list[dict[str, Any]]:
        """
        Get skill recommendations based on past performance.
        Returns skills that were effective for similar targets/phases.
        """
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        phase_norm = str(current_phase or "").strip().upper()
        target_norm = self._normalize_skill_target(target)

        cursor.execute(
            """
            SELECT skill_name, target, phase, success, effectiveness_score,
                   tokens_saved, timestamp
            FROM skill_usage
            ORDER BY timestamp DESC
            LIMIT 1000
            """
        )

        aggregated: dict[str, dict[str, Any]] = {}
        for row in cursor.fetchall():
            row_phase = str(row["phase"] or "").strip().upper()
            row_target = str(row["target"] or "")

            target_match = self._skill_target_matches(row_target, target_norm)
            if target_norm and not target_match:
                continue
            if phase_norm and row_phase and row_phase != phase_norm:
                continue

            skill_path = self._normalize_skill_name(str(row["skill_name"] or ""))
            if not skill_path:
                continue

            info = aggregated.setdefault(
                skill_path,
                {
                    "skill_path": skill_path,
                    "skill_name": Path(skill_path).stem,
                    "times_used": 0,
                    "successes": 0,
                    "effectiveness_total": 0.0,
                    "tokens_saved_total": 0,
                    "phase": row_phase,
                    "phase_match": False,
                    "target_match": False,
                    "latest_timestamp": str(row["timestamp"] or ""),
                },
            )
            info["times_used"] += 1
            info["successes"] += 1 if bool(row["success"]) else 0
            info["effectiveness_total"] += float(row["effectiveness_score"] or 0.0)
            info["tokens_saved_total"] += int(row["tokens_saved"] or 0)
            info["phase_match"] = info["phase_match"] or bool(
                phase_norm and row_phase == phase_norm
            )
            info["target_match"] = info["target_match"] or target_match
            if str(row["timestamp"] or "") > info["latest_timestamp"]:
                info["latest_timestamp"] = str(row["timestamp"] or "")

        recommendations: list[dict[str, Any]] = []
        for info in aggregated.values():
            times_used = int(info["times_used"])
            if times_used <= 0:
                continue
            success_rate = info["successes"] / times_used
            avg_effectiveness = info["effectiveness_total"] / times_used
            avg_tokens_saved = info["tokens_saved_total"] / times_used

            score = avg_effectiveness
            score += success_rate * 0.35
            score += min(0.2, avg_tokens_saved / 4000.0)
            if info["phase_match"]:
                score += 0.2
            if info["target_match"]:
                score += 0.2

            recommendations.append(
                {
                    "skill_name": info["skill_name"],
                    "skill_path": info["skill_path"],
                    "phase": info["phase"],
                    "success_rate": round(success_rate, 3),
                    "times_used": times_used,
                    "effectiveness_score": round(avg_effectiveness, 3),
                    "avg_tokens_saved": int(avg_tokens_saved),
                    "target_match": bool(info["target_match"]),
                    "score": round(score, 3),
                    "latest_timestamp": info["latest_timestamp"],
                }
            )

        recommendations.sort(
            key=lambda rec: (
                rec["score"],
                rec["times_used"],
                rec["latest_timestamp"],
            ),
            reverse=True,
        )
        return recommendations[:15]

    def save_skill_usage(
        self,
        skill_name: str,
        target: str,
        phase: str,
        success: bool,
        effectiveness_score: float,
        tokens_saved: int,
    ) -> None:
        """
        Record skill usage outcome for learning.
        """
        if not self.conn:
            return

        skill_name = self._normalize_skill_name(skill_name)
        target = self._normalize_skill_target(target)
        phase = str(phase or "").strip().upper()
        if not skill_name or not target:
            return

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO skill_usage (
                skill_name, target, phase, success, effectiveness_score,
                tokens_saved, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
            (
                skill_name,
                target,
                phase,
                1 if success else 0,
                max(0.0, min(float(effectiveness_score), 1.0)),
                max(0, int(tokens_saved)),
            ),
        )
        self.conn.commit()

    def record_tool_usage(
        self,
        tool_name: str,
        target: str,
        success: bool,
        duration_sec: float,
        output_size: int,
    ) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT id, success_count, failure_count, avg_duration_sec FROM tool_usage
            WHERE tool_name = ? AND (target = ? OR target IS NULL)
        """,
            (tool_name, target),
        )

        existing = cursor.fetchone()
        if existing:
            new_success = existing["success_count"] + (1 if success else 0)
            new_failure = existing["failure_count"] + (0 if success else 1)
            total = new_success + new_failure
            new_avg = (
                (existing["avg_duration_sec"] * (total - 1)) + duration_sec
            ) / total

            cursor.execute(
                """
                UPDATE tool_usage SET
                    success_count = ?, failure_count = ?, avg_duration_sec = ?,
                    typical_output_size = ?, last_used = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (new_success, new_failure, new_avg, output_size, existing["id"]),
            )
        else:
            cursor.execute(
                """
                INSERT INTO tool_usage
                (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    tool_name,
                    target,
                    1 if success else 0,
                    0 if success else 1,
                    duration_sec,
                    output_size,
                ),
            )

        self.conn.commit()

    def record_model_performance(
        self,
        model_name: str,
        task_type: str | None,
        response_time_sec: float,
        success: bool,
        context_size_used: int = 0,
    ) -> None:
        if not self.conn:
            return

        model_name = str(model_name or "").strip()
        if not model_name:
            return

        task_type_norm = str(task_type or "").strip().lower() or None
        response_time_sec = max(0.0, float(response_time_sec or 0.0))
        context_size_used = max(0, int(context_size_used or 0))

        cursor = self.conn.cursor()
        if task_type_norm is None:
            cursor.execute(
                """
                SELECT id, avg_response_time_sec, success_rate, total_requests, context_size_used
                FROM model_performance
                WHERE model_name = ? AND task_type IS NULL
                ORDER BY id DESC
                LIMIT 1
            """,
                (model_name,),
            )
        else:
            cursor.execute(
                """
                SELECT id, avg_response_time_sec, success_rate, total_requests, context_size_used
                FROM model_performance
                WHERE model_name = ? AND task_type = ?
                ORDER BY id DESC
                LIMIT 1
            """,
                (model_name, task_type_norm),
            )

        existing = cursor.fetchone()
        if existing:
            prev_total = int(existing["total_requests"] or 0)
            new_total = prev_total + 1
            prev_successes = float(existing["success_rate"] or 0.0) * prev_total
            new_success_rate = (prev_successes + (1.0 if success else 0.0)) / max(
                new_total, 1
            )
            new_avg_time = (
                (float(existing["avg_response_time_sec"] or 0.0) * prev_total)
                + response_time_sec
            ) / max(new_total, 1)
            new_avg_context = int(
                round(
                    (
                        (int(existing["context_size_used"] or 0) * prev_total)
                        + context_size_used
                    )
                    / max(new_total, 1)
                )
            )
            cursor.execute(
                """
                UPDATE model_performance
                SET avg_response_time_sec = ?, success_rate = ?, total_requests = ?,
                    context_size_used = ?, last_used = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (
                    new_avg_time,
                    new_success_rate,
                    new_total,
                    new_avg_context,
                    existing["id"],
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO model_performance
                (model_name, task_type, avg_response_time_sec, success_rate, total_requests, context_size_used)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    model_name,
                    task_type_norm,
                    response_time_sec,
                    1.0 if success else 0.0,
                    1,
                    context_size_used,
                ),
            )

        self.conn.commit()

    def save_chain_discovery(self, chain_data: dict[str, Any]) -> None:
        """Save a discovered attack chain for cross-session learning."""
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO chain_discoveries
            (chain_id, name, combined_severity, attack_path, reasoning,
             findings, relation_types, target, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chain_data.get("chain_id"),
                chain_data.get("name"),
                chain_data.get("combined_severity", 1),
                chain_data.get("attack_path", ""),
                chain_data.get("reasoning", ""),
                json.dumps(chain_data.get("findings", [])),
                json.dumps(chain_data.get("relation_types", [])),
                chain_data.get("target", ""),
                chain_data.get("discovered_at", ""),
            ),
        )
        self.conn.commit()

    def get_learned_chains(self, target: str = "", limit: int = 10) -> list[dict[str, Any]]:
        """Get previously discovered chains for cross-session learning."""
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if target:
            cursor.execute(
                """
                SELECT chain_id, name, combined_severity, attack_path, reasoning,
                       findings, relation_types
                FROM chain_discoveries
                WHERE target = ? OR target = ''
                ORDER BY combined_severity DESC, discovered_at DESC
                LIMIT ?
                """,
                (target, limit),
            )
        else:
            cursor.execute(
                """
                SELECT chain_id, name, combined_severity, attack_path, reasoning,
                       findings, relation_types
                FROM chain_discoveries
                ORDER BY combined_severity DESC, discovered_at DESC
                LIMIT ?
                """,
                (limit,),
            )

        chains = []
        for row in cursor.fetchall():
            chains.append({
                "chain_id": row[0],
                "name": row[1],
                "combined_severity": row[2],
                "attack_path": row[3],
                "reasoning": row[4],
                "findings": json.loads(row[5]) if row[5] else [],
                "relation_types": json.loads(row[6]) if row[6] else [],
            })
        return chains

    def get_model_recommendation(self, task_type: str) -> str:

        def _config_default_model() -> str:
            try:
                from airecon.proxy.config import get_config

                cfg = get_config()
                model = (cfg.openai_model if cfg else "") or ""
                logger.debug("Config loaded: openai_model=%s", model or None)
                if model:
                    return model
                logger.debug("Config or openai_model is None/empty")
            except Exception as e:
                logger.debug("Config read failed: %s", e)
            return ""

        if not self.conn:
            model = _config_default_model()
            if model:
                logger.debug("Returning user config model: %s", model)
                return model
            logger.warning("No model configured — check ~/.airecon/config.yaml")
            return ""

        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT model_name, success_rate, avg_response_time_sec, total_requests
            FROM model_performance
            WHERE task_type = ? OR task_type IS NULL
            ORDER BY success_rate DESC, avg_response_time_sec ASC
            LIMIT 1
        """,
            (task_type,),
        )

        row = cursor.fetchone()
        if row and row["total_requests"] >= 5:
            return row["model_name"]

        model = _config_default_model()
        if model:
            logger.debug("Returning user config model (fallback path): %s", model)
            return model

        logger.warning("No model configured — check ~/.airecon/config.yaml")
        return ""


_memory_manager: MemoryManager | None = None
_memory_manager_lock = threading.Lock()


def get_memory_manager() -> MemoryManager:
    global _memory_manager
    if _memory_manager is None:
        with _memory_manager_lock:
            if _memory_manager is None:
                _memory_manager = MemoryManager()
                _memory_manager.connect()
    return _memory_manager
