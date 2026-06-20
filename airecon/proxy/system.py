from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from .config import get_config

logger = logging.getLogger("airecon.system")

with open(Path(__file__).parent / "prompts" / "system.txt", "r") as f:
    SYSTEM_PROMPT = f.read()

def _is_ctf_target(target: str | None = None, user_message: str | None = None) -> bool:
    """Automatic CTF classification is intentionally disabled.

    Engagement mode should not be inferred from heuristics or sidecar hint files.
    The model receives the user's request directly and must reason from that
    request instead of hidden mode classifiers.
    """
    _ = (target, user_message)
    return False


def _is_bugbounty_target(
    target: str | None = None, user_message: str | None = None
) -> bool:
    _ = (target, user_message)
    return False


def _is_pentest_target(
    target: str | None = None, user_message: str | None = None
) -> bool:
    _ = (target, user_message)
    return False


def _load_local_skills(ctf_mode: bool = False) -> str:
    """Build the <available_skills> block for the system prompt.

    Lists every skill by its exact stem name so the LLM can call
    read_file with a precise path instead of guessing filenames.
    """
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return ""

    _ = ctf_mode

    # Collect stems grouped by top-level category directory.
    category_files: dict[str, list[str]] = {}
    for path in sorted(skills_dir.rglob("*.md")):
        if path.name.startswith("_"):
            continue
        rel = path.relative_to(skills_dir)
        cat = rel.parts[0] if len(rel.parts) > 1 else ""
        if cat:
            category_files.setdefault(cat, []).append(path.stem)

    if not category_files:
        return ""

    base_path = skills_dir.as_posix()
    total = sum(len(v) for v in category_files.values())

    lines: list[str] = [
        "\n\n<available_skills>",
        f"Skills base path: {base_path}",
        f"{total} skill documents — auto-injected when relevant, or load explicitly with read_file.\n",
    ]
    for cat in sorted(category_files):
        stems = sorted(category_files[cat])
        lines.append(f"  {cat}/  →  {', '.join(stems)}")

    lines.append(f"\nUsage: read_file {base_path}/<category>/<skill_name>.md")
    lines.append("</available_skills>\n")

    return "\n".join(lines)


def _load_skill_keywords() -> dict[str, str]:
    try:
        skills_json = Path(__file__).parent / "data" / "skills.json"
        if skills_json.exists():
            with open(skills_json, "r") as f:
                data = json.load(f)
                return data.get("skill_keywords", {})
    except Exception as e:
        logger.warning("Failed to load skill keywords from JSON: %s", e)
    return {}


def _keyword_matches_message(keyword: str, msg_lower: str) -> bool:
    k = keyword.lower().strip()
    if not k:
        return False

    prefix = r"\b" if k[0].isalnum() else ""
    suffix = r"\b" if k[-1].isalnum() else ""
    pattern = prefix + re.escape(k) + suffix
    return re.search(pattern, msg_lower) is not None


_SKILL_KEYWORDS: dict[str, str] = _load_skill_keywords()


def _build_skill_keyword_density(keywords: dict[str, str]) -> dict[str, int]:
    """Count keyword entries per skill path — higher = more broadly referenced."""
    density: dict[str, int] = {}
    for skill_path in keywords.values():
        density[skill_path] = density.get(skill_path, 0) + 1
    return density


# Precomputed once at import time from the full keyword vocabulary.
# Per-test _SKILL_KEYWORDS mocks do not affect this — phase-fallback
# ranking always reflects the real keyword distribution.
_SKILL_KEYWORD_DENSITY: dict[str, int] = _build_skill_keyword_density(_SKILL_KEYWORDS)

_PHASE_SKILL_CATEGORIES: dict[str, set[str]] = {
    "RECON": {"reconnaissance", "tools", "protocols"},
    "ANALYSIS": {"vulnerabilities", "frameworks", "technologies", "protocols"},
    "EXPLOIT": {
        "payloads",
        "vulnerabilities",
        "postexploit",
        "frameworks",
        "tools",
        "ctf",
    },
    "REPORT": set(),
    "COMPLETE": set(),
}


def _phase_preferred_skill_dirs(phase: str) -> set[str]:
    """Return the skill directory names preferred for the given phase."""
    return _PHASE_SKILL_CATEGORIES.get(phase.upper() if phase else "", set())


def _discover_all_skills(
    skills_dir: Path,
) -> dict[str, str]:
    """Scan the skills directory and return {relative_path: stem} for all .md files.

    This replaces hardcoded _PHASE_ENTRY_SKILLS — skills are discovered at runtime
    from the filesystem, making the system adaptive to new skills added to the repo.
    """
    import os

    skills: dict[str, str] = {}
    if not skills_dir.exists():
        return skills
    for dirpath, _, filenames in os.walk(skills_dir):
        dirpath_p = Path(dirpath)
        if dirpath_p.name.startswith("_") or dirpath_p.name.startswith("."):
            continue
        for fn in filenames:
            if fn.endswith(".md") and not fn.startswith("_"):
                rel = dirpath_p.relative_to(skills_dir) / fn
                skills[str(rel)] = Path(fn).stem.lower()
    return skills


def _select_phase_skills(
    phase: str,
    all_skills: dict[str, str],
    session_loaded: set[str] | None = None,
    max_skills: int = 3,
) -> list[str]:
    """Select skills relevant to the phase, excluding already-loaded ones.

    Skills are ranked by keyword density (how many keyword entries map to them
    in the full vocabulary) so that broadly-referenced skills are preferred
    over niche ones. Uses the precomputed _SKILL_KEYWORD_DENSITY so that
    per-test _SKILL_KEYWORDS mocks do not distort phase-fallback ranking.
    Within the same density, alphabetical order provides a stable tiebreaker.
    """
    if not phase or not all_skills:
        return []

    preferred_dirs = _phase_preferred_skill_dirs(phase)
    if not preferred_dirs:
        return []

    session_set = session_loaded or set()

    scored: list[tuple[int, str]] = []
    for rel_path, stem in all_skills.items():
        if rel_path in session_set or stem in session_set:
            continue
        cat = rel_path.split("/")[0] if "/" in rel_path else rel_path
        if cat in preferred_dirs:
            scored.append((_SKILL_KEYWORD_DENSITY.get(rel_path, 0), rel_path))

    # Higher density first; alphabetical tiebreaker for determinism.
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [rel for _, rel in scored[:max_skills]]


def _message_skill_char_budget(ctx_tokens: int) -> tuple[int, int]:
    """Return (tools/recon char limit, other skill char limit) scaled to context size."""
    ctx = max(4096, int(ctx_tokens or 0))
    if ctx >= 65536:
        return 6000, 2500
    if ctx >= 32768:
        return 5000, 1800
    if ctx >= 16384:
        return 3500, 1200
    return 2500, 900


def auto_load_skills_for_message(
    user_message: str,
    phase: str = "",
    session_loaded_skills: set[str] | None = None,
    memory_manager=None,
    current_target: str = "",
) -> tuple[str, list[str]]:
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return "", []

    try:
        cfg = get_config()
        _tools_limit, _other_limit = _message_skill_char_budget(
            int(getattr(cfg, "llm_context_window", 32768) or 32768)
        )
    except Exception:
        _tools_limit, _other_limit = 5000, 1800

    msg_lower = user_message.lower()

    skill_scores: dict[str, int] = {}
    for keyword, skill_path in _SKILL_KEYWORDS.items():
        if _keyword_matches_message(keyword, msg_lower):
            skill_scores[skill_path] = skill_scores.get(skill_path, 0) + 1

    if phase:
        preferred = _phase_preferred_skill_dirs(phase)
        if preferred:
            for skill_path in list(skill_scores.keys()):
                skill_dir = skill_path.split("/")[0]
                if skill_dir in preferred:
                    skill_scores[skill_path] += 2

    sorted_skills = sorted(
        skill_scores.keys(),
        key=lambda s: (-skill_scores[s], s),
    )

    recommended_skills = []
    if memory_manager and current_target:
        try:
            skill_recs = memory_manager.get_skill_recommendations(current_target, phase)
            for rec in skill_recs:
                skill_path = str(rec.get("skill_path") or rec.get("skill_name") or "")
                if not skill_path:
                    continue
                if "/" not in skill_path:
                    skill_path = (
                        f"ctf/{skill_path}.md"
                        if phase == "EXPLOIT"
                        else f"reconnaissance/{skill_path}.md"
                    )
                skill_file = skills_dir / skill_path
                if skill_file.exists() and skill_path not in skill_scores:
                    score = float(
                        rec.get("effectiveness_score", rec.get("success_rate", 0.0))
                    )
                    skill_scores[skill_path] = max(1, int(score * 10))
                    recommended_skills.append(skill_path)
            sorted_skills = sorted(
                skill_scores.keys(),
                key=lambda s: (-skill_scores[s], s),
            )
        except Exception as e:
            logger.debug("Skill recommendation lookup failed: %s", e)

    all_skills = _discover_all_skills(skills_dir)
    phase_fallback = (
        _select_phase_skills(
            phase, all_skills, session_loaded_skills, max_skills=2,
        )
        if not sorted_skills
        else []
    )

    parts: list[str] = []
    loaded_skills: list[str] = []
    loaded_paths: set[str] = set()

    def _load_skill(skill_rel: str, *, priority: int = 0) -> bool:
        if skill_rel in loaded_paths:
            return False

        if session_loaded_skills:
            _legacy_stem = Path(skill_rel).stem
            if (
                skill_rel in session_loaded_skills
                or _legacy_stem in session_loaded_skills
            ):
                logger.debug("Skill already loaded this session: %s", skill_rel)
                return False
        skill_file = skills_dir / skill_rel
        if not skill_file.exists():
            return False
        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")

            limit = (
                _tools_limit
                if (
                    skill_rel.startswith("tools/")
                    or skill_rel.startswith("reconnaissance/")
                )
                else _other_limit
            )
            if len(content) > limit:
                content = (
                    content[:limit]
                    + f"\n... (truncated at {limit} chars, use read_file for"
                    f" full content: {skill_file.absolute().as_posix()})"
                )
            parts.append(f"[AUTO-LOADED SKILL: {skill_rel}]\n{content}")
            loaded_skills.append(skill_rel)
            loaded_paths.add(skill_rel)
            if memory_manager and current_target:
                try:
                    memory_manager.save_skill_usage(
                        skill_name=skill_rel,
                        target=current_target,
                        phase=phase,
                        success=True,
                        effectiveness_score=min(1.0, 0.65 + (priority * 0.1)),
                        tokens_saved=max(0, len(content) // 4),
                    )
                except Exception as exc:
                    logger.debug("Skill usage save failed for %s: %s", skill_rel, exc)
            return True
        except Exception:
            return False

    keyword_count = 0
    max_keyword_skills = 3
    for skill_rel in sorted_skills:
        if keyword_count >= max_keyword_skills:
            break
        if _load_skill(skill_rel, priority=2):
            keyword_count += 1

    phase_count = 0
    max_phase_skills = 2
    for skill_rel in phase_fallback:
        if phase_count >= max_phase_skills or len(parts) >= 5:
            break
        if _load_skill(skill_rel, priority=1):
            phase_count += 1

    if not parts:
        return "", []

    total_chars = sum(len(p) for p in parts)
    logger.debug(
        "skill_injection_stats: phase=%s keyword=%d phase_extra=%d loaded=%d total_chars=%d",
        phase,
        keyword_count,
        phase_count,
        len(loaded_skills),
        total_chars,
    )

    return (
        "[SYSTEM: RELEVANT SKILLS AUTO-LOADED based on your request]\n"
        + "\n---\n".join(parts),
        loaded_skills,
    )


def auto_load_skills_for_technologies(
    technologies: dict[str, str],
    already_loaded: set[str] | None = None,
    target_profile=None,  # NEW: Target profile for context-aware selection
) -> tuple[str, list[str]]:
    if not technologies:
        return "", []

    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return "", []

    if already_loaded is None:
        already_loaded = set()

    tech_message = " ".join(technologies.keys()).lower()

    skill_scores: dict[str, int] = {}
    for keyword, skill_path in _SKILL_KEYWORDS.items():
        if _keyword_matches_message(keyword, tech_message):
            skill_scores[skill_path] = skill_scores.get(skill_path, 0) + 1

    # Context-aware skill scoring based on target profile
    if target_profile is not None:
        # Boost scores for skills relevant to detected attack surface
        attack_vectors = target_profile.attack_surface.get("attack_vectors", [])
        for vector in attack_vectors:
            vector_lower = vector.lower()
            for skill_path in list(skill_scores.keys()):
                if vector_lower in skill_path.lower():
                    skill_scores[skill_path] += 3

        # Boost scores for skills relevant to security issues
        for issue in target_profile.security_issues:
            issue_lower = issue.lower()
            for skill_path in list(skill_scores.keys()):
                if issue_lower in skill_path.lower():
                    skill_scores[skill_path] += 2

    if not skill_scores:
        return "", []

    sorted_skills = sorted(
        skill_scores.keys(),
        key=lambda s: (-skill_scores[s], s),
    )

    def _tech_skill_budget(ctx_tokens: int) -> tuple[int, int, int]:
        ctx = max(4096, int(ctx_tokens or 0))
        if ctx >= 131072:
            return 22000, 7000, 66000
        if ctx >= 65536:
            return 18000, 6000, 54000
        if ctx >= 32768:
            return 14000, 4500, 42000
        if ctx >= 16384:
            return 11000, 3500, 30000
        return 9000, 3000, 22000

    try:
        cfg = get_config()
        tech_limit, generic_limit, total_limit = _tech_skill_budget(
            int(getattr(cfg, "llm_context_window", 32768) or 32768)
        )
    except Exception:
        tech_limit, generic_limit, total_limit = _tech_skill_budget(32768)

    parts: list[str] = []
    loaded_names: list[str] = []
    used_chars = 0
    for skill_rel in sorted_skills[:3]:
        if skill_rel in already_loaded:
            continue
        skill_file = skills_dir / skill_rel
        if skill_file.exists():
            try:
                content = skill_file.read_text(encoding="utf-8", errors="replace")
                limit = (
                    tech_limit
                    if (
                        skill_rel.startswith("technologies/")
                        or skill_rel.startswith("frameworks/")
                    )
                    else generic_limit
                )
                if len(content) > limit:
                    content = (
                        content[:limit]
                        + f"\n... (truncated, use read_file for full: {skill_file.absolute().as_posix()})"
                    )
                block = f"[AUTO-LOADED TECH SKILL: {skill_rel}]\n{content}"
                remaining = total_limit - used_chars
                if remaining <= 0:
                    break
                if len(block) > remaining:
                    if remaining < 1200:
                        break
                    notice = (
                        f"\n... (truncated by adaptive total tech-skill budget "
                        f"{total_limit} chars; use read_file for full content)"
                    )
                    keep = max(0, remaining - len(notice))
                    block = block[:keep] + notice
                parts.append(block)
                used_chars += len(block)

                loaded_names.append(skill_rel)
                already_loaded.add(skill_rel)
            except Exception as e:
                logger.debug("Expected failure loading tech skill %s: %s", skill_rel, e)

    if not parts:
        return "", []

    tech_names = ", ".join(list(technologies.keys())[:8])
    return (
        f"[SYSTEM: TECH-SPECIFIC SKILLS LOADED — detected: {tech_names}]\n"
        + "\n---\n".join(parts),
        loaded_names,
    )


def get_system_prompt(
    target: str | None = None,
    user_message: str | None = None,
) -> str:
    cfg = get_config()
    base_prompt = SYSTEM_PROMPT

    recon_mode = str(getattr(cfg, "agent_recon_mode", "standard")).strip().lower()
    if recon_mode not in {"standard", "full"}:
        recon_mode = "standard"

    recon_policy = f"""
<recon_mode_policy>
RECON_MODE={recon_mode.upper()}

- In STANDARD mode, do not auto-expand focused tasks into broad full recon unless the user
  explicitly asks for comprehensive/deep/full coverage.
- In FULL mode, if the user gives only a simple target-only kickoff, you may auto-expand
  into comprehensive recon when deep_recon_autostart is enabled.
- If user intent conflicts with auto-expansion, user intent wins.
</recon_mode_policy>
"""
    base_prompt += "\n\n" + recon_policy

    if cfg.allow_destructive_testing:
        base_prompt = base_prompt.replace(
            "Full authorization for non-destructive penetration testing. No permission checks needed.",
            "FULL AUTHORIZATION for UNRESTRICTED penetration testing including destructive actions. No permission checks needed.",
        )
        safety_override = """
<safety_override>
DESTRUCTIVE MODE ENABLED — operator has granted full authorization.

- Destructive actions are permitted: crash services, drop/overwrite test data,
  exhaust resources, trigger error states, bypass rate limits.
- Aggressive fuzzing is encouraged: long payloads, max threads, deep recursion,
  boundary violations, malformed input, protocol abuse.
- For SQL injection: go beyond detection — extract schema, dump tables, test UPDATE/DELETE.
- For RCE: get a shell. Write a file. Execute a command. Prove execution, don't just detect it.
- For auth flaws: bypass completely, impersonate other users, elevate to admin.
- Do NOT self-limit based on "safety" concerns — the operator has accepted the risk.

Zero false positives remain mandatory: a crash or error is not a vulnerability
unless you reproduce it, understand WHY, and can demonstrate real impact.
</safety_override>
"""
        base_prompt = base_prompt.replace(
            "<execution_guidelines>", safety_override + "\n<execution_guidelines>"
        )

    skills_block = _load_local_skills(ctf_mode=False)
    mcp_block = _build_mcp_server_hint()
    _ = (target, user_message)
    return base_prompt + skills_block + mcp_block


def _build_mcp_server_hint() -> str:
    """List currently enabled MCP servers by name in the system prompt.

    The LLM sees ``mcp_<server>`` entries in its tool list, but without a name
    roster it has no way to know WHICH servers exist and what they are.
    This block is intentionally shallow: it reports names + short description
    from config (if present). Tool discovery still happens via
    ``action="list_tools"`` / ``action="search_tools"`` at call time.
    """
    try:
        from .mcp import list_mcp_servers
    except Exception as e:
        logger.debug("MCP hint disabled (import failure): %s", e)
        return ""

    try:
        servers = list_mcp_servers()
    except Exception as e:
        logger.debug("MCP hint disabled (list failure): %s", e)
        return ""

    enabled = [
        (name, cfg)
        for name, cfg in servers.items()
        if isinstance(cfg, dict) and bool(cfg.get("enabled", True))
    ]
    if not enabled:
        return ""

    lines: list[str] = ["\n\n<available_mcp_servers>"]
    lines.append(
        f"{len(enabled)} MCP server(s) enabled. Each exposes tools under "
        f"`mcp_<name>`. Call with `action=\"search_tools\"` + `query` to find "
        f"specific tools, then `action=\"call_tool\"` to execute."
    )
    for name, cfg in sorted(enabled, key=lambda x: x[0]):
        desc = str(cfg.get("description") or "").strip()
        transport = "stdio" if cfg.get("command") else "http/sse" if cfg.get("url") else "unknown"
        if desc:
            lines.append(f"  • mcp_{name} ({transport}): {desc[:200]}")
        else:
            lines.append(f"  • mcp_{name} ({transport})")
    lines.append(
        "Use MCP tools when no built-in tool fits — e.g., specialized scanners, "
        "threat intel sources, or custom workflows. The LLM decides based on "
        "the actual task, not a fixed mapping."
    )
    lines.append("</available_mcp_servers>\n")
    return "\n".join(lines)
