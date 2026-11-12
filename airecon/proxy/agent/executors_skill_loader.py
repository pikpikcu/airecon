from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import AgentState

logger = logging.getLogger("airecon.agent")
_SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
_SKILL_KEYWORDS_PATH = Path(__file__).resolve().parent.parent / "data" / "skills.json"


def _normalize_skill_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _load_skill_keywords() -> dict[str, str]:
    try:
        if _SKILL_KEYWORDS_PATH.exists():
            data = json.loads(_SKILL_KEYWORDS_PATH.read_text(encoding="utf-8"))
            raw = data.get("skill_keywords", {})
            if isinstance(raw, dict):
                return {
                    _normalize_skill_token(k): str(v)
                    for k, v in raw.items()
                    if str(k).strip() and str(v).strip()
                }
    except Exception as exc:
        logger.debug("Failed to load skill keyword aliases: %s", exc)
    return {}


_SKILL_KEYWORD_ALIASES = _load_skill_keywords()


def _build_skill_index() -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    if not _SKILLS_DIR.exists():
        return index

    for skill_file in sorted(_SKILLS_DIR.rglob("*.md")):
        rel = skill_file.relative_to(_SKILLS_DIR).as_posix()
        stem = skill_file.stem
        category = skill_file.parent.name
        aliases = {
            rel,
            rel[:-3] if rel.endswith(".md") else rel,
            stem,
            f"{category}/{stem}",
            _normalize_skill_token(rel),
            _normalize_skill_token(rel[:-3] if rel.endswith(".md") else rel),
            _normalize_skill_token(stem),
            _normalize_skill_token(f"{category}/{stem}"),
        }
        for alias in aliases:
            if not alias:
                continue
            index.setdefault(alias, []).append(rel)

    for keyword, rel in _SKILL_KEYWORD_ALIASES.items():
        if (_SKILLS_DIR / rel).exists():
            index.setdefault(keyword, []).append(rel)

    for alias, rels in list(index.items()):
        index[alias] = sorted(dict.fromkeys(rels))

    return index


_SKILL_INDEX = _build_skill_index()


def _skill_priority(skill_rel: str) -> tuple[int, str]:
    category = skill_rel.split("/", 1)[0] if "/" in skill_rel else ""
    priority = {
        "vulnerabilities": 0,
        "frameworks": 1,
        "technologies": 2,
        "protocols": 3,
        "tools": 4,
        "payloads": 5,
        "reconnaissance": 6,
        "postexploit": 7,
        "ctf": 8,
    }.get(category, 99)
    return (priority, skill_rel)


def _resolve_skill_path(request: str) -> tuple[str | None, str | None]:
    raw = str(request or "").strip()
    if not raw:
        return None, "Empty skill request"

    direct_candidates = [
        raw,
        raw[:-3] if raw.endswith(".md") else raw,
    ]
    for candidate in direct_candidates:
        skill_file = _SKILLS_DIR / candidate
        if skill_file.exists():
            if skill_file.is_dir():
                continue
            if skill_file.suffix != ".md":
                skill_file = skill_file.with_suffix(".md")
                if not skill_file.exists():
                    continue
            return skill_file.relative_to(_SKILLS_DIR).as_posix(), None

    alias = _normalize_skill_token(raw)
    matches = _SKILL_INDEX.get(alias, [])
    if not matches:
        return None, f"Skill not found: {raw}"

    chosen = sorted(matches, key=_skill_priority)[0]
    return chosen, None


def load_skill(
    agent_state: AgentState,
    skills: str,
    replace_skills: bool = False,
    *,
    memory_manager: Any | None = None,
    current_target: str = "",
    current_phase: str = "",
    effectiveness_score: float = 0.8,
) -> dict[str, Any]:
    if not skills or not isinstance(skills, str):
        return {
            "success": False,
            "error": "No skills provided. Pass comma-separated skill paths.",
            "loaded_skills": [],
        }

    requested = [s.strip() for s in skills.split(",") if s.strip()]
    if not requested:
        return {
            "success": False,
            "error": "Invalid skills list.",
            "loaded_skills": [],
        }

    loaded_skills: list[str] = []
    errors: list[str] = []

    current_skills = set(agent_state.skills_used) if not replace_skills else set()

    for skill_request in requested:
        skill_rel, error = _resolve_skill_path(skill_request)
        if error or not skill_rel:
            errors.append(error or f"Skill not found: {skill_request}")
            continue
        if skill_rel in current_skills or Path(skill_rel).stem in current_skills:
            logger.debug("Skill already active, skipping duplicate load: %s", skill_rel)
            continue
        skill_file = _SKILLS_DIR / skill_rel

        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")

            limit = (
                5000 if skill_rel.startswith(("tools/", "reconnaissance/")) else 1500
            )
            if len(content) > limit:
                content = (
                    content[:limit]
                    + f"\n... (truncated at {limit} chars, use read_file for full content)"
                )

            skill_block = (
                f'\n\n<dynamic_skill name="{skill_rel}">\n{content}\n</dynamic_skill>\n'
            )

            agent_state.add_message(
                "system",
                f"[SKILL LOADED: {skill_rel}]\n"
                "This skill is now active in your context. Apply its methodology when relevant."
                f"{skill_block}",
            )

            current_skills.add(skill_rel)
            loaded_skills.append(skill_rel)
            if memory_manager and current_target:
                try:
                    memory_manager.save_skill_usage(
                        skill_name=skill_rel,
                        target=current_target,
                        phase=current_phase,
                        success=True,
                        effectiveness_score=effectiveness_score,
                        tokens_saved=max(0, len(content) // 4),
                    )
                except Exception as exc:
                    logger.debug(
                        "Skill usage persistence failed for %s: %s", skill_rel, exc
                    )
            logger.info("Skill loaded dynamically: %s", skill_rel)

        except Exception as e:
            errors.append(f"Failed to load {skill_rel}: {e}")
            logger.warning("Skill load error for %s: %s", skill_rel, e)

    if replace_skills:
        agent_state.skills_used = list(current_skills)
    else:
        agent_state.skills_used = list(current_skills)

    summary = (
        f"Loaded {len(loaded_skills)} skill(s): {', '.join(loaded_skills)}"
        if loaded_skills
        else "No skills loaded"
    )

    return {
        "success": len(loaded_skills) > 0,
        "loaded_skills": loaded_skills,
        "total_active_skills": len(agent_state.skills_used),
        "message": summary,
        "errors": errors if errors else None,
    }
