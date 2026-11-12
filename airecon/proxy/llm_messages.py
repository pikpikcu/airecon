from __future__ import annotations

import copy
from typing import Any


def merge_provider_extensions(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key, value in incoming.items():
        previous = target.get(key)
        if isinstance(previous, dict) and isinstance(value, dict):
            merge_provider_extensions(previous, value)
        else:
            target[key] = copy.deepcopy(value)


def _nearest_turn_role(messages: list[dict[str, Any]], indices: range) -> Any:
    for j in indices:
        if messages[j].get("role") != "system":
            return messages[j].get("role")
    return None


def _coalesce_system_messages(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    last_turn = -1
    for i, m in enumerate(messages):
        if m.get("role") != "system":
            last_turn = i

    inline_boundaries: dict[int, str] = {}
    for i, m in enumerate(messages):
        if m.get("role") != "system" or i > last_turn:
            continue
        text = str(m.get("content", "")).strip()
        if not text:
            continue
        for j in range(i - 1, -1, -1):
            if messages[j].get("role") == "system":
                continue
            if messages[j].get("role") != "assistant":
                break
            if messages[j].get("tool_calls"):
                break
            if any(
                isinstance(block, dict) and block.get("type") == "tool_use"
                for block in messages[j].get("_provider_blocks") or []
            ):
                break
            inline_boundaries[i] = text
            break

    system_parts: list[str] = []
    trailing_parts: list[str] = []
    others: list[dict[str, Any]] = []
    for i, m in enumerate(messages):
        if m.get("role") == "system":
            text = str(m.get("content", "")).strip()
            if text:
                if i in inline_boundaries:
                    if others and others[-1].get("role") == "user" and others[-1].get("_inline_boundary"):
                        others[-1]["content"] += "\n\n" + inline_boundaries[i]
                    else:
                        others.append({"role": "user", "content": inline_boundaries[i], "_inline_boundary": True})
                elif i > last_turn:
                    trailing_parts.append(text)
                else:
                    system_parts.append(text)
        else:
            others.append(m)

    if not system_parts and not trailing_parts and not inline_boundaries:
        return others
    if (
        len(system_parts) == 1
        and not trailing_parts
        and not inline_boundaries
        and messages
        and messages[0].get("role") == "system"
    ):
        return messages

    out: list[dict[str, Any]] = []
    if system_parts:
        merged = {"role": "system", "content": "\n\n".join(system_parts)}
        out.append(merged)
    out.extend(others)

    if trailing_parts:
        last = others[-1] if others else None
        if (
            last is not None
            and last.get("role") == "assistant"
            and not last.get("tool_calls")
            and not any(
                isinstance(block, dict) and block.get("type") == "tool_use"
                for block in last.get("_provider_blocks") or []
            )
        ):
            out.append({"role": "user", "content": "\n\n".join(trailing_parts)})
        elif out and out[0].get("role") == "system":
            out[0] = {
                "role": "system",
                "content": "\n\n".join(system_parts + trailing_parts),
            }
        else:
            out.insert(
                0, {"role": "system", "content": "\n\n".join(trailing_parts)}
            )
    for msg in out:
        if isinstance(msg, dict):
            msg.pop("_inline_boundary", None)
    return out
