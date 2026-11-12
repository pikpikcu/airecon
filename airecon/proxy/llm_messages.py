"""Shared message-order normalization for supported wire protocols."""
from __future__ import annotations

import copy
from typing import Any


def merge_provider_extensions(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Preserve nested opaque fields arriving on separate tool-call deltas."""
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
    # System text positioned after the last conversational turn is not part
    # of the system prompt — it is an instruction for the *next* reply (the
    # reflector's retry prompt is appended this way after a text-only turn).
    # Hoisting it to the top would leave the request ending on the
    # assistant's own text, which current Claude models reject with a 400
    # (prefilled-assistant rejection), so it is handled separately below.
    last_turn = -1
    for i, m in enumerate(messages):
        if m.get("role") != "system":
            last_turn = i

    # A system message that directly follows a *text-only* assistant turn
    # (e.g. the reflector's retry prompt, once the retried reply has landed)
    # is a chronological turn boundary. Hoisting it into the system prompt
    # would leave two adjacent assistant turns, which Anthropic conversion
    # merges into one — putting plain text before the signed thinking block
    # and breaking tool_use pairing. It must stay in place as a user turn,
    # both when the next turn is another assistant reply and when that reply
    # was already dropped by OpenAI-side conversion (a signed native turn
    # with no text and no tool_calls leaves only its tool_result user turn).
    # A system note after an assistant turn that carries tool calls (or
    # native tool_use blocks) is NOT a boundary: inserting a user turn
    # between a tool call and its results breaks tool pairing on both
    # protocols, so such notes are hoisted into the system prompt as before.
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
                    # Keep its chronological place as a user turn after the
                    # assistant turn it follows; join consecutive ones.
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
        # Already a single leading system message — nothing to reorder.
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
            # Keep the trailing instruction at the end as a user turn so
            # the request ends on the user, carrying the prompt with it.
            out.append({"role": "user", "content": "\n\n".join(trailing_parts)})
        elif out and out[0].get("role") == "system":
            # The conversation does not end on a plain assistant turn, so
            # the trailing text can join the system prompt as before.
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
