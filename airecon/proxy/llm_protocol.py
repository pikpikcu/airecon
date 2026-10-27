"""Anthropic wire conversion, isolated from transport/retry ownership.

Adapted from PR #129 (202c0e9); signatures/usage/errors retain their native
contracts. No SDK or additional network endpoint is introduced here.
"""
from __future__ import annotations

import copy
import json
import uuid
from typing import Any, AsyncIterator, Callable


def anthropic_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    result = []
    for tool in tools or []:
        fn = tool.get("function") or tool
        if not fn.get("name"):
            continue
        result.append({"name": fn["name"], "description": fn.get("description", ""),
                       "input_schema": fn.get("parameters") or fn.get("input_schema") or {"type": "object", "properties": {}}})
    return result


_STOP_REASONS = {
    "tool_use": "tool_calls",
    "refusal": "content_filter",
    "model_context_window_exceeded": "length",
}


def anthropic_tail_thinking(messages: list[dict[str, Any]]) -> bool | None:
    """Preserve the thinking mode inside an open native tool-use turn."""
    for msg in reversed(messages or []):
        if not isinstance(msg, dict):
            return None
        role = msg.get("role")
        if role == "tool":
            continue
        if role != "assistant":
            return None
        native = msg.get("_provider_blocks")
        if isinstance(native, list) and native:
            if not any(isinstance(b, dict) and b.get("type") == "tool_use" for b in native):
                return None
            first = native[0] if isinstance(native[0], dict) else {}
            return first.get("type") in ("thinking", "redacted_thinking")
        if msg.get("tool_calls"):
            return False
        return None
    return None


def prompt_tokens(usage: dict[str, Any]) -> int:
    """Anthropic input_tokens excludes cache reads/writes."""
    return sum(int(usage.get(k) or 0) for k in (
        "input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))


def anthropic_error_status(error: Any) -> int:
    kind = str(error.get("type", "")) if isinstance(error, dict) else ""
    return {
        "invalid_request_error": 400, "authentication_error": 401,
        "billing_error": 402, "permission_error": 403, "not_found_error": 404,
        "request_too_large": 413, "rate_limit_error": 429, "api_error": 500,
        "timeout_error": 504, "overloaded_error": 529,
    }.get(kind, 500)


def anthropic_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    systems: list[str] = []
    result: list[dict[str, Any]] = []
    pending: list[str] = []
    emitted: set[str] = set()
    for original in messages:
        msg = original if isinstance(original, dict) else {"role": "user", "content": str(original)}
        role = msg.get("role", "user")
        text = str(msg.get("content") or "")
        if role == "system":
            if text.strip():
                systems.append(text)
            continue
        blocks: list[dict[str, Any]] = []
        if role == "assistant":
            native = msg.get("_provider_blocks")
            if isinstance(native, list) and native:
                # Signed thinking and its tool_use blocks must be replayed exactly.
                blocks = copy.deepcopy(native)
                ids = [b["id"] for b in blocks if b.get("type") == "tool_use"]
            else:
                if text.strip():
                    blocks.append({"type": "text", "text": text})
                ids = []
                for tc in msg.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        args = json.loads(args) if args.strip() else {}
                    if not isinstance(args, dict):
                        raise ValueError("Anthropic tool input must be a JSON object")
                    cid = tc.get("id") or "call_" + uuid.uuid4().hex[:24]
                    blocks.append({"type": "tool_use", "id": cid, "name": fn.get("name", ""), "input": args})
                    ids.append(cid)
            pending = list(ids)
            emitted.update(ids)
        elif role == "tool":
            cid = msg.get("tool_call_id")
            if not cid and pending:
                cid = pending[0]
            if not cid or cid not in emitted:
                continue
            if cid in pending:
                pending.remove(cid)
            blocks = [{"type": "tool_result", "tool_use_id": cid, "content": text or "[no output]"}]
            role = "user"
        elif text.strip():
            blocks = [{"type": "text", "text": text}]
            role = "user"
        if not blocks:
            continue
        if result and result[-1]["role"] == role:
            result[-1]["content"].extend(blocks)
        else:
            result.append({"role": role, "content": blocks})
    return "\n\n".join(systems), result


async def anthropic_lines(response: Any, stop: Callable[[], bool] | None) -> AsyncIterator[str]:
    """Normalize native SSE to the existing OpenAI accumulator's event shape."""
    blocks: dict[int, dict[str, Any]] = {}
    usage: dict[str, Any] = {}
    finish = None
    stopped = False
    async for line in response.aiter_lines():
        if stop and stop():
            return
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError("Invalid JSON in Anthropic event stream") from None
        kind = event.get("type")
        out: dict[str, Any] = {}
        if kind == "error":
            out = {"error": event.get("error") or {"message": "Anthropic streaming error"}}
        elif kind == "message_start":
            usage.update((event.get("message") or {}).get("usage") or {})
        elif kind == "content_block_start":
            index = event["index"]
            block = copy.deepcopy(event["content_block"])
            blocks[index] = block
            if block.get("type") == "tool_use":
                out = {"choices": [{"delta": {"tool_calls": [{"index": index, "id": block["id"], "function": {"name": block["name"], "arguments": ""}}]}}]}
                block["_input_json"] = ""
            elif block.get("type") == "text" and block.get("text"):
                out = {"choices": [{"delta": {"content": block["text"]}}]}
        elif kind == "content_block_delta":
            index = event["index"]
            delta = event.get("delta") or {}
            block = blocks.get(index)
            if block is None:
                raise RuntimeError("Anthropic delta has no content block start")
            dtype = delta.get("type")
            if dtype == "text_delta":
                text = delta.get("text", "")
                block["text"] = block.get("text", "") + text
                out = {"choices": [{"delta": {"content": text}}]}
            elif dtype == "thinking_delta":
                text = delta.get("thinking", "")
                block["thinking"] = block.get("thinking", "") + text
                out = {"choices": [{"delta": {"reasoning_content": text}}]}
            elif dtype == "signature_delta":
                block["signature"] = block.get("signature", "") + delta.get("signature", "")
            elif dtype == "input_json_delta":
                text = delta.get("partial_json", "")
                block["_input_json"] += text
                out = {"choices": [{"delta": {"tool_calls": [{"index": index, "function": {"arguments": text}}]}}]}
        elif kind == "message_delta":
            reason = (event.get("delta") or {}).get("stop_reason")
            if reason:
                finish = _STOP_REASONS.get(reason, reason)
            usage.update(event.get("usage") or {})
        elif kind == "message_stop":
            stopped = True
            native = []
            for index in sorted(blocks):
                block = blocks[index]
                partial = block.pop("_input_json", "")
                if partial:
                    try:
                        block["input"] = json.loads(partial)
                    except json.JSONDecodeError:
                        # Shared decoding rejects this batch; never invent {}.
                        block["input"] = None
                native.append(block)
            out = {"choices": [{"delta": {}, "finish_reason": finish}],
                   "usage": {"prompt_tokens": prompt_tokens(usage), "completion_tokens": int(usage.get("output_tokens") or 0)},
                   "_provider_blocks": native}
        if out:
            yield "data: " + json.dumps(out, ensure_ascii=False)
        if stopped:
            return
    if not stopped:
        raise RuntimeError("Anthropic stream ended before message_stop; incomplete response")
