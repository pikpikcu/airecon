from __future__ import annotations

import asyncio
import copy
import json
import logging
import re
import threading
import time
import uuid
from typing import Any, AsyncIterator, Callable, Dict
from urllib.parse import urlsplit

import httpx

from .config import get_config
from .memory import get_memory_manager
from .llm_messages import _coalesce_system_messages, merge_provider_extensions
from .llm_protocol import (
    anthropic_error_status,
    anthropic_lines,
    anthropic_messages,
    anthropic_tail_thinking,
    anthropic_tools,
)

_ANTHROPIC_AUTH_MODES = ("x-api-key", "bearer", "both")

logger = logging.getLogger("airecon.llm")

_CONTEXT_RESET_THRESHOLD = 65536

_ALLOWED_MESSAGE_KEYS = frozenset(
    {"role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content"}
)


def _replay_key(model: str, host: str) -> tuple[str, str]:
    return (host.rstrip("/").lower(), model)


def reasoning_replay_enabled(model: str | None = None, host: str | None = None) -> bool:
    cfg = get_config()
    mode = str(getattr(cfg, "llm_reasoning_replay", "auto") or "auto").strip().lower()
    if mode == "always":
        return True
    if mode == "off":
        return False
    model = str(model if model is not None else getattr(cfg, "openai_model", "") or "")
    host = str(host if host is not None else getattr(cfg, "openai_base_url", "") or "")
    hostname = (urlsplit(host).hostname or "").lower()
    return (
        _replay_key(model, host) in LLMClient._reasoning_replay_models
        or "deepseek" in hostname
        or model.lower().startswith("deepseek/")
    )


def _to_openai_tool_calls(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tc in tool_calls or []:
        fn = tc.get("function", {}) or {}
        args = fn.get("arguments", {})
        if not isinstance(args, str):
            try:
                args = json.dumps(args, ensure_ascii=False)
            except Exception:
                args = "{}"
        out.append(
            {
                "id": tc.get("id") or f"call_{uuid.uuid4().hex[:24]}",
                "type": "function",
                "function": {"name": fn.get("name", ""), "arguments": args},
            }
        )
        if "extra_content" in tc:
            out[-1]["extra_content"] = copy.deepcopy(tc["extra_content"])
    return out


def _to_openai_messages(
    messages: list[dict[str, Any]], *, replay_reasoning: bool | None = None,
) -> list[dict[str, Any]]:
    if replay_reasoning is None:
        replay_reasoning = reasoning_replay_enabled()
    converted: list[dict[str, Any]] = []
    pending_tool_ids: list[str] = []
    emitted_call_ids: set[str] = set()
    for msg in messages or []:
        if not isinstance(msg, dict):
            converted.append({"role": "user", "content": str(msg)})
            continue

        role = msg.get("role", "user")
        new_msg: dict[str, Any] = {"role": role}

        content = msg.get("content", "")
        new_msg["content"] = content if content is not None else ""

        if replay_reasoning and role == "assistant" and "reasoning_content" in msg:
            new_msg["reasoning_content"] = msg["reasoning_content"]

        if role == "assistant" and msg.get("tool_calls"):
            oai_calls = _to_openai_tool_calls(msg["tool_calls"])
            new_msg["tool_calls"] = oai_calls
            pending_tool_ids = [c["id"] for c in oai_calls]
            emitted_call_ids.update(pending_tool_ids)

        if role == "tool":
            tcid = msg.get("tool_call_id")
            if not tcid and pending_tool_ids:
                tcid = pending_tool_ids.pop(0)

            if not tcid or tcid not in emitted_call_ids:
                logger.debug(
                    "Dropping orphaned tool result (tool_call_id=%r) with no "
                    "matching assistant tool_call in payload",
                    tcid,
                )
                continue
            new_msg["tool_call_id"] = tcid
            name = msg.get("name")
            if name:
                new_msg["name"] = name

        new_msg = {k: v for k, v in new_msg.items() if k in _ALLOWED_MESSAGE_KEYS}

        _has_text = bool(str(new_msg.get("content", "")).strip())
        if role == "tool":
            if not _has_text:
                new_msg["content"] = "[no output]"
        elif role == "assistant":
            if not _has_text and not new_msg.get("tool_calls"):
                continue
        else:
            if not _has_text:
                continue

        converted.append(new_msg)
    return _coalesce_system_messages(converted)


_RETRY_AFTER_RE = re.compile(
    r"(?:reset|retry|again|available)[^0-9]{0,20}?(\d+(?:\.\d+)?)\s*(s|sec|second)",
    re.IGNORECASE,
)


def _is_retryable_status(status_code: int) -> bool:
    return status_code == 429 or status_code == 408 or 500 <= status_code < 600


def _retry_wait_seconds(status_code: int, message: str, attempt: int) -> float:
    base = 5.0 * (attempt + 1)
    if status_code == 429:
        m = _RETRY_AFTER_RE.search(message or "")
        if m:
            try:
                return min(30.0, max(base, float(m.group(1)) + 1.0))
            except (TypeError, ValueError):
                pass
    return min(30.0, base)


class LLMBackendHTTPError(RuntimeError):
    def __init__(self, status_code: int, message: str) -> None:
        self.is_context_error = any(marker in message.lower() for marker in (
            "no user query found in messages", "context_length_exceeded",
            "maximum context length", "context window exceeded",
            "exceeds the context window", "prompt is too long", "input is too long",
            "too many tokens",
        ))
        self.retryable = _is_retryable_status(status_code) and not self.is_context_error
        if self.is_context_error and "no user query found in messages" in message.lower():
            message += (
                "\n\nBackend context/history error (non-retryable). Ollama can "
                "drop the user turn when the server context window is too small. "
                "Set server-side OLLAMA_CONTEXT_LENGTH or Modelfile PARAMETER "
                "num_ctx to a size the server supports, verify context_length "
                "via /api/ps, and match AIRecon's llm_context_window to it. "
                "Ollama /v1 ignores the request's num_ctx; changing only the "
                "client setting does not enlarge the server context. Also "
                "ensure the conversation contains a non-empty user message. "
                "Retrying the unchanged request will not fix this error."
            )
        super().__init__(message)
        self.status_code = status_code


class LLMReasoningReplayRequired(LLMBackendHTTPError):
    pass


class LLMToolCallError(RuntimeError):
    def __init__(self, tool_name: str, reason: str) -> None:
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"Invalid tool-call arguments for {tool_name}: {reason}")


def _decode_tool_arguments(
    name: str, raw: str, tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    try:
        arguments = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise LLMToolCallError(name, "arguments must be a complete JSON object") from exc
    if not isinstance(arguments, dict):
        raise LLMToolCallError(name, "arguments must be a JSON object")
    schema = next((
        (tool.get("function") or {}).get("parameters") or {}
        for tool in tools or [] if (tool.get("function") or {}).get("name") == name
    ), {})
    properties = schema.get("properties") or {}
    for key in schema.get("required") or []:
        if key not in arguments or arguments[key] is None:
            raise LLMToolCallError(name, f"missing required argument '{key}'")
        if (properties.get(key) or {}).get("type") == "string":
            value = arguments[key]
            if not isinstance(value, str):
                raise LLMToolCallError(name, f"required argument '{key}' must be a string")
            if name == "execute" and key == "command" and not value.strip():
                raise LLMToolCallError(name, "required argument 'command' must be a non-empty string")
            if len(value) < (properties[key].get("minLength") or 0):
                raise LLMToolCallError(name, f"required argument '{key}' is too short")
    return arguments


class LLMClient:
    _global_semaphore: asyncio.Semaphore | None = None
    _httpx_client: httpx.AsyncClient | None = None
    _initialized: bool = False
    _init_lock: asyncio.Lock | None = None
    _semaphore_init_lock = threading.Lock()
    _reasoning_unsupported: set[str] = set()
    _unsupported_params: dict[str, set[str]] = {}
    _reasoning_replay_models: set[tuple[str, str]] = set()

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        cfg = get_config()
        host = (base_url or cfg.openai_base_url).rstrip("/")
        self._host = host
        self.model = model or cfg.openai_model

        self._api_key = (cfg.openai_api_key or "").strip()
        self._backend_name = "OpenAI-compatible"
        provider = str(getattr(cfg, "llm_provider", "openai") or "openai").lower()
        self._is_anthropic = provider in ("anthropic", "claude")
        self._anthropic_auth = "x-api-key"
        if self._is_anthropic:
            self._backend_name = "Anthropic-compatible"
            mode = str(getattr(cfg, "llm_anthropic_auth", "x-api-key") or "x-api-key").strip().lower()
            if mode not in _ANTHROPIC_AUTH_MODES:
                raise ValueError(f"llm_anthropic_auth must be one of {', '.join(_ANTHROPIC_AUTH_MODES)}")
            self._anthropic_auth = mode
        self._supports_native_tools = bool(cfg.openai_supports_native_tools)

        self._enable_thinking = bool(getattr(cfg, "llm_enable_thinking", False))
        self._thinking_intensity = (
            str(getattr(cfg, "llm_thinking_mode", "low") or "low").strip().lower()
        )
        self._thinking_request_mode = (
            str(getattr(cfg, "llm_thinking_request_mode", "auto") or "auto")
            .strip()
            .lower()
        )
        self._thinking_strategy = self._resolve_thinking_strategy(
            self.model, self._thinking_request_mode
        )
        self._supports_thinking = bool(cfg.openai_supports_thinking) or (
            self._enable_thinking and self._thinking_strategy != "off"
        )

        logger.info(
            "Initializing LLM client host=%s model=%s thinking=%s strategy=%s tools=%s",
            host,
            self.model,
            self._supports_thinking,
            self._thinking_strategy,
            self._supports_native_tools,
        )

        if LLMClient._global_semaphore is None:
            with LLMClient._semaphore_init_lock:
                if LLMClient._global_semaphore is None:
                    try:
                        _n = max(1, int(getattr(cfg, "llm_max_concurrent_requests", 1)))
                    except (TypeError, ValueError):
                        _n = 1
                    LLMClient._global_semaphore = asyncio.Semaphore(_n)
        self._request_semaphore = LLMClient._global_semaphore

    async def _async_init(self) -> None:
        if LLMClient._initialized:
            return

        if LLMClient._init_lock is None:
            LLMClient._init_lock = asyncio.Lock()

        async with LLMClient._init_lock:
            if LLMClient._initialized:
                return

            logger.info(
                "Initializing LLM httpx client (async init) for model: %s", self.model
            )
            if LLMClient._httpx_client is None:
                _cfg = get_config()
                _http_timeout = _cfg.llm_timeout
                LLMClient._httpx_client = httpx.AsyncClient(  # nosec B113: timeout configured below
                    timeout=httpx.Timeout(
                        _http_timeout, connect=10.0, read=_http_timeout, write=10.0
                    ),
                    headers={"Content-Type": "application/json"},
                )
                LLMClient._initialized = True
            logger.info("LLM httpx client initialized")

    def _endpoint(self) -> str:
        return "/messages" if getattr(self, "_is_anthropic", False) else "/chat/completions"

    def _wire_payload(self, messages: list[dict[str, Any]], stream: bool) -> dict[str, Any]:
        if getattr(self, "_is_anthropic", False):
            system, converted = anthropic_messages(messages)
            payload: dict[str, Any] = {"model": self.model, "messages": converted, "stream": stream}
            if system:
                payload["system"] = system
            return payload
        messages_out = _to_openai_messages(
            messages, replay_reasoning=reasoning_replay_enabled(self.model, self._host),
        )
        return {"model": self.model, "messages": messages_out, "stream": stream}

    async def _wire_lines(self, response: Any, stop: Callable[[], bool] | None) -> AsyncIterator[str]:
        if getattr(self, "_is_anthropic", False):
            async for line in anthropic_lines(response, stop):
                yield line
        else:
            async for line in response.aiter_lines():
                yield line

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]] | None:
        cfg = get_config()
        embedding_model = model or getattr(cfg, "embedding_model", "")
        if not embedding_model or not texts or not getattr(cfg, "intelligence_embeddings_enabled", True):
            return None
        if getattr(self, "_is_anthropic", False):
            return None
        try:
            await self._async_init()
            response = await self._post("/embeddings", {"model": embedding_model, "input": texts}, 30.0)
            rows = sorted(response.json().get("data", []), key=lambda row: row["index"])
            if [row["index"] for row in rows] != list(range(len(texts))):
                return None
            import math
            vectors = [[float(value) for value in row["embedding"]] for row in rows]
            if not vectors or not vectors[0] or any(len(v) != len(vectors[0]) or not all(math.isfinite(x) for x in v) for v in vectors):
                return None
            return vectors
        except (RuntimeError, httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            logger.debug("Embedding unavailable: %s", type(exc).__name__)
            return None

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if getattr(self, "_is_anthropic", False):
            headers["anthropic-version"] = "2023-06-01"
            mode = getattr(self, "_anthropic_auth", "x-api-key")
            if self._api_key and mode in ("x-api-key", "both"):
                headers["x-api-key"] = self._api_key
            if self._api_key and mode in ("bearer", "both"):
                headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _apply_options(
        self, payload: dict[str, Any], options: dict[str, Any] | None
    ) -> None:
        cfg = get_config()
        max_tokens = cfg.openai_max_tokens
        temperature: float | None = getattr(cfg, "openai_temperature", None)
        if options:
            if options.get("num_predict") is not None:
                try:
                    np = int(options["num_predict"])
                    if np > 0:
                        max_tokens = np
                except (TypeError, ValueError):
                    pass
            if options.get("temperature") is not None:
                try:
                    temperature = float(options["temperature"])
                except (TypeError, ValueError):
                    pass
        stripped = LLMClient._unsupported_params.get(self.model, set())
        if max_tokens and max_tokens > 0:
            token_key = "max_completion_tokens" if "max_tokens" in stripped else "max_tokens"
            payload[token_key] = int(max_tokens)
        if temperature is not None and "temperature" not in stripped:
            payload["temperature"] = float(temperature)

        if options and not getattr(self, "_is_anthropic", False):
            _stripped = LLMClient._unsupported_params.get(self.model, set())
            for _k in ("num_ctx", "num_keep", "repeat_penalty"):
                _v = options.get(_k)
                if _v is not None and _k not in _stripped:
                    payload[_k] = _v

    @staticmethod
    def _resolve_thinking_strategy(model: str, mode: str) -> str:
        mode = (mode or "auto").strip().lower()
        if mode in ("off", "reasoning_effort", "enable_thinking"):
            return mode
        return "reasoning_effort"

    def _reasoning_effort_value(self) -> str:
        return {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "adaptive": "medium",
        }.get(self._thinking_intensity, "medium")

    def _apply_thinking(self, payload: dict[str, Any], think: bool) -> None:
        if not self._enable_thinking:
            return
        if getattr(self, "_is_anthropic", False):
            if think and self.model not in LLMClient._reasoning_unsupported:
                maximum = int(payload.get("max_tokens", 0))
                if maximum > 1024:
                    budgets = {"low": 1024, "medium": 4096, "adaptive": 4096, "high": 16000}
                    payload["thinking"] = {"type": "enabled", "budget_tokens": min(budgets.get(self._thinking_intensity, 4096), maximum - 1)}
                    payload.pop("temperature", None)
            return
        strat = self._thinking_strategy
        if strat == "reasoning_effort":
            if think and self.model not in LLMClient._reasoning_unsupported:
                payload["reasoning_effort"] = self._reasoning_effort_value()
        elif strat == "enable_thinking":
            ctk = dict(payload.get("chat_template_kwargs") or {})
            ctk["enable_thinking"] = bool(think)
            payload["chat_template_kwargs"] = ctk

    @staticmethod
    def _is_unsupported_reasoning_error(status_code: int, body: str) -> bool:
        if status_code != 400:
            return False
        b = (body or "").lower()
        if "reasoning_content" in b or "thought_signature" in b:
            return False
        mentions_reasoning = (
            "reasoning_effort" in b
            or "reasoning.effort" in b
            or "reasoning" in b
            or "thinking" in b
        )
        if not mentions_reasoning:
            return False
        return any(
            kw in b
            for kw in (
                "unsupported",
                "not supported",
                "does not support",
                "unknown",
                "unexpected",
                "invalid",
                "not permitted",
                "unrecognized",
            )
        )

    def _learn_reasoning_replay(
        self, messages: list[dict[str, Any]], status_code: int, body: str,
    ) -> bool:
        if getattr(self, "_is_anthropic", False) or status_code != 400:
            return False
        if "reasoning_content" not in (body or "").lower():
            return False
        mode = str(getattr(get_config(), "llm_reasoning_replay", "auto") or "auto").strip().lower()
        if mode == "off" or reasoning_replay_enabled(self.model, self._host):
            return False
        if not any(
            isinstance(m, dict) and m.get("role") == "assistant" and "reasoning_content" in m
            for m in messages or []
        ):
            return False
        LLMClient._reasoning_replay_models.add(_replay_key(self.model, self._host))
        logger.warning(
            "Backend %s requires reasoning_content replay for model=%s; "
            "later requests carry it.",
            self._host, self.model,
        )
        return True

    def _maybe_degrade_reasoning(
        self, payload: dict[str, Any], status_code: int, body: str
    ) -> bool:
        if not self._is_unsupported_reasoning_error(status_code, body):
            return False
        removed = False
        if payload.pop("thinking", None) is not None:
            removed = True
        if payload.pop("reasoning_effort", None) is not None:
            removed = True
        ctk = payload.get("chat_template_kwargs")
        if isinstance(ctk, dict) and "enable_thinking" in ctk:
            ctk.pop("enable_thinking", None)
            removed = True
            if not ctk:
                payload.pop("chat_template_kwargs", None)
        if removed:
            LLMClient._reasoning_unsupported.add(self.model)
            logger.warning(
                "Backend rejected reasoning params for model=%s; disabling "
                "reasoning for this model and retrying.",
                self.model,
            )
        return removed

    @staticmethod
    def _named_unsupported_param(body: str) -> str | None:
        m = re.search(
            r"(?:unsupported|unknown|unexpected|unrecognized|invalid|not\s+"
            r"(?:a\s+)?(?:valid|supported|permitted))[^'\"]*['\"]([a-zA-Z0-9_.]+)['\"]",
            body or "",
            re.IGNORECASE,
        )
        return m.group(1) if m else None

    _OPTIONAL_PARAMS = ("num_ctx", "num_keep", "repeat_penalty", "temperature", "stream_options")

    def _maybe_degrade_unsupported_param(
        self, payload: dict[str, Any], status_code: int, body: str
    ) -> bool:
        if status_code != 400:
            return False
        body_l = (body or "").lower()
        if not re.search(r"unsupported|unknown|unexpected|unrecognized|not\s+(?:supported|permitted)|extra inputs", body_l):
            return False
        to_strip: set[str] = set()
        for k in self._OPTIONAL_PARAMS:
            if k in payload and k.lower() in body_l:
                to_strip.add(k)
        named = self._named_unsupported_param(body)
        if not getattr(self, "_is_anthropic", False) and "max_tokens" in payload and (named == "max_tokens" or "'max_tokens'" in body_l):
            payload["max_completion_tokens"] = payload.pop("max_tokens")
            LLMClient._unsupported_params.setdefault(self.model, set()).add("max_tokens")
            return True
        if not to_strip:
            return False
        for k in to_strip:
            payload.pop(k, None)
        LLMClient._unsupported_params.setdefault(self.model, set()).update(to_strip)
        logger.warning(
            "Backend rejected param(s) %s for model=%s; stripping for this model "
            "and retrying.",
            sorted(to_strip),
            self.model,
        )
        return True

    async def _post(
        self, endpoint: str, json_data: dict[str, Any], timeout: float
    ) -> httpx.Response:
        async with self._request_semaphore:
            client = LLMClient._httpx_client
            if client is None:
                raise RuntimeError("HTTP client not initialized")
            url = f"{self._host}{endpoint}"
            to = httpx.Timeout(timeout, connect=10.0, read=timeout, write=10.0)
            resp = await client.request(
                "POST",
                url,
                json=json_data,
                headers=self._auth_headers(),
                timeout=to,
            )
            if resp.status_code >= 400:
                try:
                    body = resp.text[:500]
                except Exception:
                    body = "<unreadable body>"
                logger.error(
                    "LLM backend POST %s -> HTTP %d: %s",
                    endpoint,
                    resp.status_code,
                    body,
                )
                raise LLMBackendHTTPError(
                    resp.status_code,
                    f"{self._backend_name} returned HTTP {resp.status_code} "
                    f"for {endpoint}: {body}",
                )
            return resp

    async def reset_context(self, system_prompt: str | None = None) -> bool:
        self._last_reset_error = ""
        self._last_reset_status = None
        return True

    async def unload_model(self) -> None:
        return None

    async def close(self) -> None:
        client = LLMClient._httpx_client
        if client is not None:
            await client.aclose()
        LLMClient._httpx_client = None
        LLMClient._initialized = False

    async def _detect_capabilities(self) -> tuple[bool, bool] | None:
        return self._supports_thinking, self._supports_native_tools

    @property
    def supports_thinking(self) -> bool:
        return self._supports_thinking

    @property
    def supports_native_tools(self) -> bool:
        return self._supports_native_tools

    async def health_check(self) -> bool:
        try:
            client = LLMClient._httpx_client
            if client is None:
                return False
            resp = await client.get(
                f"{self._host}/models",
                headers=self._auth_headers(),
                timeout=httpx.Timeout(10.0),
            )
            return resp.status_code < 500
        except Exception as e:
            logger.warning("LLM health check failed: %s", e)
            return False

    async def complete(
        self,
        messages: list[dict[str, Any]],
        max_retries: int = 3,
        options: dict[str, Any] | None = None,
        operation: str = "compression",
    ) -> str:
        return await self._complete_impl(messages, max_retries, options, operation)

    async def _complete_impl(
        self,
        messages: list[dict[str, Any]],
        max_retries: int = 3,
        options: dict[str, Any] | None = None,
        operation: str = "compression",
    ) -> str:
        max_retries = max(0, max_retries)
        request_started = time.monotonic()
        payload: dict[str, Any] = self._wire_payload(messages, False)
        self._apply_options(payload, options)

        try:
            attempt = 0
            while attempt <= max_retries:
                try:
                    timeout = self._get_dynamic_timeout(operation)
                    resp = await self._post(self._endpoint(), payload, timeout)
                    data = resp.json()

                    content: str | None = None
                    if getattr(self, "_is_anthropic", False) and isinstance(data, dict):
                        if data.get("type") == "error" or data.get("error"):
                            error = data.get("error") or {}
                            message = error.get("message", "Anthropic error") if isinstance(error, dict) else "Anthropic error"
                            raise LLMBackendHTTPError(anthropic_error_status(error), str(message))
                        blocks = data.get("content")
                        if isinstance(blocks, list):
                            content = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
                    elif isinstance(data, dict):
                        choices = data.get("choices") or []
                        if choices:
                            content = (choices[0].get("message") or {}).get("content")

                    if content is None:
                        logger.warning(
                            "LLM backend returned unexpected format: %r (attempt %d/%d)",
                            data,
                            attempt + 1,
                            max_retries + 1,
                        )
                        if attempt < max_retries:
                            await asyncio.sleep(2 ** (attempt + 1))
                            attempt += 1
                            continue
                        raise RuntimeError(
                            "Invalid LLM response: missing choices[0].message.content"
                        )

                    elapsed = time.monotonic() - request_started
                    self._record_response_time(elapsed)
                    self._record_model_performance(
                        operation=operation,
                        response_time_sec=elapsed,
                        success=True,
                        messages=messages,
                        options=options,
                    )
                    return content or ""

                except LLMBackendHTTPError as e:
                    if self._learn_reasoning_replay(messages, e.status_code, str(e)):
                        payload["messages"] = _to_openai_messages(messages, replay_reasoning=True)
                        continue
                    if self._maybe_degrade_unsupported_param(payload, e.status_code, str(e)):
                        continue
                    if e.retryable and attempt < max_retries:
                        _wait = _retry_wait_seconds(e.status_code, str(e), attempt)
                        logger.warning(
                            "LLM HTTP %d (retryable) — backing off %.1fs "
                            "(attempt %d/%d)",
                            e.status_code,
                            _wait,
                            attempt + 1,
                            max_retries + 1,
                        )
                        await asyncio.sleep(_wait)
                        attempt += 1
                        continue
                    raise
                except RuntimeError:
                    raise
                except httpx.HTTPStatusError as e:
                    if 500 <= e.response.status_code < 600 and attempt < max_retries:
                        await asyncio.sleep(5 * (attempt + 1))
                        attempt += 1
                        continue
                    raise
                except (httpx.NetworkError, httpx.TimeoutException, asyncio.TimeoutError):
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** (attempt + 1))
                        attempt += 1
                        continue
                    raise

            raise RuntimeError("Unexpected code path in LLM _complete_impl()")
        except Exception:
            elapsed = time.monotonic() - request_started
            self._record_model_performance(
                operation=operation,
                response_time_sec=elapsed,
                success=False,
                messages=messages,
                options=options,
            )
            raise

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        think: bool = False,
        max_retries: int = 3,
        operation: str = "chat",
        stop_requested_fn: Callable[[], bool] | None = None,
    ) -> AsyncIterator[Any]:
        async for chunk in self._chat_stream_impl(
            messages,
            tools,
            options,
            think,
            max_retries,
            operation,
            stop_requested_fn,
        ):
            yield chunk

    async def _chat_stream_impl(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        think: bool = False,
        max_retries: int = 3,
        operation: str = "chat",
        stop_requested_fn: Callable[[], bool] | None = None,
    ) -> AsyncIterator[Any]:
        cfg = get_config()
        payload: dict[str, Any] = self._wire_payload(messages, True)
        if not getattr(self, "_is_anthropic", False):
            payload["stream_options"] = {"include_usage": True}
        if tools and self._supports_native_tools:
            payload["tools"] = anthropic_tools(tools) if getattr(self, "_is_anthropic", False) else tools
        elif tools and not self._supports_native_tools:
            logger.debug(
                "Native tools disabled — omitting %d tool schemas from payload",
                len(tools),
            )
        self._apply_options(payload, options)
        if getattr(self, "_is_anthropic", False):
            open_turn = anthropic_tail_thinking(messages)
            if open_turn is not None:
                think = open_turn
        self._apply_thinking(payload, think)

        if "stream_options" in LLMClient._unsupported_params.get(self.model, set()):
            payload.pop("stream_options", None)

        overall_timeout = cfg.llm_timeout
        chunk_timeout = cfg.llm_chunk_timeout
        request_started = time.monotonic()

        attempt = 0
        while attempt <= max(0, max_retries):
            tool_acc: dict[int, dict[str, Any]] = {}
            tool_ids: dict[int, str] = {}
            usage: dict[str, Any] = {}
            produced_any = False
            finish_reason: str | None = None
            provider_blocks = None
            reasoning_parts: list[str] = []
            saw_reasoning_content = False
            try:
                async with self._request_semaphore:
                    client = LLMClient._httpx_client
                    if client is None:
                        raise RuntimeError("HTTP client not initialized")
                    url = f"{self._host}{self._endpoint()}"
                    timeout_obj = httpx.Timeout(
                        overall_timeout, connect=10.0, read=chunk_timeout, write=10.0
                    )
                    async with client.stream(
                        "POST",
                        url,
                        json=payload,
                        headers=self._auth_headers(),
                        timeout=timeout_obj,
                    ) as resp:
                        if resp.status_code >= 400:
                            try:
                                await resp.aread()
                                body = resp.text[:500]
                            except Exception:
                                body = "<unreadable body>"
                            if self._learn_reasoning_replay(messages, resp.status_code, body):
                                raise LLMReasoningReplayRequired(
                                    resp.status_code,
                                    f"{self._backend_name} returned HTTP "
                                    f"{resp.status_code} for {self._endpoint()}: {body}",
                                )
                            if self._maybe_degrade_reasoning(
                                payload, resp.status_code, body
                            ) or self._maybe_degrade_unsupported_param(
                                payload, resp.status_code, body
                            ):
                                continue
                            logger.error(
                                "LLM backend STREAM %s -> HTTP %d: %s",
                                self._endpoint(),
                                resp.status_code,
                                body,
                            )
                            raise LLMBackendHTTPError(
                                resp.status_code,
                                f"{self._backend_name} returned HTTP "
                                f"{resp.status_code} for {self._endpoint()}: {body}",
                            )
                        async for raw_line in self._wire_lines(resp, stop_requested_fn):
                            if stop_requested_fn and stop_requested_fn():
                                return
                            if not raw_line:
                                continue
                            line = raw_line.strip()
                            if not line.startswith("data:"):
                                continue
                            data_str = line[len("data:"):].strip()
                            if data_str == "[DONE]":
                                break
                            try:
                                evt = json.loads(data_str)
                            except json.JSONDecodeError:
                                raise RuntimeError(f"{self._backend_name} sent invalid JSON in a stream event; response discarded") from None

                            if evt.get("error"):
                                error = evt["error"]
                                message = error.get("message", "LLM streaming error") if isinstance(error, dict) else "LLM streaming error"
                                if getattr(self, "_is_anthropic", False):
                                    status = anthropic_error_status(error)
                                else:
                                    error_type = str(error.get("type", "")) if isinstance(error, dict) else ""
                                    status = 429 if "rate_limit" in error_type else 500
                                raise LLMBackendHTTPError(status, str(message))

                            if isinstance(evt.get("usage"), dict):
                                usage = evt["usage"]
                            if evt.get("_provider_blocks") is not None:
                                provider_blocks = evt["_provider_blocks"]

                            choices = evt.get("choices") or []
                            if not choices:
                                continue
                            choice0 = choices[0]
                            delta = choice0.get("delta") or {}
                            if choice0.get("finish_reason"):
                                finish_reason = choice0["finish_reason"]

                            if not self._is_anthropic and isinstance(
                                delta.get("reasoning_content"), str,
                            ):
                                saw_reasoning_content = True
                                reasoning_parts.append(delta["reasoning_content"])
                            reasoning = delta.get("reasoning_content") or delta.get(
                                "reasoning"
                            )
                            if reasoning:
                                produced_any = True
                                yield {
                                    "message": {
                                        "role": "assistant",
                                        "thinking": reasoning,
                                    },
                                    "done": False,
                                }

                            content = delta.get("content")
                            if not content and delta.get("refusal"):
                                content = delta["refusal"]
                            if content:
                                produced_any = True
                                yield {
                                    "message": {
                                        "role": "assistant",
                                        "content": content,
                                    },
                                    "done": False,
                                }

                            for tc in delta.get("tool_calls") or []:
                                idx = tc.get("index", 0)
                                slot = tool_acc.setdefault(idx, {"name": "", "args": ""})
                                if tc.get("id"):
                                    tool_ids[idx] = tc["id"]
                                if isinstance(tc.get("extra_content"), dict):
                                    merge_provider_extensions(
                                        slot.setdefault("extra_content", {}), tc["extra_content"],
                                    )
                                fn = tc.get("function") or {}
                                if fn.get("name"):
                                    slot["name"] = fn["name"]
                                if fn.get("arguments"):
                                    if not isinstance(fn["arguments"], str):
                                        raise LLMToolCallError(slot["name"], "stream arguments must be JSON text")
                                    slot["args"] += fn["arguments"]

                if stop_requested_fn and stop_requested_fn():
                    return
                if tool_acc and finish_reason in ("length", "max_tokens"):
                    raise LLMToolCallError("tool batch", "tool-call response was truncated by the output length limit")
                if tool_acc and finish_reason is None:
                    raise LLMToolCallError("tool batch", "stream ended without a finish reason; tool batch may be truncated")
                final_tool_calls: list[dict[str, Any]] = []
                for idx in sorted(tool_acc):
                    slot = tool_acc[idx]
                    if not slot["name"]:
                        continue
                    raw_args = slot["args"].strip()
                    parsed_args = _decode_tool_arguments(slot["name"], raw_args, tools)
                    final_call = {
                        "id": tool_ids.get(idx, f"call_{uuid.uuid4().hex[:24]}"),
                        "function": {"name": slot["name"], "arguments": parsed_args},
                    }
                    if "extra_content" in slot:
                        final_call["extra_content"] = copy.deepcopy(slot["extra_content"])
                    final_tool_calls.append(final_call)

                final_message: dict[str, Any] = {"role": "assistant", "content": ""}
                if saw_reasoning_content:
                    final_message["reasoning_content"] = "".join(reasoning_parts)
                if provider_blocks:
                    final_message["_provider_blocks"] = provider_blocks
                if final_tool_calls:
                    final_message["tool_calls"] = final_tool_calls
                    produced_any = True

                if not produced_any and finish_reason in ("content_filter", "error"):
                    self._record_model_performance(
                        operation=operation,
                        response_time_sec=time.monotonic() - request_started,
                        success=False,
                        messages=messages,
                        options=options,
                    )
                    raise RuntimeError(
                        f"{self._backend_name} returned an empty completion "
                        f"(finish_reason={finish_reason!r}) — the model produced no "
                        "content, reasoning, or tool calls. This is typically a "
                        "provider-side safety block or a rejected request."
                    )

                yield {
                    "message": final_message,
                    "done": True,
                    "prompt_eval_count": int(usage.get("prompt_tokens", 0) or 0),
                    "eval_count": int(usage.get("completion_tokens", 0) or 0),
                }

                elapsed_total = time.monotonic() - request_started
                if produced_any:
                    self._record_response_time(elapsed_total)
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=elapsed_total,
                    success=True,
                    messages=messages,
                    options=options,
                )
                return

            except LLMBackendHTTPError as e:
                if e.retryable and attempt < max_retries and not produced_any:
                    _wait = _retry_wait_seconds(e.status_code, str(e), attempt)
                    logger.warning(
                        "LLM stream HTTP %d (retryable) — backing off %.1fs "
                        "(attempt %d/%d)",
                        e.status_code,
                        _wait,
                        attempt + 1,
                        max_retries + 1,
                    )
                    await asyncio.sleep(_wait)
                    attempt += 1
                    continue
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=time.monotonic() - request_started,
                    success=False,
                    messages=messages,
                    options=options,
                )
                raise
            except RuntimeError:
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=time.monotonic() - request_started,
                    success=False,
                    messages=messages,
                    options=options,
                )
                raise
            except httpx.HTTPStatusError as e:
                if 500 <= e.response.status_code < 600 and attempt < max_retries and not produced_any:
                    await asyncio.sleep(5 * (attempt + 1))
                    attempt += 1
                    continue
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=time.monotonic() - request_started,
                    success=False,
                    messages=messages,
                    options=options,
                )
                raise
            except (httpx.NetworkError, httpx.TimeoutException, asyncio.TimeoutError):
                if attempt < max_retries and not produced_any:
                    await asyncio.sleep(2 ** (attempt + 1))
                    attempt += 1
                    continue
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=time.monotonic() - request_started,
                    success=False,
                    messages=messages,
                    options=options,
                )
                raise

        self._record_model_performance(
            operation=operation,
            response_time_sec=time.monotonic() - request_started,
            success=False,
            messages=messages,
            options=options,
        )
        raise RuntimeError(
            f"{self._backend_name} stream ended without a response after "
            f"{max_retries + 1} attempt(s)."
        )

    def _record_model_performance(
        self,
        operation: str,
        response_time_sec: float,
        success: bool,
        messages: list[dict[str, Any]],
        options: dict[str, Any] | None = None,
    ) -> None:
        model_name = str(getattr(self, "model", "") or "").strip()
        if not model_name:
            return
        try:
            get_memory_manager().record_model_performance(
                model_name=model_name,
                task_type=self._normalize_task_type(operation),
                response_time_sec=max(0.0, float(response_time_sec or 0.0)),
                success=success,
                context_size_used=self._estimate_context_size(messages, options),
            )
        except Exception as exc:
            logger.debug("Failed to record model performance: %s", exc)

    def _get_dynamic_timeout(self, operation: str = "inference") -> float:
        cfg = get_config()
        if operation == "compression":
            return max(180.0, cfg.llm_chunk_timeout)
        return cfg.llm_chunk_timeout

    def _record_response_time(self, response_time: float) -> None:
        if not hasattr(self, "_response_times"):
            self._response_times = []
        if not hasattr(self, "_max_response_times"):
            self._max_response_times = 20
        self._response_times.append(response_time)
        max_len = self._max_response_times
        if len(self._response_times) > max_len:
            self._response_times = self._response_times[-max_len:]

    def get_response_time_stats(self) -> Dict[str, float]:
        if not hasattr(self, "_response_times"):
            self._response_times = []
        times = self._response_times[-10:] if self._response_times else []
        if not times:
            return {"avg": 0.0, "min": 0.0, "max": 0.0, "count": 0}
        return {
            "avg": sum(times) / len(times),
            "min": min(times),
            "max": max(times),
            "count": len(self._response_times),
        }

    @staticmethod
    def _normalize_task_type(operation: str) -> str:
        task_type = str(operation or "").strip().lower()
        aliases = {
            "inference": "chat",
            "validation": "analysis",
            "summarization": "compression",
        }
        return aliases.get(task_type, task_type or "general")

    @staticmethod
    def _estimate_context_size(
        messages: list[dict[str, Any]],
        options: dict[str, Any] | None = None,
    ) -> int:
        total_chars = 0
        for message in messages or []:
            if not isinstance(message, dict):
                total_chars += len(str(message))
                continue
            for key in ("content", "thinking", "tool_calls"):
                value = message.get(key)
                if value in (None, ""):
                    continue
                if isinstance(value, str):
                    total_chars += len(value)
                else:
                    try:
                        total_chars += len(json.dumps(value, ensure_ascii=False))
                    except Exception:
                        total_chars += len(str(value))

        estimated_tokens = total_chars // 4
        if estimated_tokens > 0:
            return estimated_tokens
        return 0


def create_llm_client(model: str | None = None) -> LLMClient:
    cfg = get_config()
    return LLMClient(model=model or cfg.openai_model)
