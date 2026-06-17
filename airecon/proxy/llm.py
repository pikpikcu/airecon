"""LLM backend for AIRecon (OpenAI-compatible).

AIRecon talks to a single OpenAI-compatible ``/v1/chat/completions`` gateway —
for example LiteLLM, vLLM, or a hosted OpenAI/Anthropic-compatible endpoint. A
local gateway can also proxy a local Ollama/LLM server, so there is no separate
native-LLM backend.

``LLMClient`` is fully self-contained: it owns the shared httpx client, the
request semaphore, dynamic timeouts and the performance-recording hooks the rest
of the agent relies on, and speaks OpenAI's wire format directly.

The streaming method yields **LLM-shaped** chunks — dicts of the form
``{"message": {"content"/"thinking": ..., "tool_calls": [...]}, "done": bool}``
with tool-call ``arguments`` decoded to a ``dict`` — which is exactly what
``loop_tool_cycle`` already consumes, so the ~30 downstream modules need no
changes to how they read responses.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from typing import Any, AsyncIterator, Callable, Dict

import httpx

from .config import get_config
from .memory import get_memory_manager

logger = logging.getLogger("airecon.llm")

# Conversations longer than this (in tokens) trigger the agent loop's
# context-compaction pass. Kept here as the single source of truth that
# loop_lifecycle imports.
_CONTEXT_RESET_THRESHOLD = 65536

# Keys that are valid on an OpenAI chat message. Anything else AIRecon stores
# internally (``thinking``, ``_bucket``, ``name`` on non-tool roles, ...) is
# stripped before sending upstream.
_ALLOWED_MESSAGE_KEYS = frozenset(
    {"role", "content", "name", "tool_calls", "tool_call_id"}
)


def _to_openai_tool_calls(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert AIRecon-internal tool calls to OpenAI request format.

    AIRecon stores ``arguments`` as a dict; OpenAI expects a JSON string and a
    stable ``id`` + ``type`` on every call.
    """
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
    return out


def _to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize AIRecon's conversation into strict OpenAI chat messages.

    AIRecon often pairs a ``tool`` result with its call **by order** and stores
    no ``tool_call_id``. OpenAI-compatible providers reject such a message with
    ``tool_call_id is not set``, so we keep a FIFO of the ids assigned to the most
    recent assistant ``tool_calls`` and bind each following ``tool`` result to the
    next pending id.
    """
    converted: list[dict[str, Any]] = []
    pending_tool_ids: list[str] = []
    # Every id that actually appears in a preceding assistant ``tool_calls``.
    # A ``tool`` result is only valid if it references one of these — strict
    # gateways (e.g. the OpenAI Responses backend) reject a function-call output
    # whose call_id has no matching call with
    # "No tool call found for function call output with call_id ...".
    emitted_call_ids: set[str] = set()
    for msg in messages or []:
        if not isinstance(msg, dict):
            converted.append({"role": "user", "content": str(msg)})
            continue

        role = msg.get("role", "user")
        new_msg: dict[str, Any] = {"role": role}

        content = msg.get("content", "")
        # OpenAI allows null content only when tool_calls are present.
        new_msg["content"] = content if content is not None else ""

        if role == "assistant" and msg.get("tool_calls"):
            oai_calls = _to_openai_tool_calls(msg["tool_calls"])
            new_msg["tool_calls"] = oai_calls
            pending_tool_ids = [c["id"] for c in oai_calls]
            emitted_call_ids.update(pending_tool_ids)

        if role == "tool":
            tcid = msg.get("tool_call_id")
            if not tcid and pending_tool_ids:
                tcid = pending_tool_ids.pop(0)
            # A tool result MUST bind to a real tool_call that already appeared
            # in THIS payload. Fabricating an id (previous behaviour) created an
            # orphan the gateway rejects, so drop unbindable results instead —
            # their originating assistant turn was compacted/trimmed away.
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
        converted.append(new_msg)
    return converted


class LLMBackendHTTPError(RuntimeError):
    """Raised when the LLM backend returns an HTTP error status.

    Carries ``status_code`` so callers can distinguish retryable 5xx server
    errors from non-retryable 4xx client errors.
    """

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class LLMClient:
    """Standalone OpenAI-compatible (LiteLLM/vLLM/hosted) LLM client."""

    _global_semaphore: asyncio.Semaphore | None = None
    _httpx_client: httpx.AsyncClient | None = None
    _initialized: bool = False
    _init_lock: asyncio.Lock | None = None
    _semaphore_init_lock = threading.Lock()
    # Models discovered at runtime to reject reasoning params (HTTP 400). Shared
    # across instances so the probe runs at most once per model per process.
    _reasoning_unsupported: set[str] = set()

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        cfg = get_config()
        host = (base_url or cfg.openai_base_url).rstrip("/")
        self._host = host
        self.model = model or cfg.openai_model

        self._api_key = (cfg.openai_api_key or "").strip()
        self._backend_name = "OpenAI-compatible"
        self._supports_native_tools = bool(cfg.openai_supports_native_tools)

        # ── Deep-thinking support (restored for the OpenAI/gateway path) ──────
        # `llm_enable_thinking` is the master switch; `llm_thinking_request_mode`
        # decides HOW we ask the gateway for reasoning. We resolve a concrete
        # strategy for THIS model so a plain model (gpt-4o/gemini-flash) never
        # gets reasoning params it would reject, while a reasoning model
        # (o-series/qwen3/deepseek-r1) actually thinks before acting.
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
        # `supports_thinking` drives the agent's per-iteration thinking gate.
        # It is True when we can actually surface OR request reasoning, so the
        # documented "Deep Thinking Model Support" feature works on this backend.
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

    # ── helpers ──────────────────────────────────────────────────────────────
    def _auth_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _apply_options(
        self, payload: dict[str, Any], options: dict[str, Any] | None
    ) -> None:
        """Translate AIRecon generation options to OpenAI request params."""
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
        if max_tokens and max_tokens > 0:
            payload["max_tokens"] = int(max_tokens)
        if temperature is not None:
            payload["temperature"] = float(temperature)

    @staticmethod
    def _resolve_thinking_strategy(model: str, mode: str) -> str:
        """Decide how to request reasoning from the gateway.

        Returns one of: "off", "reasoning_effort", "enable_thinking".

        There is deliberately NO model-name list here. Guessing a model's
        reasoning capability from its name does not scale (GPT, Claude, Qwen,
        Gemini, Grok, DeepSeek… all differ and new models ship constantly).
        Instead:
          * An explicit ``llm_thinking_request_mode`` (off|reasoning_effort|
            enable_thinking) is always honored.
          * In ``auto`` we use the OpenAI-standard ``reasoning_effort`` parameter
            and rely on RUNTIME capability detection: if the backend rejects it
            with an HTTP 400 "unsupported parameter" (which is exactly what the
            OpenAI API returns for non-reasoning models), the client strips the
            param, remembers that for the model, and retries — see
            ``_maybe_degrade_reasoning``. ``enable_thinking`` (a non-standard
            vLLM/SGLang chat-template flag) stays an explicit opt-in.
        """
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
        """Translate the agent's `think` decision into gateway request params."""
        if not self._enable_thinking:
            return
        strat = self._thinking_strategy
        if strat == "reasoning_effort":
            # Reasoning models bill/latency-scale with effort; only request it
            # when the agent actually wants a thinking turn — and never for a
            # model we've already learned (at runtime) rejects the parameter.
            if think and self.model not in LLMClient._reasoning_unsupported:
                payload["reasoning_effort"] = self._reasoning_effort_value()
        elif strat == "enable_thinking":
            # vLLM/SGLang pass this through to the model's chat template, so we
            # can both enable AND suppress reasoning per-turn to save tokens.
            ctk = dict(payload.get("chat_template_kwargs") or {})
            ctk["enable_thinking"] = bool(think)
            payload["chat_template_kwargs"] = ctk

    @staticmethod
    def _is_unsupported_reasoning_error(status_code: int, body: str) -> bool:
        """True if an HTTP 400 indicates the backend rejected reasoning params.

        OpenAI (and compatible gateways) return 400 with messages like
        "Unsupported parameter: 'reasoning_effort'" or "'reasoning.effort' is not
        supported with this model" for non-reasoning models. We detect that text
        so we can degrade gracefully instead of failing the run — no model-name
        list required.
        """
        if status_code != 400:
            return False
        b = (body or "").lower()
        mentions_reasoning = (
            "reasoning_effort" in b
            or "reasoning.effort" in b
            or "reasoning" in b
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

    def _maybe_degrade_reasoning(
        self, payload: dict[str, Any], status_code: int, body: str
    ) -> bool:
        """Strip reasoning params if the backend rejected them; remember the model.

        Returns True when something was stripped (caller should retry the request
        without reasoning params).
        """
        if not self._is_unsupported_reasoning_error(status_code, body):
            return False
        removed = False
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

    # ── lifecycle / capability ───────────────────────────────────────────────
    async def reset_context(self, system_prompt: str | None = None) -> bool:
        # Remote stateless API — there is no server-side KV cache to reset.
        self._last_reset_error = ""
        self._last_reset_status = None
        return True

    async def unload_model(self) -> None:
        # No local VRAM to release for a remote backend.
        return None

    async def close(self) -> None:
        client = LLMClient._httpx_client
        if client is not None:
            await client.aclose()
        # Reset shared class-level state so a subsequent _async_init() rebuilds
        # a fresh client instead of re-using the now-closed one.
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
            # Some gateways gate /models behind auth or don't implement it;
            # treat any non-5xx response as "reachable".
            return resp.status_code < 500
        except Exception as e:
            logger.warning("LLM health check failed: %s", e)
            return False

    # ── non-streaming completion ─────────────────────────────────────────────
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
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": _to_openai_messages(messages),
            "stream": False,
        }
        self._apply_options(payload, options)

        try:
            for attempt in range(max_retries + 1):
                try:
                    timeout = self._get_dynamic_timeout(operation)
                    resp = await self._post("/chat/completions", payload, timeout)
                    data = resp.json()

                    content: str | None = None
                    if isinstance(data, dict):
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
                    if 500 <= e.status_code < 600 and attempt < max_retries:
                        await asyncio.sleep(5 * (attempt + 1))
                        continue
                    raise
                except RuntimeError:
                    raise
                except httpx.HTTPStatusError as e:
                    if 500 <= e.response.status_code < 600 and attempt < max_retries:
                        await asyncio.sleep(5 * (attempt + 1))
                        continue
                    raise
                except (httpx.NetworkError, httpx.TimeoutException, asyncio.TimeoutError):
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** (attempt + 1))
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

    # ── streaming chat ───────────────────────────────────────────────────────
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
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": _to_openai_messages(messages),
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            # AIRecon already builds tools in OpenAI function-schema shape
            # ({"type": "function", "function": {...}}), so pass them through.
            payload["tools"] = tools
        self._apply_options(payload, options)
        # Restore "Deep Thinking Model Support" on the OpenAI/gateway path: turn
        # the agent's per-iteration `think` decision into a real reasoning
        # request (reasoning_effort or chat_template_kwargs.enable_thinking).
        self._apply_thinking(payload, think)

        overall_timeout = cfg.llm_timeout
        chunk_timeout = cfg.llm_chunk_timeout
        request_started = time.monotonic()

        for attempt in range(max_retries + 1):
            tool_acc: dict[int, dict[str, str]] = {}
            tool_ids: dict[int, str] = {}
            usage: dict[str, Any] = {}
            produced_any = False
            finish_reason: str | None = None
            try:
                async with self._request_semaphore:
                    client = LLMClient._httpx_client
                    if client is None:
                        raise RuntimeError("HTTP client not initialized")
                    url = f"{self._host}/chat/completions"
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
                            # Read the body so the real cause (bad model name,
                            # rejected `tools`/`stream_options`, auth, ...) is
                            # visible instead of a generic error loop.
                            try:
                                await resp.aread()
                                body = resp.text[:500]
                            except Exception:
                                body = "<unreadable body>"
                            # Automatic capability detection: if the backend
                            # rejected reasoning params, strip them and retry the
                            # same request instead of failing the run.
                            if self._maybe_degrade_reasoning(
                                payload, resp.status_code, body
                            ):
                                continue
                            logger.error(
                                "LLM backend STREAM /chat/completions -> HTTP %d: %s",
                                resp.status_code,
                                body,
                            )
                            raise LLMBackendHTTPError(
                                resp.status_code,
                                f"{self._backend_name} returned HTTP "
                                f"{resp.status_code} for /chat/completions: {body}",
                            )
                        async for raw_line in resp.aiter_lines():
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
                                continue

                            if isinstance(evt.get("usage"), dict):
                                usage = evt["usage"]

                            choices = evt.get("choices") or []
                            if not choices:
                                continue
                            choice0 = choices[0]
                            delta = choice0.get("delta") or {}
                            if choice0.get("finish_reason"):
                                finish_reason = choice0["finish_reason"]

                            # Reasoning models (o1, DeepSeek-R1, and many hosted
                            # models behind LiteLLM) stream their
                            # chain-of-thought in `reasoning_content` or
                            # `reasoning` rather than `content`. Map it to an
                            # LLM-style `thinking` chunk so the agent loop sees
                            # real output instead of treating the turn as empty
                            # and burning useless retries.
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
                            # OpenAI (and some safety-tuned gateways) put refusal
                            # text in a structured `refusal` field instead of
                            # `content`; surface it so a refusal is not silently
                            # dropped and mistaken for an empty reply.
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
                                fn = tc.get("function") or {}
                                if fn.get("name"):
                                    slot["name"] = fn["name"]
                                if fn.get("arguments"):
                                    slot["args"] += fn["arguments"]

                # Build the consolidated final chunk (LLM shape).
                final_tool_calls: list[dict[str, Any]] = []
                for idx in sorted(tool_acc):
                    slot = tool_acc[idx]
                    if not slot["name"]:
                        continue
                    raw_args = slot["args"].strip()
                    try:
                        parsed_args: Any = json.loads(raw_args) if raw_args else {}
                    except json.JSONDecodeError:
                        logger.warning(
                            "Tool-call arguments were not valid JSON for %s: %r",
                            slot["name"],
                            raw_args[:200],
                        )
                        parsed_args = {}
                    final_tool_calls.append(
                        {
                            "id": tool_ids.get(idx, f"call_{uuid.uuid4().hex[:24]}"),
                            "function": {
                                "name": slot["name"],
                                "arguments": parsed_args,
                            },
                        }
                    )

                final_message: dict[str, Any] = {"role": "assistant", "content": ""}
                if final_tool_calls:
                    final_message["tool_calls"] = final_tool_calls
                    produced_any = True

                # 200 but zero usable output. Almost always a provider-side safety
                # block or rejected request — fail fast with the real reason so the
                # loop doesn't retry and then print irrelevant advice.
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
                # Retry transient 5xx server errors; 4xx is a client problem
                # (bad model, rejected params, auth) that won't resolve on retry.
                if 500 <= e.status_code < 600 and attempt < max_retries:
                    await asyncio.sleep(5 * (attempt + 1))
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
                # 4xx from the gateway (bad model, rejected params, auth, ...) or a
                # content-filter empty. Retrying won't help, so fail fast.
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=time.monotonic() - request_started,
                    success=False,
                    messages=messages,
                    options=options,
                )
                raise
            except httpx.HTTPStatusError as e:
                if 500 <= e.response.status_code < 600 and attempt < max_retries:
                    await asyncio.sleep(5 * (attempt + 1))
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
                if attempt < max_retries:
                    await asyncio.sleep(2 ** (attempt + 1))
                    continue
                self._record_model_performance(
                    operation=operation,
                    response_time_sec=time.monotonic() - request_started,
                    success=False,
                    messages=messages,
                    options=options,
                )
                raise

        # Reaching here means the loop exhausted every attempt without yielding a
        # terminal chunk or raising — the only way in is a reasoning-degrade
        # `continue` on the final attempt. Guarantee a terminal signal so the
        # async generator never ends silently (which would look like an empty
        # response to the caller).
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

    # ── performance / timeout bookkeeping ────────────────────────────────────
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
        """Record a response time for adaptive timeout calculations."""
        if not hasattr(self, "_response_times"):
            self._response_times = []
        if not hasattr(self, "_max_response_times"):
            self._max_response_times = 20
        self._response_times.append(response_time)
        max_len = self._max_response_times
        if len(self._response_times) > max_len:
            self._response_times = self._response_times[-max_len:]

    def get_response_time_stats(self) -> Dict[str, float]:
        """Avg/min/max of the last 10 response times."""
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
    """Return the configured OpenAI-compatible LLM client."""
    cfg = get_config()
    return LLMClient(model=model or cfg.openai_model)
