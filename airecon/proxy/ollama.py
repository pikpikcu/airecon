"""Async client for Ollama using the official Python SDK."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, AsyncIterator

import ollama

from .config import get_config

logger = logging.getLogger("airecon.ollama")

# Ollama errors that must NOT be retried — retrying wastes 14s and the
# model/context state won't change between attempts.
_PERMANENT_OLLAMA_ERRORS: frozenset[str] = frozenset([
    "model not found",
    "model is not loaded",
    "unsupported model",
    "context length exceeded",
    "out of memory",
    "no gpu",
])


def _detect_model_capabilities_from_show(
    model_name: str,
    show_response: dict[str, Any] | Any,
) -> tuple[bool, bool]:
    """Detect capabilities from Ollama `show` metadata.

    We intentionally trust model metadata over name heuristics. This keeps
    capability detection aligned with Ollama model definitions instead of
    broad assumptions from tag names.
    """
    data = show_response if isinstance(show_response, dict) else dict(show_response)

    capabilities = {
        str(item).strip().lower()
        for item in (data.get("capabilities") or [])
        if item is not None
    }
    template = (data.get("template") or "").lower()
    modelfile = (data.get("modelfile") or "").lower()

    supports_thinking = (
        "thinking" in capabilities
        or "<think>" in template
        or "<think>" in modelfile
        or "<thinking>" in template
        or "<thinking>" in modelfile
    )

    has_native_tools = any(
        cap in capabilities
        for cap in ("tools", "tool-calling", "function-calling")
    )

    # AIRecon's tool loop relies on reasoning traces to validate tool calls.
    # A model that supports tool-calling but produces no thinking output is
    # disabled for safety — without reasoning traces the agent cannot verify
    # whether a tool invocation is well-grounded.
    supports_native_tools = has_native_tools and supports_thinking

    logger.info(
        "Model %s (show): capabilities=%s thinking=%s native_tools=%s",
        model_name,
        sorted(capabilities),
        supports_thinking,
        supports_native_tools,
    )
    return supports_thinking, supports_native_tools


class OllamaClient:
    """Wrapper around the official ollama.AsyncClient."""
    # Shared per-loop request gates keyed by (loop_id, host, model):
    # prevents concurrent large-model inference spikes from parallel subagents.
    _request_gate_lock = threading.Lock()
    _request_gates: dict[tuple[int, str, str], tuple[int, asyncio.Semaphore]] = {}

    def __init__(self, base_url: str | None = None,
                 model: str | None = None) -> None:
        cfg = get_config()
        host = (base_url or cfg.ollama_url).rstrip("/")
        self._host = host
        self.model = model or cfg.ollama_model

        # Auto-detect model capabilities
        self._supports_thinking = cfg.ollama_supports_thinking
        self._supports_native_tools = cfg.ollama_supports_native_tools

        # If config has auto-detect (True by default), run ONE metadata call.
        # Only override capabilities when detection succeeds — on transient
        # failure we keep the config default (True = optimistic/force-on) so
        # a brief Ollama hiccup at startup does not silently disable thinking
        # for the whole session.
        if cfg.ollama_supports_thinking is True or cfg.ollama_supports_native_tools is True:
            detected = self._detect_capabilities()
            if detected is not None:
                detected_think, detected_tools = detected
                if cfg.ollama_supports_thinking is True:
                    self._supports_thinking = detected_think
                if cfg.ollama_supports_native_tools is True:
                    self._supports_native_tools = detected_tools

        # Invariant: native tool-calling requires thinking traces for validation.
        # Enforce regardless of how capabilities were set (config or detection).
        if not self._supports_thinking and self._supports_native_tools:
            logger.warning(
                "native_tools=True requires thinking=True (AIRecon uses reasoning "
                "traces to validate tool calls). Forcing native_tools=False."
            )
            self._supports_native_tools = False

        logger.info(
            "Initializing Ollama SDK client for host: %s, model: %s, timeout: %ss",
            host, self.model, cfg.ollama_timeout,
        )
        logger.info(
            "Model capabilities: thinking=%s, native_tools=%s",
            self._supports_thinking, self._supports_native_tools,
        )
        self._client = ollama.AsyncClient(
            host=host, timeout=cfg.ollama_timeout)

    async def _get_request_gate(self) -> asyncio.Semaphore:
        """Return a shared semaphore that bounds concurrent Ollama requests."""
        cfg = get_config()
        limit = max(
            1,
            int(getattr(cfg, "ollama_max_concurrent_requests", 1)),
        )
        loop_id = id(asyncio.get_running_loop())
        key = (loop_id, self._host, self.model)

        with self._request_gate_lock:
            cached = self._request_gates.get(key)
            if cached is None or cached[0] != limit:
                gate = asyncio.Semaphore(limit)
                self._request_gates[key] = (limit, gate)
                logger.info(
                    "Ollama concurrency gate initialized for %s (%s): %d",
                    self.model,
                    self._host,
                    limit,
                )
            else:
                gate = cached[1]
        return gate

    def _detect_capabilities(self) -> tuple[bool, bool] | None:
        """Detect model capabilities via Ollama `show` metadata.

        Returns (thinking, native_tools) on success, or None on any error.
        Callers that receive None should keep their existing config defaults.
        """
        try:
            sync_client = ollama.Client(host=self._host)
            show_response = sync_client.show(model=self.model)
            return _detect_model_capabilities_from_show(self.model, show_response)
        except Exception as e:
            logger.warning(
                "Could not inspect model metadata via `ollama show` for %s: %s. "
                "Keeping config defaults (thinking/native-tools remain as configured). "
                "If your model does NOT support thinking or tool-calling, set "
                "ollama_supports_thinking=false and/or ollama_supports_native_tools=false "
                "in config.json to avoid runtime errors.",
                self.model,
                e,
            )
            return None

    @property
    def supports_thinking(self) -> bool:
        return self._supports_thinking

    @property
    def supports_native_tools(self) -> bool:
        return self._supports_native_tools

    async def close(self) -> None:
        """Close client and unload model."""
        await self.unload_model()

    async def unload_model(self) -> None:
        """Unload model from memory by setting keep_alive to 0."""
        try:
            logger.info("Unloading model %s...", self.model)
            await self._client.generate(model=self.model, prompt="", keep_alive=0)
            logger.info("Model unloaded successfully.")
        except Exception as e:
            logger.error("Failed to unload model: %s", e)

    async def health_check(self) -> bool:
        """Check if Ollama is reachable."""
        try:
            await self._client.list()
            return True
        except Exception:
            return False

    async def complete(
        self,
        messages: list[dict[str, Any]],
        max_retries: int = 3,
        options: dict[str, Any] | None = None,
    ) -> str:
        """Non-streaming single completion for internal use (e.g. memory compression).

        Returns the assistant message content as a plain string.
        Retries up to max_retries times with exponential backoff on transient errors.
        Raises RuntimeError if Ollama returns an unexpected response format after all retries.
        """
        max_retries = max(0, max_retries)
        gate = await self._get_request_gate()
        async with gate:
            for attempt in range(max_retries + 1):
                try:
                    kwargs: dict[str, Any] = {
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "keep_alive": get_config().ollama_keep_alive,
                    }
                    if options:
                        kwargs["options"] = options
                    response = await self._client.chat(**kwargs)

                    # Extract content with explicit validation
                    content = None
                    if hasattr(response, "message") and response.message is not None:
                        content = response.message.content
                    elif isinstance(response, dict):
                        content = response.get("message", {}).get("content")

                    if content is None:
                        logger.warning(
                            "Ollama returned unexpected response format: %r. "
                            "Response: %r. Attempt %d/%d",
                            type(response), response, attempt + 1, max_retries + 1
                        )
                        if attempt < max_retries:
                            wait = 2 ** (attempt + 1)
                            await asyncio.sleep(wait)
                            continue
                        raise RuntimeError(
                            f"Invalid Ollama response format: {type(response)}. "
                            f"Expected response with 'message.content' attribute or dict with 'message.content' key."
                        )

                    return content or ""

                except RuntimeError:
                    raise
                except Exception as e:
                    err_str = str(e).lower()
                    is_transient = any(
                        k in err_str
                        for k in (
                            "connection reset", "connection refused", "eof",
                            "broken pipe", "timeout", "timed out",
                            "network", "connection error",
                        )
                    )
                    if is_transient and attempt < max_retries:
                        wait = 2 ** (attempt + 1)  # 2s, 4s, 8s
                        logger.warning(
                            "Transient Ollama error in complete() (attempt %d/%d), retrying in %ss: %s",
                            attempt + 1, max_retries + 1, wait, e,
                        )
                        await asyncio.sleep(wait)
                        continue
                    raise
        raise RuntimeError("Unexpected code path in complete()")

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        think: bool = False,
        max_retries: int = 3,
    ) -> AsyncIterator[Any]:
        """
        Streaming chat completion using SDK.
        Returns the raw chunk object from Ollama SDK.
        Retries up to max_retries times on transient connection errors.
        """
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "keep_alive": get_config().ollama_keep_alive,
        }
        if think:
            kwargs["think"] = think
        if tools:
            kwargs["tools"] = tools
        if options:
            kwargs["options"] = options

        gate = await self._get_request_gate()
        async with gate:
            for attempt in range(max_retries + 1):
                try:
                    async for chunk in await self._client.chat(**kwargs):
                        yield chunk
                    return

                except ollama.ResponseError as e:
                    err_str = str(e.error)
                    if (
                        "invalid character '<'" in err_str
                        or "failed to parse JSON" in err_str
                    ):
                        # HTML response = Ollama crashed or OOM — not retryable
                        raise ollama.ResponseError(
                            "Ollama returned an HTML error page instead of JSON. "
                            "This usually means Ollama crashed or ran out of memory. "
                            "Try: `systemctl restart ollama` or reduce `ollama_num_ctx` in config.",
                            status_code=e.status_code,
                        )
                    # Permanent errors must not be retried
                    err_lower = err_str.lower()
                    if any(p in err_lower for p in _PERMANENT_OLLAMA_ERRORS):
                        logger.error("Permanent Ollama error (not retrying): %s", err_str)
                        raise
                    # Other ResponseErrors (model loading, transient) → retry
                    if attempt < max_retries:
                        wait = 2 ** (attempt + 1)  # 2s, 4s, 8s
                        logger.warning(
                            "Ollama ResponseError (attempt %d/%d), retrying in %ss: %s",
                            attempt + 1, max_retries + 1, wait, e.error,
                        )
                        await asyncio.sleep(wait)
                        continue
                    logger.error(
                        "Ollama ResponseError after %d attempts: %s",
                        max_retries + 1, e.error,
                    )
                    raise

                except Exception as e:
                    err_str = str(e).lower()
                    is_transient = any(
                        k in err_str
                        for k in (
                            "connection reset",
                            "connection refused",
                            "eof",
                            "broken pipe",
                            "timeout",
                            "timed out",
                            "network",
                            "connection error",
                        )
                    )
                    if is_transient and attempt < max_retries:
                        wait = 2 ** (attempt + 1)  # 2s, 4s, 8s
                        logger.warning(
                            "Transient Ollama error (attempt %d/%d), retrying in %ss: %s",
                            attempt + 1, max_retries + 1, wait, e,
                        )
                        await asyncio.sleep(wait)
                        continue
                    logger.exception("Unexpected SDK error: %s", e)
                    raise
