"""Async client for Ollama using the official Python SDK."""

from __future__ import annotations

import logging
import re
from typing import Any, AsyncIterator

import ollama
from .config import get_config

logger = logging.getLogger("airecon.ollama")

# Models known to support native thinking (reasoning models)
THINKING_MODELS = {
    "qwen3",
    "qwen2.5",
    "deepseek-r1",
    "deepseek-reasoner",
    "llama4",
    "gemini-2.5",
    "gemma3",
    "phi4",
}

# Models known to support native function calling
NATIVE_TOOL_MODELS = {
    "qwen3",
    "qwen2.5",
    "llama3.1",
    "llama3.2",
    "llama4",
    "mistral",
    "mixtral",
    "phi4",
    "gemini-2.5",
    "gemma3",
}


def _detect_model_capabilities(model_name: str) -> tuple[bool, bool]:
    """Auto-detect model capabilities based on model name patterns.

    Returns: (supports_thinking, supports_native_tools)
    """
    model_lower = model_name.lower()

    # Check for thinking capability
    supports_thinking = any(
        pattern in model_lower for pattern in THINKING_MODELS)
    # Override: models with "reasoner" in name are reasoning models
    if "reasoner" in model_lower:
        supports_thinking = True

    # Check for native tool calling
    supports_native_tools = any(
        pattern in model_lower for pattern in NATIVE_TOOL_MODELS
    )
    # Override: latest generations often have improved tool support
    if re.search(r"(3\.\d|4\.\d)", model_lower):
        supports_native_tools = True

    logger.info(
        f"Model {model_name}: thinking={supports_thinking}, native_tools={supports_native_tools}"
    )
    return supports_thinking, supports_native_tools


class OllamaClient:
    """Wrapper around the official ollama.AsyncClient."""

    def __init__(self, base_url: str | None = None,
                 model: str | None = None) -> None:
        cfg = get_config()
        host = (base_url or cfg.ollama_url).rstrip("/")
        self.model = model or cfg.ollama_model

        # Auto-detect model capabilities
        self._supports_thinking = cfg.ollama_supports_thinking
        self._supports_native_tools = cfg.ollama_supports_native_tools

        # If config has auto-detect (True by default), try to detect
        # Only override if config explicitly enables auto-detection
        if cfg.ollama_supports_thinking is True:
            detected_think, detected_tools = _detect_model_capabilities(
                self.model)
            self._supports_thinking = detected_think
        if cfg.ollama_supports_native_tools is True:
            detected_think, detected_tools = _detect_model_capabilities(
                self.model)
            self._supports_native_tools = detected_tools

        logger.info(
            f"Initializing Ollama SDK client for host: {host}, model: {self.model}, timeout: {cfg.ollama_timeout}s"
        )
        logger.info(
            f"Model capabilities: thinking={self._supports_thinking}, native_tools={self._supports_native_tools}"
        )
        self._client = ollama.AsyncClient(
            host=host, timeout=cfg.ollama_timeout)

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
            logger.info(f"Unloading model {self.model}...")
            await self._client.generate(model=self.model, prompt="", keep_alive=0)
            logger.info("Model unloaded successfully.")
        except Exception as e:
            logger.error(f"Failed to unload model: {e}")

    async def health_check(self) -> bool:
        """Check if Ollama is reachable."""
        try:
            await self._client.list()
            return True
        except Exception:
            return False

    async def complete(self, messages: list[dict[str, Any]], max_retries: int = 3) -> str:
        """Non-streaming single completion for internal use (e.g. memory compression).

        Returns the assistant message content as a plain string.
        Retries up to max_retries times with exponential backoff on transient errors.
        """
        import asyncio

        last_err: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                response = await self._client.chat(
                    model=self.model,
                    messages=messages,
                    stream=False,
                    keep_alive=get_config().ollama_keep_alive,
                )
                if hasattr(response, "message"):
                    return response.message.content or ""
                if isinstance(response, dict):
                    return response.get("message", {}).get("content", "")
                return ""

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
                        f"Transient Ollama error in complete() (attempt "
                        f"{attempt + 1}/{max_retries + 1}), retrying in {wait}s: {e}"
                    )
                    last_err = e
                    await asyncio.sleep(wait)
                    continue
                raise

        raise RuntimeError(
            f"Ollama complete() failed after {max_retries + 1} attempts: {last_err}"
        )

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
        import asyncio

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

        last_err: Exception | None = None
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
                # Other ResponseErrors (model loading, transient) → retry
                if attempt < max_retries:
                    wait = 2 ** (attempt + 1)  # 2s, 4s, 8s
                    logger.warning(
                        f"Ollama ResponseError (attempt {attempt + 1}/{max_retries + 1}), "
                        f"retrying in {wait}s: {e.error}"
                    )
                    last_err = e
                    await asyncio.sleep(wait)
                    continue
                logger.error(
                    f"Ollama ResponseError after {max_retries + 1} attempts: {e.error}")
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
                        f"Transient Ollama error (attempt {attempt + 1}/{max_retries + 1}), "
                        f"retrying in {wait}s: {e}"
                    )
                    last_err = e
                    await asyncio.sleep(wait)
                    continue
                logger.exception(f"Unexpected SDK error: {e}")
                raise

        raise RuntimeError(
            f"Ollama connection failed after {max_retries + 1} attempts: {last_err}"
        )
