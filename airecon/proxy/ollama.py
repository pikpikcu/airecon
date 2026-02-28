"""Async client for Ollama using the official Python SDK."""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator

import ollama
from .config import get_config

logger = logging.getLogger("airecon.ollama")


class OllamaClient:
    """Wrapper around the official ollama.AsyncClient."""

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        cfg = get_config()
        host = (base_url or cfg.ollama_url).rstrip("/")
        self.model = model or cfg.ollama_model
        
        logger.info(f"Initializing Ollama SDK client for host: {host}, model: {self.model}, timeout: {cfg.ollama_timeout}s")
        self._client = ollama.AsyncClient(host=host, timeout=cfg.ollama_timeout)

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

    async def list_models(self) -> list[dict]:
        """List available models."""
        try:
            response = await self._client.list()
            if hasattr(response, "models"):
                models = response.models
            else:
                models = response.get("models", [])
            
            return [
                model.model_dump() if hasattr(model, "model_dump") else model 
                for model in models
            ]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        think: bool = False,
        max_retries: int = 2,
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
                if "invalid character '<'" in err_str or "failed to parse JSON" in err_str:
                    raise ollama.ResponseError(
                        "Ollama returned an HTML error page instead of JSON. "
                        "This usually means Ollama crashed or ran out of memory. "
                        "Try: `systemctl restart ollama` or reduce `ollama_num_ctx` in config.",
                        status_code=e.status_code,
                    )
                logger.error(f"Ollama ResponseError (attempt {attempt + 1}): {e.error}")
                raise

            except Exception as e:
                err_str = str(e).lower()
                is_transient = any(k in err_str for k in (
                    "connection reset", "connection refused", "eof", "broken pipe",
                    "timeout", "timed out", "network", "connection error",
                ))
                if is_transient and attempt < max_retries:
                    wait = 1.5 * (attempt + 1)
                    logger.warning(
                        f"Transient Ollama error (attempt {attempt + 1}/{max_retries + 1}), "
                        f"retrying in {wait:.1f}s: {e}"
                    )
                    last_err = e
                    await asyncio.sleep(wait)
                    continue
                logger.exception(f"Unexpected SDK error: {e}")
                raise

        raise RuntimeError(
            f"Ollama connection failed after {max_retries + 1} attempts: {last_err}"
        )
