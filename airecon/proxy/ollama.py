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
            # Sending an empty generate request with keep_alive=0 unloads it immediately
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
            # Handle object response (0.6.x+) vs dict response (older)
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
    ) -> AsyncIterator[Any]:
        """
        Streaming chat completion using SDK.
        Returns the raw chunk object from Ollama SDK.
        """
        try:
            kwargs = {
                "model": self.model,
                "messages": messages,
                "stream": True,
                "keep_alive": -1, # Keep model loaded
            }
            
            # Support for reasoning models in newer SDK versions
            if think:
                kwargs["think"] = think 

            if tools:
                kwargs["tools"] = tools
            if options:
                kwargs["options"] = options

            # SDK handles streaming and parsing natively
            async for chunk in await self._client.chat(**kwargs):
                yield chunk

        except ollama.ResponseError as e:
            logger.error(f"Ollama SDK Error: {e.error}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected SDK error: {e}")
            raise
