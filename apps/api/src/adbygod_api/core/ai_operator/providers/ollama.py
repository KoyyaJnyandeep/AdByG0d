from __future__ import annotations

import json
import logging
import os
from typing import AsyncGenerator

import httpx

from .base import AIProvider, ChatMessage, ProviderInfo

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:14b"
KNOWN_MODELS = [
    "qwen2.5:14b",   # recommended: best local tool-calling/JSON, fits 8GB VRAM
    "qwen2.5:7b",    # lighter alternative, fully in VRAM
    "qwen2.5:32b",   # if you have 24GB+ VRAM
    "llama3.2",
    "llama3.1",
    "llama3",
    "mistral",
    "mixtral",
    "codellama",
    "phi3",
    "gemma2",
    "deepseek-r1",
]


def _base_url(base_url: str | None = None) -> str:
    return (base_url or os.environ.get("OLLAMA_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")


def _default_model() -> str:
    return os.environ.get("OLLAMA_DEFAULT_MODEL", DEFAULT_MODEL)


class OllamaProvider(AIProvider):
    @property
    def provider_id(self) -> str:
        return "ollama"

    @property
    def display_name(self) -> str:
        return f"Ollama (local · {_base_url()})"

    @staticmethod
    def _to_ollama_messages(messages: list[ChatMessage]) -> list[dict]:
        # Ollama supports system role natively
        return [{"role": m.role, "content": m.content} for m in messages]

    async def complete(self, messages: list[ChatMessage], model: str | None = None, max_tokens: int = 2048, temperature: float = 0.3, api_key: str | None = None, base_url: str | None = None) -> str:
        url = f"{_base_url(base_url)}/api/chat"
        payload = {
            "model": model or _default_model(),
            "messages": self._to_ollama_messages(messages),
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "")

    async def stream(self, messages: list[ChatMessage], model: str | None = None, max_tokens: int = 2048, temperature: float = 0.4, api_key: str | None = None, base_url: str | None = None) -> AsyncGenerator[str, None]:
        url = f"{_base_url(base_url)}/api/chat"
        payload = {
            "model": model or _default_model(),
            "messages": self._to_ollama_messages(messages),
            "stream": True,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        chunk = data.get("message", {}).get("content", "")
                        if chunk:
                            yield chunk
                        if data.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue

    async def health_check(self, api_key: str | None = None, base_url: str | None = None) -> ProviderInfo:
        url = f"{_base_url(base_url)}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                installed = [m["name"].split(":")[0] for m in data.get("models", [])]
                default = installed[0] if installed else _default_model()
                return ProviderInfo(
                    id="ollama", name=self.display_name, available=True,
                    models=installed or KNOWN_MODELS, default_model=default, local=True,
                )
        except httpx.ConnectError:
            return ProviderInfo(id="ollama", name=f"Ollama (local · {_base_url(base_url)})", available=False, models=KNOWN_MODELS, default_model=DEFAULT_MODEL, local=True, error=f"Cannot connect to {_base_url(base_url)} — is Ollama running?")
        except Exception as e:
            return ProviderInfo(id="ollama", name=self.display_name, available=False, models=KNOWN_MODELS, default_model=DEFAULT_MODEL, local=True, error=str(e)[:200])
