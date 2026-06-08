from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from .base import AIProvider, ChatMessage, ProviderInfo

log = logging.getLogger(__name__)

OPENAI_MODELS = [
    "gpt-4.1",        # Best: latest, most capable
    "gpt-4.1-mini",   # Fast + capable
    "gpt-4o",         # Reliable multimodal
    "gpt-4o-mini",    # Fastest / cheapest GPT-4o tier
    "o3",             # Best reasoning
    "o4-mini",        # Fast reasoning
    "o1",             # Solid reasoning
    "gpt-4-turbo",    # Older but available
]
DEFAULT_MODEL = "gpt-4.1"


class OpenAIProvider(AIProvider):
    @property
    def provider_id(self) -> str:
        return "openai"

    @property
    def display_name(self) -> str:
        return "GPT-4o (OpenAI)"

    def _get_client(self, api_key: str | None = None, base_url: str | None = None):
        try:
            import openai as _openai
        except ImportError:
            raise RuntimeError("openai package not installed. Run: pip install openai") from None
        key = (api_key or "").strip() or os.environ.get("OPENAI_API_KEY", "").strip()
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        return _openai.AsyncOpenAI(api_key=key, base_url=url)

    @staticmethod
    def _to_oai_messages(messages: list[ChatMessage]) -> list[dict]:
        import json as _json
        result = []
        for m in messages:
            content = m.content
            # OpenAI requires content to be a string or array of content objects.
            # Tool results and history items sometimes carry raw dicts — serialize them.
            if isinstance(content, (dict, list)):
                content = _json.dumps(content, ensure_ascii=False)
            elif content is None:
                content = ""
            result.append({"role": m.role, "content": content})
        return result

    async def complete(self, messages: list[ChatMessage], model: str | None = None, max_tokens: int = 2048, temperature: float = 0.3, api_key: str | None = None, base_url: str | None = None) -> str:
        client = self._get_client(api_key, base_url)
        resp = await client.chat.completions.create(
            model=model or DEFAULT_MODEL,
            messages=self._to_oai_messages(messages),  # type: ignore[arg-type]
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return resp.choices[0].message.content or ""

    async def stream(self, messages: list[ChatMessage], model: str | None = None, max_tokens: int = 2048, temperature: float = 0.4, api_key: str | None = None, base_url: str | None = None) -> AsyncGenerator[str, None]:
        client = self._get_client(api_key, base_url)
        stream = await client.chat.completions.create(
            model=model or DEFAULT_MODEL,
            messages=self._to_oai_messages(messages),  # type: ignore[arg-type]
            max_tokens=max_tokens,
            temperature=temperature,
            stream=True,
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta

    async def health_check(self, api_key: str | None = None, base_url: str | None = None) -> ProviderInfo:
        try:
            import openai as _openai  # noqa: F401
        except ImportError:
            return ProviderInfo(id="openai", name=self.display_name, available=False, models=OPENAI_MODELS, default_model=DEFAULT_MODEL, error="openai package not installed")

        env_key = os.environ.get("OPENAI_API_KEY", "")
        # Try caller-supplied key first; fall back to env var
        candidates = [k for k in [api_key, env_key] if k and k.strip()]
        if not candidates:
            return ProviderInfo(id="openai", name=self.display_name, available=False, models=OPENAI_MODELS, default_model=DEFAULT_MODEL, error="OPENAI_API_KEY not set")

        last_error = ""
        for key in candidates:
            try:
                client = self._get_client(key.strip(), base_url)
                await client.models.list()
                return ProviderInfo(id="openai", name=self.display_name, available=True, models=OPENAI_MODELS, default_model=DEFAULT_MODEL)
            except Exception as e:
                last_error = str(e)[:200]
                continue

        return ProviderInfo(id="openai", name=self.display_name, available=False, models=OPENAI_MODELS, default_model=DEFAULT_MODEL, error=last_error)
