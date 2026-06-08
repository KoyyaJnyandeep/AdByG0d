from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

import anthropic

from .base import AIProvider, ChatMessage, ProviderInfo

log = logging.getLogger(__name__)

CLAUDE_MODELS = ["claude-sonnet-4-6", "claude-opus-4-8", "claude-haiku-4-5-20251001"]
DEFAULT_MODEL = "claude-sonnet-4-6"


class ClaudeProvider(AIProvider):
    @property
    def provider_id(self) -> str:
        return "claude"

    @property
    def display_name(self) -> str:
        return "Claude (Anthropic)"

    def _client(self, api_key_override: str | None = None) -> anthropic.Anthropic:
        key = api_key_override or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        return anthropic.Anthropic(api_key=key)

    def _build_messages(self, messages: list[ChatMessage]) -> tuple[str | None, list[dict]]:
        system = None
        msgs: list[dict] = []
        for m in messages:
            if m.role == "system":
                system = m.content
            else:
                msgs.append({"role": m.role, "content": m.content})
        return system, msgs

    async def complete(self, messages: list[ChatMessage], model: str | None = None, max_tokens: int = 2048, temperature: float = 0.3, api_key: str | None = None, base_url: str | None = None) -> str:
        client = self._client(api_key)
        system, msgs = self._build_messages(messages)
        kwargs: dict = dict(model=model or DEFAULT_MODEL, max_tokens=max_tokens, messages=msgs)
        if system:
            kwargs["system"] = system
        resp = client.messages.create(**kwargs)
        return resp.content[0].text

    async def stream(self, messages: list[ChatMessage], model: str | None = None, max_tokens: int = 2048, temperature: float = 0.4, api_key: str | None = None, base_url: str | None = None) -> AsyncGenerator[str, None]:
        client = self._client(api_key)
        system, msgs = self._build_messages(messages)
        kwargs: dict = dict(model=model or DEFAULT_MODEL, max_tokens=max_tokens, messages=msgs)
        if system:
            kwargs["system"] = system
        with client.messages.stream(**kwargs) as stream_ctx:
            for chunk in stream_ctx.text_stream:
                yield chunk

    async def health_check(self, api_key: str | None = None, base_url: str | None = None) -> ProviderInfo:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            return ProviderInfo(id="claude", name=self.display_name, available=False, models=CLAUDE_MODELS, default_model=DEFAULT_MODEL, error="ANTHROPIC_API_KEY not set")
        try:
            client = self._client(key)
            client.messages.create(model=DEFAULT_MODEL, max_tokens=5, messages=[{"role": "user", "content": "ping"}])
            return ProviderInfo(id="claude", name=self.display_name, available=True, models=CLAUDE_MODELS, default_model=DEFAULT_MODEL)
        except Exception as e:
            return ProviderInfo(id="claude", name=self.display_name, available=False, models=CLAUDE_MODELS, default_model=DEFAULT_MODEL, error=str(e)[:200])
