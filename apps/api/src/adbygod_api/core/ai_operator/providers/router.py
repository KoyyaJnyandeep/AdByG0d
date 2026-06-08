from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from .base import AIProvider, ChatMessage, ProviderInfo
from .claude import ClaudeProvider
from .openai_provider import OpenAIProvider
from .ollama import OllamaProvider

log = logging.getLogger(__name__)

_REGISTRY: dict[str, AIProvider] = {
    "claude": ClaudeProvider(),
    "openai": OpenAIProvider(),
    "ollama": OllamaProvider(),
}

# Fallback chain: if preferred provider fails, try these in order
_FALLBACK_ORDER = ["claude", "openai", "ollama"]


def get_provider(provider_id: str | None = None) -> AIProvider:
    pid = provider_id or os.environ.get("AI_DEFAULT_PROVIDER", "claude")
    if pid not in _REGISTRY:
        raise ValueError(f"Unknown provider: {pid!r}. Choose from {list(_REGISTRY)}")
    return _REGISTRY[pid]


async def list_providers() -> list[ProviderInfo]:
    results = []
    for provider in _REGISTRY.values():
        try:
            info = await provider.health_check()
        except Exception as e:
            from .base import ProviderInfo as PI
            info = PI(id=provider.provider_id, name=provider.display_name, available=False, models=[], default_model="", error=str(e))
        results.append(info)
    return results


async def check_provider_health(provider_id: str, api_key: str | None = None, base_url: str | None = None) -> ProviderInfo:
    if provider_id not in _REGISTRY:
        from .base import ProviderInfo as PI
        return PI(id=provider_id, name=provider_id, available=False, models=[], default_model="", error="Unknown provider")
    return await _REGISTRY[provider_id].health_check(api_key=api_key, base_url=base_url)


async def stream_with_fallback(
    messages: list[ChatMessage],
    provider_id: str | None = None,
    model: str | None = None,
    max_tokens: int = 2048,
    temperature: float = 0.4,
    api_key: str | None = None,
    base_url: str | None = None,
) -> AsyncGenerator[str, None]:
    """Try the requested provider; fall back to next available on failure."""
    preferred = provider_id or os.environ.get("AI_DEFAULT_PROVIDER", "claude")
    order = [preferred] + [p for p in _FALLBACK_ORDER if p != preferred]

    last_err = None
    for pid in order:
        if pid not in _REGISTRY:
            continue
        try:
            provider = _REGISTRY[pid]
            if pid != preferred:
                yield f"\n[⚠ Fell back to {provider.display_name}]\n"
            kwargs = {"model": model, "max_tokens": max_tokens, "temperature": temperature}
            if pid == preferred:
                kwargs["api_key"] = api_key
                kwargs["base_url"] = base_url
            async for chunk in provider.stream(messages, **kwargs):
                yield chunk
            return
        except Exception as e:
            log.warning("Provider %s failed: %s", pid, e)
            last_err = e
            continue

    raise RuntimeError(f"All providers failed. Last error: {last_err}")
