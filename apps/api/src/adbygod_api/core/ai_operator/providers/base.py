from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncGenerator


@dataclass
class ChatMessage:
    role: str   # "system" | "user" | "assistant"
    content: str


@dataclass
class ProviderInfo:
    id: str
    name: str
    available: bool
    models: list[str]
    default_model: str
    local: bool = False
    error: str | None = None


class AIProvider(ABC):
    """All AI providers implement this interface."""

    @property
    @abstractmethod
    def provider_id(self) -> str: ...

    @property
    @abstractmethod
    def display_name(self) -> str: ...

    @abstractmethod
    async def complete(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> str:
        """Non-streaming completion. Returns full response text."""
        ...

    @abstractmethod
    async def stream(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.4,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> AsyncGenerator[str, None]:
        """Streaming completion. Yields text chunks."""
        ...

    @abstractmethod
    async def health_check(self, api_key: str | None = None, base_url: str | None = None) -> ProviderInfo: ...
