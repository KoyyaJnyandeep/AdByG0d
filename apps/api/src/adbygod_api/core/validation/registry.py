from __future__ import annotations

from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    pass

_REGISTRY: dict[str, list[Type]] = {}


def register(module_id: str):
    """Decorator: @register("kerberos") on expert classes."""
    def decorator(cls: Type) -> Type:
        _REGISTRY.setdefault(module_id, []).append(cls)
        return cls
    return decorator


def get_experts_for(module_id: str) -> list[Type]:
    return list(_REGISTRY.get(module_id, []))


def all_module_ids() -> list[str]:
    return list(_REGISTRY.keys())


def expert_count(module_id: str) -> int:
    return len(_REGISTRY.get(module_id, []))


def registered_count() -> int:
    return sum(len(v) for v in _REGISTRY.values())
