from __future__ import annotations

from typing import Any


def first_value(value: Any, default: Any = None) -> Any:
    """Return a scalar from common ldap3 attribute/list wrappers."""
    if value is None:
        return default
    if hasattr(value, "values"):
        values = value.values
        value = values[0] if values else default
    elif hasattr(value, "value"):
        value = value.value
    if isinstance(value, (list, tuple, set)):
        return next(iter(value), default)
    if str(value) in ("", "[]", "None"):
        return default
    return value


def int_value(value: Any, default: int = 0) -> int:
    value = first_value(value, default)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def list_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if hasattr(value, "values"):
        return list(value.values)
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if str(value) in ("", "[]", "None"):
        return []
    return [value]
