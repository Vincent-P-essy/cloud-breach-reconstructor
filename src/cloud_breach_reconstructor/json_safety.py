from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, NoReturn

from .errors import EvidenceError

MAX_JSON_DEPTH = 64


def validate_json_value(
    value: Any, *, label: str = "JSON value", maximum_depth: int = MAX_JSON_DEPTH
) -> None:
    """Reject structures that cannot be represented as finite, bounded JSON."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > maximum_depth:
            raise EvidenceError(f"{label} exceeds maximum JSON depth of {maximum_depth}")
        if isinstance(item, Mapping):
            if not all(isinstance(key, str) for key in item):
                raise EvidenceError(f"{label} contains a non-string object key")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list | tuple):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise EvidenceError(f"{label} contains a non-finite number")


def finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise EvidenceError("JSON contains a non-finite number")
    return parsed


def reject_json_constant(value: str) -> NoReturn:
    raise EvidenceError(f"invalid JSON numeric constant: {value}")
