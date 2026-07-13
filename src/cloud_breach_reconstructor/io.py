from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import EvidenceError, InputLimitError
from .json_safety import finite_float, reject_json_constant, validate_json_value

MAX_INPUT_BYTES = 50_000_000
MAX_LINE_BYTES = 1_000_000


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def decode_json(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=reject_json_constant,
            parse_float=finite_float,
        )
    except json.JSONDecodeError as error:
        raise EvidenceError(f"invalid JSON at line {error.lineno}, column {error.colno}") from error
    except RecursionError as error:
        raise EvidenceError("JSON exceeds maximum nesting depth") from error
    validate_json_value(value)
    return value


def load_records(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise EvidenceError(f"evidence file does not exist: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise InputLimitError(f"evidence file exceeds {MAX_INPUT_BYTES} bytes")
    records: list[dict[str, Any]] = []
    try:
        if path.suffix.casefold() == ".jsonl":
            with path.open("r", encoding="utf-8") as stream:
                for number, line in enumerate(stream, start=1):
                    if len(line.encode()) > MAX_LINE_BYTES:
                        raise InputLimitError(f"JSONL line {number} exceeds {MAX_LINE_BYTES} bytes")
                    if not line.strip():
                        continue
                    value = decode_json(line)
                    if not isinstance(value, dict):
                        raise EvidenceError(f"JSONL line {number} is not an object")
                    records.append(value)
            return records
        text = path.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise EvidenceError("evidence must be valid UTF-8") from error
    value = decode_json(text)
    if isinstance(value, dict):
        candidate = value.get("events")
        if not isinstance(candidate, list):
            raise EvidenceError("JSON object input must contain an events array")
        value = candidate
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise EvidenceError("JSON input must be an array of objects")
    return value


def load_truth(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise EvidenceError(f"ground truth file does not exist: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise InputLimitError(f"ground truth exceeds {MAX_INPUT_BYTES} bytes")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise EvidenceError("ground truth must be valid UTF-8") from error
    value = decode_json(text)
    if not isinstance(value, dict):
        raise EvidenceError("ground truth must be a JSON object")
    return value
