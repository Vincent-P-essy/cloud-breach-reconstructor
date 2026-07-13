from __future__ import annotations

from pathlib import Path

from cloud_breach_reconstructor.io import load_records, load_truth

ROOT = Path(__file__).resolve().parents[1]


def lab_records():
    return load_records(ROOT / "datasets/lab/events.jsonl")


def lab_truth():
    return load_truth(ROOT / "datasets/lab/ground-truth.json")


def canonical(event_id: str, timestamp: str, **overrides):
    value = {
        "provider": "aws",
        "event_id": event_id,
        "timestamp": timestamp,
        "source_type": "test",
        "actor": "arn:aws:iam::1:user/test",
        "action": "test:Read",
        "resource": "resource:test",
        "outcome": "success",
        "session_id": "",
        "request_id": "",
        "source_ip": "192.0.2.1",
        "account_id": "1",
        "attributes": {},
    }
    value.update(overrides)
    return value
