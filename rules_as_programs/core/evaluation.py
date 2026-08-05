"""Normalized finding-time evaluation records, including legacy fallback."""

from __future__ import annotations

import hashlib
from typing import Any


def normalize_evaluation(
    finding: dict[str, Any],
    audit_entry: dict[str, Any] | None,
) -> dict[str, Any]:
    entry = audit_entry or {}
    current = entry.get("evaluation")
    if isinstance(current, dict) and current.get("schema_version") == 2:
        return dict(current)
    trace = list(entry.get("trace") or [])
    paw_entries = [
        item for item in trace if item.get("type") == "paw"]
    evidence_entries = [
        item for item in trace if item.get("type") == "evidence"]
    paw = paw_entries[-1] if paw_entries else {}
    evidence = evidence_entries[-1] if evidence_entries else {}
    input_text = str(
        paw.get("input")
        if paw else evidence.get("text")
        or finding.get("evidence", ""))
    input_bytes = input_text.encode("utf-8")
    return {
        "schema_version": 1,
        "kind": (
            "paw" if paw
            else "legacy_unknown" if finding.get("fuzzy")
            else "deterministic"
        ),
        "rule": {
            "id": finding.get("rule_id", ""),
            "name": finding.get("rule_title", ""),
        },
        "input": {
            "text": input_text,
            "sha256": hashlib.sha256(input_bytes).hexdigest(),
            "char_count": len(input_text),
            "byte_count": len(input_bytes),
            "recording_complete": False,
            "truncation_reason": "legacy_audit_record",
            "format": "legacy",
            "segments": [],
            "role": "legacy_recording",
        },
        "output": {
            "raw": str(
                paw.get("output") or finding.get("label", "")),
            "recording_complete": False,
            "truncation_reason": "legacy_audit_record",
            "severity": finding.get("severity", ""),
            "message": finding.get("message", ""),
        },
        "trigger": {
            "event_id": finding.get("trigger_event_id", ""),
            "kind": finding.get("trigger_kind", ""),
            "seq": None,
            "included_in_input": None,
            "event": None,
        },
        "context_through_seq": None,
        "trace_call_count": len(trace),
    }
