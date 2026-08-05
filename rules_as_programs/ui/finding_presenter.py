"""Pure presentation projection for one finding detail response."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from ..core.triggers import TRIGGERS


@dataclass(frozen=True)
class TextPresentation:
    format: str
    source: str
    formatted: str
    records: tuple[Any, ...] = ()


def utf16_range(text: str, start: int, end: int) -> tuple[int, int]:
    """Translate Python character offsets to an AppKit NSRange."""
    source = str(text or "")
    safe_start = max(0, min(len(source), int(start)))
    safe_end = max(safe_start, min(len(source), int(end)))
    location = len(source[:safe_start].encode("utf-16-le")) // 2
    end_location = len(source[:safe_end].encode("utf-16-le")) // 2
    return location, end_location - location


def classify_text(text: str) -> TextPresentation:
    source = str(text or "")
    stripped = source.strip()
    if stripped:
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, (dict, list)):
            return TextPresentation(
                "json", source,
                json.dumps(value, indent=2, ensure_ascii=False),
                (value,),
            )
        lines = [line for line in source.splitlines() if line.strip()]
        if len(lines) >= 2:
            records = []
            for line in lines:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    records = []
                    break
                if not isinstance(item, (dict, list)):
                    records = []
                    break
                records.append(item)
            if records:
                formatted = "\n\n".join(
                    f"Record {index + 1}\n"
                    + json.dumps(item, indent=2, ensure_ascii=False)
                    for index, item in enumerate(records)
                )
                return TextPresentation(
                    "jsonl", source, formatted, tuple(records))
    if source.lstrip().startswith(
        ("## Probes", "## Latest", "## Recent activity")
    ):
        return TextPresentation("rap-evidence-v1", source, source)
    return TextPresentation("plain", source, source)


def evidence_sections(text: str) -> list[dict[str, Any]]:
    source = str(text or "")
    headings = (
        ("## Probes", "Probes"),
        ("## Latest", "Latest message"),
        ("## Recent activity", "Recent activity"),
    )
    found = []
    for marker, label in headings:
        start = source.find(marker)
        if start >= 0:
            found.append((start, marker, label))
    found.sort()
    out = []
    for index, (start, marker, label) in enumerate(found):
        end = found[index + 1][0] if index + 1 < len(found) else len(source)
        block = source[start:end].strip()
        first_line, _, body = block.partition("\n")
        out.append({
            "label": label,
            "heading": first_line or marker,
            "text": body,
            "start": start,
            "end": end,
            "included": True,
        })
    return out


def present_finding(detail: dict[str, Any]) -> dict[str, Any]:
    finding = dict(detail.get("finding") or {})
    evaluation = dict(detail.get("evaluation") or {})
    if evaluation.get("schema_version") != 4:
        raise ValueError("unsupported finding schema")
    input_data = dict(evaluation.get("input") or {})
    input_text = str(input_data.get("text", ""))
    text = classify_text(input_text)
    if (
        input_data.get("format") == "plain"
        and text.format == "rap-evidence-v1"
    ):
        text = TextPresentation("plain", input_text, input_text)
    events = list((detail.get("ledger") or {}).get("events") or [])
    trigger = dict(evaluation.get("trigger") or {})
    hook = str(trigger.get("hook", ""))
    definition = TRIGGERS.get(hook)
    trigger_snapshot = trigger.get("event")
    if (
        isinstance(trigger_snapshot, dict)
        and not events
        and not any(event.get("is_trigger") for event in events)
    ):
        events = [{
            **trigger_snapshot,
            "is_trigger": True,
            "from_snapshot": True,
        }]
    current_rule = dict(detail.get("current_rule") or {})
    recorded_source = str((evaluation.get("rule") or {}).get("source", ""))
    trigger_index = next(
        (index for index, event in enumerate(events) if event.get("is_trigger")),
        -1,
    )
    preview = (
        events[max(0, trigger_index - 2):trigger_index + 3]
        if trigger_index >= 0 else events[:5]
    )
    return {
        "rule_name": str(
            finding.get("rule_title")
            or (evaluation.get("rule") or {}).get("name")
            or finding.get("rule_id", "Rule")),
        "severity": str(
            evaluation.get("severity") or finding.get("severity", "info")),
        "project_root": str(finding.get("project_root", "")),
        "occurred_at": float(finding.get("ts", 0) or 0),
        "relative_time": relative_time(float(finding.get("ts", 0) or 0)),
        "input": input_data,
        "input_text": input_text,
        "input_presentation": text,
        "input_label": (
            definition.input_label if definition else "Input"),
        "input_typography": (
            definition.typography if definition else "proportional"),
        "input_provenance": (
            f"{hook} {input_data.get('json_pointer', '')} "
            f"({input_data.get('pointer_source', 'default')})"
        ).strip(),
        "trigger": trigger,
        "context_preview": preview,
        "context_events": events,
        "additional_activity_count": len([
            event for event in events if not event.get("is_trigger")]),
        "rule_deleted": bool(
            finding.get("review_reason") == "rule_deleted"
            or recorded_source and not current_rule),
        "rule_editable": bool(current_rule),
        "recorded_source_complete": bool(recorded_source),
        "recorded_rule_projection": dict(
            detail.get("recorded_rule_projection") or {}),
        "evaluation": evaluation,
    }


def relative_time(timestamp: float, now: float | None = None) -> str:
    seconds = max(0, int((now or time.time()) - float(timestamp or 0)))
    if seconds < 60:
        return "now" if seconds < 10 else f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"
