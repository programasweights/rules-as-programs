"""Pure menu-bar status presentation derived from one UI snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from .model import UISnapshot

SEVERITY_RANK = {"info": 1, "warn": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class StatusPresentation:
    kind: str
    severity: str | None
    finding_count: int
    attention_count: int
    badge_text: str
    tooltip: str
    accessibility: str


def status_presentation(snapshot: UISnapshot) -> StatusPresentation:
    findings = [
        finding
        for groups in snapshot.findings_by_project.values()
        for finding in groups
        if not finding.get("stale")
    ]
    severity = max(
        (str(item.get("severity", "info")) for item in findings),
        key=lambda value: SEVERITY_RANK.get(value, 0),
        default=None,
    )
    finding_count = snapshot.open_count
    attention_count = int(snapshot.data.get("attention_count", 0) or 0)
    health = str(snapshot.daemon.get("health", "ready"))

    if snapshot.status == "unavailable":
        kind, badge = "unavailable", "!"
    elif health == "paused":
        kind, badge = "paused", "‖"
    elif health in ("failed", "degraded"):
        kind, badge = "degraded", "!"
    elif finding_count:
        kind = "finding"
        badge = "9+" if finding_count > 9 else str(finding_count)
    elif attention_count:
        kind, badge = "attention", "?"
    else:
        kind, badge = "clear", ""

    if kind == "unavailable":
        summary = "daemon unavailable"
    elif kind == "paused":
        summary = "monitoring paused"
    elif kind == "degraded":
        summary = "monitoring degraded"
    elif finding_count:
        label = {
            "info": "Info",
            "warn": "Warning",
            "high": "High",
            "critical": "Critical",
        }.get(severity or "", "Finding")
        summary = f"{finding_count} open, highest {label}"
    else:
        summary = "no open findings"
    if attention_count:
        summary += (
            ", 1 project needs reply" if attention_count == 1
            else f", {attention_count} projects need reply"
        )

    return StatusPresentation(
        kind=kind,
        severity=severity,
        finding_count=finding_count,
        attention_count=attention_count,
        badge_text=badge,
        tooltip=f"Rules as Programs — {summary}",
        accessibility=f"Rules as Programs, {summary}",
    )
