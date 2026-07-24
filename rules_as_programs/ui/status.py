"""Pure menu-bar status presentation derived from one UI snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from .model import UISnapshot

SEVERITY_RANK = {"info": 1, "warn": 2, "critical": 3}


@dataclass(frozen=True)
class StatusPresentation:
    kind: str
    severity: str | None
    finding_count: int
    attention_count: int
    incident_count: int
    paused: bool
    unavailable: bool
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
    health_issues = snapshot.data.get("health_issues", [])
    incident_count = (
        len(health_issues)
        if isinstance(health_issues, list)
        else 0
    )
    if not incident_count and health in ("failed", "degraded"):
        incident_count = 1
    paused = health == "paused"
    unavailable = snapshot.status == "unavailable"

    if finding_count:
        kind = "finding"
        badge = "99+" if finding_count > 99 else str(finding_count)
    elif attention_count:
        kind, badge = "attention", "?"
    elif unavailable:
        kind, badge = "unavailable", "!"
    elif paused:
        kind, badge = "paused", "‖"
    elif incident_count:
        kind, badge = "degraded", "!"
    else:
        kind, badge = "clear", ""

    if finding_count:
        label = {
            "info": "Info",
            "warn": "Warning",
            "critical": "Critical",
        }.get(severity or "", "Finding")
        summary = f"{finding_count} open, highest {label}"
    else:
        summary = "no open findings"
    if unavailable:
        summary += "; daemon unavailable, count is last known"
    elif paused:
        summary += "; monitoring paused"
    if incident_count:
        issue_summary = ""
        if isinstance(health_issues, list) and health_issues:
            issue_summary = str(health_issues[0].get("summary", ""))
        summary += (
            f"; {issue_summary}" if issue_summary
            else f"; {incident_count} rule check issue"
            f"{'s' if incident_count != 1 else ''}"
        )
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
        incident_count=incident_count,
        paused=paused,
        unavailable=unavailable,
        badge_text=badge,
        tooltip=f"Rules as Programs — {summary}",
        accessibility=f"Rules as Programs, {summary}",
    )
