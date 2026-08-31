"""Filesystem paths and scoping helpers shared across the package.

Two ideas live here:

* **State** (sqlite verdict store, per-conversation ledgers, logs) lives under a
  single cache dir, overridable with ``RAP_STATE_DIR``.  The transient daemon
  socket may be placed elsewhere with ``RAP_SOCKET_PATH`` when a runtime needs
  a bounded AF_UNIX pathname.
* **Rules** are resolved from two scopes so users can keep constraints global or
  scope them to a single repo:
    - global:  ``~/.codex/rules-as-programs/rules/<id>/rule.py``
    - project: ``<repo>/.codex/rules-as-programs/rules/<id>/rule.py``
  Project rules override global rules that share the same ``id``.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "rules-as-programs"


def state_dir() -> Path:
    """Root for all runtime state (socket, db, ledgers, logs)."""
    override = os.environ.get("RAP_STATE_DIR")
    if override:
        base = Path(override).expanduser()
    else:
        base = Path.home() / ".cache" / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def socket_path() -> Path:
    override = os.environ.get("RAP_SOCKET_PATH")
    if override:
        return Path(override).expanduser()
    return state_dir() / "daemon.sock"


def db_path() -> Path:
    return state_dir() / "verdicts.db"


def validation_db_path() -> Path:
    return state_dir() / "validation-results.db"


def deployment_queue_path() -> Path:
    return state_dir() / "deployment-queue.json"


def ledger_dir() -> Path:
    d = state_dir() / "ledgers"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_path() -> Path:
    return state_dir() / "daemon.log"


def daemon_stderr_path() -> Path:
    return state_dir() / "daemon-stderr.log"


def tray_log_path() -> Path:
    return state_dir() / "tray.log"


def tray_lock_path() -> Path:
    return state_dir() / "tray.lock"


def pid_path() -> Path:
    return state_dir() / "daemon.pid"


def paw_cache_path() -> Path:
    """Where we remember compiled PAW program ids keyed by spec hash."""
    return state_dir() / "paw_programs.json"


def compiler_catalog_path() -> Path:
    return state_dir() / "compiler_catalog.json"


def mutes_path() -> Path:
    """Personal hidden-finding state: {rule_id: null}. '*' = hide all."""
    return state_dir() / "mutes.json"


def rule_state_path() -> Path:
    """Persistent rule enable/disable state: {rule_id: false} means disabled."""
    return state_dir() / "rule_state.json"


def rule_coverage_path() -> Path:
    """Projects explicitly selected for each library-owned rule."""
    return state_dir() / "rule_coverage.json"


def rule_deployment_drafts_path() -> Path:
    """Undeployed project-coverage edits keyed by immutable rule ID."""
    return state_dir() / "rule_deployment_drafts.json"


def project_monitoring_path() -> Path:
    """Per-project monitoring switch: {project_path: false} means off."""
    return state_dir() / "project_monitoring.json"


def monitoring_state_path() -> Path:
    """Global monitoring state, separate from finding-surfacing mutes."""
    return state_dir() / "monitoring_state.json"


def active_revisions_path() -> Path:
    return state_dir() / "active_revisions.json"


def revision_dir() -> Path:
    path = state_dir() / "revisions"
    path.mkdir(parents=True, exist_ok=True)
    return path


# --- per-project audit log (lives inside the project) ----------------------

def project_log_dir(project_root: str | os.PathLike[str]) -> Path:
    return Path(project_root) / ".codex" / APP_NAME / "log"


def project_log_file(project_root: str | os.PathLike[str]) -> Path:
    return project_log_dir(project_root) / "audit.jsonl"


def project_evaluation_log_file(
    project_root: str | os.PathLike[str],
) -> Path:
    return project_log_dir(project_root) / "evaluations.jsonl"


def project_rules_config_path(project_root: str | os.PathLike[str]) -> Path:
    return Path(project_root) / ".codex" / APP_NAME / "config.json"


# --- bundled brand assets --------------------------------------------------

def asset_dir() -> Path:
    return Path(__file__).parent / "assets"


def bundled_paw_png() -> Path:
    return asset_dir() / "paw-192.png"


def icon_png() -> Path:
    """Menu-bar icon source. Prefer the refreshable state-dir copy (updated from
    programasweights.com on ``rap init``), falling back to the bundled asset."""
    cached = state_dir() / "paw-192.png"
    if cached.exists():
        return cached
    return bundled_paw_png()


# --- Rule scopes -----------------------------------------------------------

def global_rules_dir() -> Path:
    return codex_home() / APP_NAME / "rules"


def project_rules_dir(project_root: str | os.PathLike[str]) -> Path:
    return Path(project_root) / ".codex" / APP_NAME / "rules"


def codex_home() -> Path:
    """Codex user configuration root, honoring ``CODEX_HOME``."""
    configured = os.environ.get("CODEX_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


def codex_hooks_path(
    scope: str,
    project_root: str | os.PathLike[str] | None = None,
) -> Path:
    """Path to the Codex ``hooks.json`` for a given scope.

    scope: ``"global"`` -> ``$CODEX_HOME/hooks.json``
           ``"project"`` -> ``<project_root>/.codex/hooks.json``
    """
    if scope == "global":
        return codex_home() / "hooks.json"
    if scope == "project":
        if project_root is None:
            project_root = os.getcwd()
        return Path(project_root) / ".codex" / "hooks.json"
    raise ValueError(f"unknown scope: {scope!r}")


def legacy_rules_dir(
    scope: str,
    project_root: str | os.PathLike[str] | None = None,
) -> Path:
    """Pre-Codex RAP rule directory used only by the migration path."""
    if scope == "global":
        return Path.home() / ".cursor" / APP_NAME / "rules"
    if scope == "project":
        return Path(project_root or os.getcwd()) / ".cursor" / APP_NAME / "rules"
    raise ValueError(f"unknown scope: {scope!r}")


def legacy_project_state_dir(
    project_root: str | os.PathLike[str],
) -> Path:
    return Path(project_root) / ".cursor" / APP_NAME
