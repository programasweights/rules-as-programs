#!/usr/bin/env python3
"""Run the RAP multi-rule/multi-project scaling and fault study.

The default formal design implements protocol v3. Candidate and smoke runs are
explicitly labeled and cannot write below ``outputs/frozen``. Each
matrix condition uses a fresh isolated RAP state directory, fresh synthetic
project roots, and a fresh daemon process.  The installed project hook wrapper
is the only event-ingress path.

The primary endpoint is *query-visible completion of every expected rule
evaluation*.  It is not Codex turn latency, rendered UI latency, or human
perception.  Codex normally schedules this fail-open hook asynchronously; the
harness synchronously launches the exact installed wrapper so its boundary can
be measured reproducibly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

try:
    import psutil
except ImportError as exc:  # pragma: no cover - environment dependency
    raise SystemExit(
        "run_scaling_faults.py requires psutil (python -m pip install psutil)"
    ) from exc


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rules_as_programs import config as rap_config  # noqa: E402
from rules_as_programs import ipc, rules_api  # noqa: E402
from rules_as_programs.adapters.codex.adapter import CodexAdapter, normalize  # noqa: E402
from rules_as_programs.core import revisions  # noqa: E402
from rules_as_programs.core.triggers import extract_input  # noqa: E402

from experiments.eacl2027 import run_integrated as integrated  # noqa: E402


EXTERNAL_MANIFEST = (
    ROOT / "outputs" / "frozen" / "external-paw-finetuned.jsonl.manifest.json"
)
EXTERNAL_OUTPUT = ROOT / "outputs" / "frozen" / "external-paw-finetuned.jsonl"
EXTERNAL_DATASET = ROOT / "data" / "public" / "external.jsonl"
FORMAL_AMENDMENT = ROOT / "protocol-v3-amendment-004.json"
FORMAL_AMENDMENT_SHA256 = (
    "94020b51609ded8be42158111a2bd1670bb292db004aca5875ddf78059c48d6b"
)
FROZEN_OUTPUT_DIR = (ROOT / "outputs" / "frozen").resolve()
EXTERNAL_RULE_ORDER = (
    "3pcxewp5hggr1vsn",
    "98z9wvr031840p4g",
    "e3m4bdwj6gqcwpnn",
    "g3b7damk0b5xgdj6",
    "q88xgdmftag16dq9",
    "qfh0h1cf4wt5aeg4",
    "sr09vpkt60y74r0q",
    "xb24rc14cpcrsf4g",
)
DEFAULT_RULE_COUNTS = (1, 2, 4, 8)
DEFAULT_PROJECT_COUNTS = (1, 4, 8)
DEFAULT_BURST_SIZES = (24, 64)
DEFAULT_REPEATS = 5
DEFAULT_SEQUENTIAL_EVENTS = 250
DEFAULT_WARMUPS_PER_PROJECT = 1
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_HOOK_WORKERS = 24
DEFAULT_SOAK_BATCH_SIZE = 64
DEFAULT_SOAK_EVENTS = 10_000
DEFAULT_FAULT_REPETITIONS = 20
TRAFFIC_PATTERNS = ("round_robin_across_projects", "one_project_hotspot")
QUERY_POLL_INTERVAL_SECONDS = 0.01
RESOURCE_SAMPLE_INTERVAL_SECONDS = 0.05
EVALUATION_HISTORY_LIMIT = 5000
SQLITE_BUSY_TIMEOUT_SECONDS = 5.0
_SENSITIVE_ENV_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "AUTHORIZATION",
    "PRIVATE_KEY",
)


class SystemsHarnessError(RuntimeError):
    """Raised when a systems-study invariant is violated."""


@dataclass(frozen=True)
class RuleArtifact:
    rule_id: str
    source: str
    source_path: str
    source_file_sha256: str
    source_sha256: str
    behavior_sha256: str
    program_id: str = ""
    compiler: str = ""
    compiler_snapshot: str = ""
    probe_tool_input: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArtifactBundle:
    artifacts: tuple[RuleArtifact, ...]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class MatrixConfig:
    rule_counts: tuple[int, ...] = DEFAULT_RULE_COUNTS
    project_counts: tuple[int, ...] = DEFAULT_PROJECT_COUNTS
    burst_sizes: tuple[int, ...] = DEFAULT_BURST_SIZES
    repeats: int = DEFAULT_REPEATS
    sequential_events: int = DEFAULT_SEQUENTIAL_EVENTS
    warmups_per_project: int = DEFAULT_WARMUPS_PER_PROJECT
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_hook_workers: int = DEFAULT_MAX_HOOK_WORKERS
    soak_events: int = 0
    soak_rule_count: int = 8
    soak_project_count: int = 8
    soak_batch_size: int = DEFAULT_SOAK_BATCH_SIZE
    fault_repetitions: int = DEFAULT_FAULT_REPETITIONS

    def validate(self, available_rules: int = 8) -> None:
        for label, values in (
            ("rule counts", self.rule_counts),
            ("project counts", self.project_counts),
            ("burst sizes", self.burst_sizes),
        ):
            if not values or any(value < 1 for value in values):
                raise ValueError(f"{label} must contain positive integers")
            if len(set(values)) != len(values):
                raise ValueError(f"{label} must not contain duplicates")
        if max(self.rule_counts) > available_rules:
            raise ValueError(
                f"requested {max(self.rule_counts)} rules, only {available_rules} exist"
            )
        if self.repeats < 1 or self.sequential_events < 1:
            raise ValueError("repeats and sequential events must be positive")
        if self.warmups_per_project < 0:
            raise ValueError("warmups per project must be non-negative")
        if self.timeout_seconds <= 0 or self.max_hook_workers < 1:
            raise ValueError("timeout and max hook workers must be positive")
        if self.soak_events < 0 or self.soak_batch_size < 1:
            raise ValueError("soak events must be non-negative and batch size positive")
        if self.fault_repetitions < 1:
            raise ValueError("fault repetitions must be positive")
        if self.soak_events and (
            self.soak_rule_count not in self.rule_counts
            or self.soak_project_count not in self.project_counts
        ):
            raise ValueError(
                "soak rule/project count must be present in the configured matrix"
            )
        if self.soak_batch_size * max(self.rule_counts) >= EVALUATION_HISTORY_LIMIT:
            raise ValueError(
                "soak batch creates too many evaluations for exact history accounting"
            )


@dataclass(frozen=True)
class ExpectedEvaluation:
    case_id: str
    project_root: str
    input_sha256: str
    rule_id: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.project_root, self.input_sha256, self.rule_id)


@dataclass
class InstalledProject:
    index: int
    root: Path
    wrapper: Path
    hooks_json: Path


@dataclass
class RunningFixture:
    isolated_root: Path
    environment: dict[str, str]
    projects: list[InstalledProject]
    artifacts: tuple[RuleArtifact, ...]
    diagnostics: Path
    daemon: subprocess.Popen[Any]
    identity: dict[str, Any]


FAULT_CAPABILITIES: dict[str, dict[str, Any]] = {
    "daemon_crash": {
        "feasible": os.name == "posix",
        "injection": "SIGKILL the isolated daemon before an installed-hook delivery",
        "boundary": "hook fail-open plus first post-respawn exact evaluation",
    },
    "worker_exit": {
        "feasible": True,
        "injection": "terminate the idle supervised PAW inference worker",
        "boundary": "next event to all expected query-visible evaluations",
    },
    "worker_timeout": {
        "feasible": hasattr(signal, "SIGSTOP"),
        "injection": (
            "SIGSTOP the idle PAW worker before dispatch so the production native "
            "timeout kills it"
        ),
        "boundary": "faulting evaluation outcome plus next-event recovery",
        "limitation": "does not claim a kill at a known instruction inside llama.cpp",
    },
    "sqlite_lock": {
        "feasible": True,
        "injection": (
            "hold an external SQLite EXCLUSIVE transaction beyond the production "
            "five-second busy timeout"
        ),
        "boundary": "accepted event, incident/outcome state, and next-event recovery",
    },
    "malformed_payload": {
        "feasible": True,
        "injection": "send invalid JSON and an oversized trigger field to the wrapper",
        "boundary": "hook contract and evaluation-history delta",
    },
    "duplicate_delivery": {
        "feasible": True,
        "injection": "concurrently redeliver byte-identical Codex hook payloads",
        "boundary": "daemon admission counter and exact evaluation/finding counts",
    },
    "deployment_failure": {
        "feasible": True,
        "injection": "change a working draft after prepare and then commit its stale token",
        "boundary": "commit rejection and next evaluation's active-revision hash",
        "limitation": "tests atomic stale-commit failure, not remote compiler transport",
    },
    "remote_compiler_transport_failure": {
        "feasible": False,
        "reason": (
            "the study pins already-compiled public programs; faithfully forcing a remote "
            "compiler outage requires service/network control outside the production API"
        ),
    },
}


DETERMINISTIC_RULE_ID = "systfawtprbe0001"
DETERMINISTIC_RULE_SOURCE = f'''from rules_as_programs import rule


@rule(
    id="{DETERMINISTIC_RULE_ID}",
    name="Synthetic systems fault probe",
    trigger="PreToolUse",
    max_input_bytes=1024,
)
def synthetic_systems_fault_probe(ctx):
    """Synthetic systems fault probe."""
    return ctx.result("WARNING")
'''


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _subprocess_environment(
    environment: dict[str, str], overrides: dict[str, str] | None = None
) -> dict[str, str]:
    """Remove credentials that local inference and the hook never require.

    Besides reducing ambient authority, this prevents a failed subprocess call
    from rendering unrelated API credentials in a Python traceback.
    """
    sanitized = {
        name: value
        for name, value in environment.items()
        if not any(marker in name.upper() for marker in _SENSITIVE_ENV_MARKERS)
        and name not in ("SSH_AUTH_SOCK", "GITHUB_ENV")
    }
    sanitized.update(overrides or {})
    return sanitized


def _jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemsHarnessError(
            f"could not read validated JSONL {path}: {exc}"
        ) from exc


def _normalized_managed_source(rule_id: str, source: str) -> str:
    """Return the exact source form persisted by ``rules_api.save_rule``."""
    projection = rules_api.source_projection(source)
    if not projection.get("ok"):
        raise SystemsHarnessError(
            f"could not project rule source {rule_id}: {projection.get('error')}"
        )
    name = str(projection.get("name") or projection.get("title") or "Rule")
    ok, normalized, error = rules_api.patch_rule_identity(source, rule_id, name)
    if not ok:
        raise SystemsHarnessError(f"could not normalize {rule_id}: {error}")
    return normalized if normalized.endswith("\n") else normalized + "\n"


def load_external_artifacts() -> ArtifactBundle:
    """Load and cross-check the eight frozen external finetuned programs."""
    try:
        manifest = json.loads(EXTERNAL_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemsHarnessError(f"invalid external PAW manifest: {exc}") from exc
    if _sha256_file(EXTERNAL_DATASET) != str(manifest.get("dataset_sha256", "")):
        raise SystemsHarnessError("external dataset hash does not match its manifest")
    if _sha256_file(EXTERNAL_OUTPUT) != str(manifest.get("output_sha256", "")):
        raise SystemsHarnessError(
            "external PAW output hash does not match its manifest"
        )
    dataset_value = str(manifest.get("dataset", ""))
    if (REPO_ROOT / dataset_value).resolve() != EXTERNAL_DATASET.resolve():
        raise SystemsHarnessError("external manifest points at an unexpected dataset")

    compiler = str(manifest.get("compiler", ""))
    program_ids = dict(manifest.get("program_ids") or {})
    compiler_info = dict(manifest.get("compiler_info") or {})
    if set(program_ids) != set(EXTERNAL_RULE_ORDER):
        raise SystemsHarnessError(
            "external manifest rule set is not the fixed eight-rule set"
        )
    dataset = _jsonl(EXTERNAL_DATASET)
    output = _jsonl(EXTERNAL_OUTPUT)
    artifacts = []
    for rule_id in EXTERNAL_RULE_ORDER:
        source_path = ROOT / "rules" / rule_id / "rule.py"
        compiled_source = source_path.read_text(encoding="utf-8")
        source = _normalized_managed_source(rule_id, compiled_source)
        source_file_hash = _sha256_file(source_path)
        source_hashes = {
            str(row.get("source_hash", ""))
            for row in dataset
            if str(row.get("rule_id", "")) == rule_id
        }
        output_programs = {
            str(row.get("program_id", ""))
            for row in output
            if str(row.get("rule_id", "")) == rule_id
        }
        output_sources = {
            str(row.get("source_hash", ""))
            for row in output
            if str(row.get("rule_id", "")) == rule_id
        }
        program_id = str(program_ids.get(rule_id, ""))
        if source_hashes != {source_file_hash} or output_sources != source_hashes:
            raise SystemsHarnessError(f"source provenance mismatch for {rule_id}")
        if output_programs != {program_id} or not program_id:
            raise SystemsHarnessError(f"program provenance mismatch for {rule_id}")
        if revisions.behavior_hash(compiled_source) != revisions.behavior_hash(source):
            raise SystemsHarnessError(
                f"managed source normalization changed behavior for {rule_id}"
            )
        info = dict(compiler_info.get(rule_id) or {})
        snapshot = str(info.get("latest_snapshot", ""))
        if not compiler or not snapshot:
            raise SystemsHarnessError(f"compiler provenance missing for {rule_id}")
        representative = next(
            (
                dict(row)
                for row in dataset
                if str(row.get("rule_id", "")) == rule_id
                and str(row.get("expected", "")) == "WARNING"
            ),
            None,
        )
        if representative is None:
            raise SystemsHarnessError(f"no positive probe input for {rule_id}")
        try:
            tool_input = json.loads(str(representative["input"]))
        except (KeyError, json.JSONDecodeError) as exc:
            raise SystemsHarnessError(f"invalid probe input for {rule_id}") from exc
        if not isinstance(tool_input, dict):
            raise SystemsHarnessError(f"probe input for {rule_id} is not an object")
        artifacts.append(
            RuleArtifact(
                rule_id=rule_id,
                source=source,
                source_path=str(source_path.relative_to(REPO_ROOT)),
                source_file_sha256=source_file_hash,
                source_sha256=revisions.hash_source(source),
                behavior_sha256=revisions.behavior_hash(source),
                program_id=program_id,
                compiler=compiler,
                compiler_snapshot=snapshot,
                probe_tool_input=tool_input,
            )
        )
    return ArtifactBundle(
        artifacts=tuple(artifacts),
        provenance={
            "manifest": {
                "path": str(EXTERNAL_MANIFEST.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(EXTERNAL_MANIFEST),
            },
            "dataset": {
                "path": str(EXTERNAL_DATASET.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(EXTERNAL_DATASET),
            },
            "output": {
                "path": str(EXTERNAL_OUTPUT.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(EXTERNAL_OUTPUT),
            },
            "rule_order": list(EXTERNAL_RULE_ORDER),
        },
    )


def deterministic_artifact() -> RuleArtifact:
    source = _normalized_managed_source(
        DETERMINISTIC_RULE_ID, DETERMINISTIC_RULE_SOURCE
    )
    return RuleArtifact(
        rule_id=DETERMINISTIC_RULE_ID,
        source=source,
        source_path="<generated deterministic fault fixture>",
        source_file_sha256=_sha256_bytes(DETERMINISTIC_RULE_SOURCE.encode("utf-8")),
        source_sha256=revisions.hash_source(source),
        behavior_sha256=revisions.behavior_hash(source),
        probe_tool_input={"command": "synthetic fault probe"},
    )


def parse_int_tuple(value: str, *, allowed: set[int] | None = None) -> tuple[int, ...]:
    try:
        parsed = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not parsed or any(item < 1 for item in parsed):
        raise argparse.ArgumentTypeError("expected one or more positive integers")
    if len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("values must not be repeated")
    if allowed is not None and not set(parsed).issubset(allowed):
        raise argparse.ArgumentTypeError(
            f"values must be selected from {','.join(str(item) for item in sorted(allowed))}"
        )
    return parsed


def build_matrix_plan(config: MatrixConfig) -> list[dict[str, Any]]:
    config.validate()
    plan = []
    for rule_count in config.rule_counts:
        for project_count in config.project_counts:
            for repeat in range(config.repeats):
                workloads = [
                    ("sequential", config.sequential_events),
                    *(("burst", size) for size in config.burst_sizes),
                ]
                for traffic in TRAFFIC_PATTERNS:
                    for mode, events in workloads:
                        plan.append(
                            {
                                "condition_id": (
                                    f"r{rule_count}-p{project_count}-{traffic}-"
                                    f"{mode}{events}-rep{repeat}"
                                ),
                                "rule_count": rule_count,
                                "project_count": project_count,
                                "mode": mode,
                                "events": events,
                                "repeat": repeat,
                                "fresh_daemon": True,
                                "fresh_state": True,
                                "schedule": traffic,
                            }
                        )
    return plan


def _raw_event(
    project: Path,
    *,
    project_index: int,
    sequence: int,
    condition_id: str,
    tool_input: dict[str, Any],
) -> dict[str, Any]:
    case_id = f"{condition_id}-p{project_index}-e{sequence}"
    marked_input = dict(tool_input)
    marked_input["_rap_systems_probe"] = {
        "case_id": case_id,
        "project_index": project_index,
    }
    return {
        "session_id": f"systems-session-{case_id}",
        "turn_id": f"systems-turn-{case_id}",
        "hook_event_name": "PreToolUse",
        "cwd": str(project),
        "tool_name": "Bash",
        "tool_use_id": f"systems-tool-{case_id}",
        "tool_input": marked_input,
    }


def _expected_input(raw: dict[str, Any]) -> str:
    events = normalize(raw)
    if len(events) != 1:
        raise SystemsHarnessError(
            f"expected one normalized event, observed {len(events)}"
        )
    text, _pointer, _kind, _overridden = extract_input(
        "PreToolUse", events[0].raw_payload, ""
    )
    return text


def _install_projects(
    isolated_root: Path,
    artifacts: Sequence[RuleArtifact],
    project_count: int,
) -> list[InstalledProject]:
    projects = []
    for project_index in range(project_count):
        project = (isolated_root / f"project-{project_index}").resolve()
        project.mkdir(parents=True)
        for artifact in artifacts:
            saved = rules_api.save_rule(
                artifact.rule_id, artifact.source, "project", str(project)
            )
            if not saved.get("ok"):
                raise SystemsHarnessError(
                    f"could not install {artifact.rule_id} in {project}: "
                    f"{saved.get('error', 'unknown error')}"
                )
            saved_source = str(saved["source"])
            if revisions.hash_source(saved_source) != artifact.source_sha256:
                raise SystemsHarnessError(
                    f"installed source hash changed for {artifact.rule_id}"
                )
            revisions.activate(
                artifact.rule_id,
                str(saved["path"]),
                saved_source,
                compiler=artifact.compiler or None,
                program_id=artifact.program_id or None,
                compiler_snapshot=artifact.compiler_snapshot or None,
                compiler_mode=(
                    revisions.EXPLICIT_COMPILER_MODE if artifact.compiler else None
                ),
            )
        CodexAdapter().install("project", str(project))
        wrapper = project / ".codex" / "hooks" / "rap-hook.sh"
        hooks_json = project / ".codex" / "hooks.json"
        if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
            raise SystemsHarnessError(f"installed wrapper missing for {project}")
        if "rap-hook.sh" not in hooks_json.read_text(encoding="utf-8"):
            raise SystemsHarnessError(f"hooks.json does not register RAP for {project}")
        projects.append(InstalledProject(project_index, project, wrapper, hooks_json))
    return projects


@contextmanager
def _running_fixture(
    artifacts: Sequence[RuleArtifact],
    project_count: int,
    *,
    environment_overrides: dict[str, str] | None = None,
) -> Iterator[RunningFixture]:
    with tempfile.TemporaryDirectory(prefix="rap-systems-", dir="/tmp") as temporary:
        isolated_root = Path(temporary)
        with integrated._isolated_environment(isolated_root) as base_environment:
            environment = _subprocess_environment(
                base_environment, environment_overrides
            )
            projects = _install_projects(isolated_root, artifacts, project_count)
            diagnostics = isolated_root / "daemon-output.log"
            try:
                daemon, identity = integrated._start_daemon(
                    environment, diagnostics, DEFAULT_TIMEOUT_SECONDS
                )
            except Exception as exc:
                raise SystemsHarnessError(str(exc)) from None
            fixture = RunningFixture(
                isolated_root=isolated_root,
                environment=environment,
                projects=projects,
                artifacts=tuple(artifacts),
                diagnostics=diagnostics,
                daemon=daemon,
                identity=identity,
            )
            try:
                yield fixture
            finally:
                # This also shuts down an auto-respawned daemon because the parent
                # process still points at the fixture's isolated socket.
                try:
                    ipc.send_request({"type": "shutdown"}, timeout=1.0)
                except Exception:
                    pass
                integrated._stop_daemon(daemon)


def _invoke_payload(
    wrapper: Path,
    cwd: Path,
    payload: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    started_ns = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            [str(wrapper)],
            cwd=cwd,
            env=environment,
            input=payload,
            text=True,
            capture_output=True,
            timeout=integrated.HOOK_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemsHarnessError("installed hook process timed out") from exc
    exited_ns = time.perf_counter_ns()
    result = {
        "started_ns": started_ns,
        "exited_ns": exited_ns,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    try:
        integrated._assert_hook_contract(result, "systems harness hook")
    except integrated.IntegratedExperimentError as exc:
        raise SystemsHarnessError(str(exc)) from exc
    return result


def _invoke_raw(
    wrapper: Path,
    raw: dict[str, Any],
    environment: dict[str, str],
) -> dict[str, Any]:
    return _invoke_payload(wrapper, Path(str(raw["cwd"])), json.dumps(raw), environment)


def _evaluation_history(
    project: Path, *, limit: int = EVALUATION_HISTORY_LIMIT
) -> list[dict[str, Any]]:
    response = ipc.send_request(
        {
            "type": "evaluation_history",
            "project_root": str(project),
            "limit": min(EVALUATION_HISTORY_LIMIT, max(1, limit)),
        },
        timeout=1.0,
    )
    if not response or not response.get("ok"):
        return []
    return list(response.get("evaluations") or [])


def _input_hash_from_row(row: dict[str, Any]) -> str:
    value = str((row.get("input") or {}).get("sha256", ""))
    if value:
        return value
    text = (row.get("input") or {}).get("text")
    return _sha256_bytes(str(text).encode("utf-8")) if text is not None else ""


def _row_key(row: dict[str, Any], log_project: Path) -> tuple[str, str, str]:
    return (
        str(log_project),
        _input_hash_from_row(row),
        str((row.get("rule") or {}).get("id", "")),
    )


def _key_json(key: tuple[str, str, str]) -> dict[str, str]:
    return {"project_root": key[0], "input_sha256": key[1], "rule_id": key[2]}


def account_evaluations(
    rows_by_project: dict[str, list[dict[str, Any]]],
    expected: Sequence[ExpectedEvaluation],
    artifacts: Sequence[RuleArtifact],
    *,
    started_wall_time: float,
) -> dict[str, Any]:
    """Account exact evaluations and project isolation for one workload."""
    expected_keys = [item.key for item in expected]
    if len(set(expected_keys)) != len(expected_keys):
        raise SystemsHarnessError("expected evaluation generator produced duplicates")
    expected_set = set(expected_keys)
    global_input_projects: dict[str, str] = {}
    for item in expected:
        previous = global_input_projects.setdefault(
            item.input_sha256, item.project_root
        )
        if previous != item.project_root:
            raise SystemsHarnessError(
                "probe input hashes are not globally project-unique"
            )
    expected_artifacts = {item.rule_id: item for item in artifacts}
    relevant_rows: list[tuple[tuple[str, str, str], dict[str, Any]]] = []
    unexpected = []
    cross_project = []
    provenance_mismatches = []
    for project_root, rows in rows_by_project.items():
        project = Path(project_root)
        for row in rows:
            input_hash = _input_hash_from_row(row)
            row_project = str(row.get("project_root", ""))
            if row_project and Path(row_project).resolve() != project.resolve():
                cross_project.append(
                    {
                        "reason": "row project_root differs from containing project log",
                        "log_project": project_root,
                        "row_project": row_project,
                        "evaluation_id": row.get("evaluation_id"),
                    }
                )
            owner = global_input_projects.get(input_hash)
            if owner and Path(owner).resolve() != project.resolve():
                cross_project.append(
                    {
                        "reason": "another project's exact probe input appeared here",
                        "log_project": project_root,
                        "expected_project": owner,
                        "evaluation_id": row.get("evaluation_id"),
                    }
                )
            key = _row_key(row, project)
            if key in expected_set:
                relevant_rows.append((key, row))
                artifact = expected_artifacts.get(key[2])
                rule = row.get("rule") or {}
                if artifact is not None:
                    checks = {
                        "source_hash": artifact.source_sha256,
                        "behavior_hash": artifact.behavior_sha256,
                        "compiler": artifact.compiler,
                        "compiler_snapshot": artifact.compiler_snapshot,
                        "program_id": artifact.program_id,
                    }
                    differences = {
                        name: {"expected": wanted, "observed": str(rule.get(name, ""))}
                        for name, wanted in checks.items()
                        if str(rule.get(name, "")) != wanted
                    }
                    if differences:
                        provenance_mismatches.append(
                            {"key": _key_json(key), "differences": differences}
                        )
            elif float(row.get("timestamp", 0) or 0) >= started_wall_time:
                unexpected.append(
                    {
                        "project_root": project_root,
                        "input_sha256": input_hash,
                        "rule_id": str((row.get("rule") or {}).get("id", "")),
                        "evaluation_id": row.get("evaluation_id"),
                    }
                )
    counts = Counter(key for key, _row in relevant_rows)
    missing = [key for key in expected_keys if counts[key] == 0]
    duplicates = [
        {"key": _key_json(key), "count": count}
        for key, count in counts.items()
        if count > 1
    ]
    failed = []
    running = []
    result_counts: Counter[str] = Counter()
    for key, row in relevant_rows:
        status = str(row.get("status", ""))
        if status == "failed":
            failed.append(
                {
                    "key": _key_json(key),
                    "error_code": (row.get("outcome") or {}).get("error_code"),
                    "error": (row.get("outcome") or {}).get("error"),
                }
            )
        elif status != "completed":
            running.append({"key": _key_json(key), "status": status or "running"})
        result_counts[str(row.get("result", "")) or status or "unknown"] += 1
    return {
        "evaluations_expected": len(expected_keys),
        "evaluations_observed_for_expected_keys": len(relevant_rows),
        "expected_keys_observed": len(expected_keys) - len(missing),
        "loss_count": len(missing),
        "duplicate_count": sum(item["count"] - 1 for item in duplicates),
        "unexpected_count": len(unexpected),
        "cross_project_contamination_count": len(cross_project),
        "failed_count": len(failed),
        "running_count": len(running),
        "provenance_mismatch_count": len(provenance_mismatches),
        "result_counts": dict(sorted(result_counts.items())),
        "missing": [_key_json(key) for key in missing],
        "duplicates": duplicates,
        "unexpected": unexpected,
        "cross_project_contamination": cross_project,
        "failed": failed,
        "running": running,
        "provenance_mismatches": provenance_mismatches,
    }


def _terminal_keys(
    rows_by_project: dict[str, list[dict[str, Any]]],
    expected: Sequence[ExpectedEvaluation],
) -> set[tuple[str, str, str]]:
    expected_set = {item.key for item in expected}
    terminal = set()
    for project_root, rows in rows_by_project.items():
        project = Path(project_root)
        for row in rows:
            key = _row_key(row, project)
            if key in expected_set and str(row.get("status", "")) in (
                "completed",
                "failed",
            ):
                terminal.add(key)
    return terminal


def _wait_for_expected(
    projects: Sequence[InstalledProject],
    expected: Sequence[ExpectedEvaluation],
    event_started_ns: dict[str, int],
    timeout: float,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], dict[str, int]]:
    expected_by_input: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for item in expected:
        expected_by_input[item.input_sha256].add(item.key)
    first_visible: dict[str, int] = {}
    all_visible: dict[str, int] = {}
    deadline_ns = max(event_started_ns.values()) + int(timeout * 1_000_000_000)
    last_rows: dict[str, list[dict[str, Any]]] = {}
    while time.perf_counter_ns() < deadline_ns:
        last_rows = {
            str(project.root): _evaluation_history(project.root) for project in projects
        }
        observed_ns = time.perf_counter_ns()
        terminal = _terminal_keys(last_rows, expected)
        for input_hash, keys in expected_by_input.items():
            present = terminal.intersection(keys)
            if present and input_hash not in first_visible:
                first_visible[input_hash] = observed_ns
            if keys.issubset(terminal) and input_hash not in all_visible:
                all_visible[input_hash] = observed_ns
        if len(all_visible) == len(expected_by_input):
            # One settle interval catches duplicate evaluations admitted just
            # behind the first complete observation.
            time.sleep(QUERY_POLL_INTERVAL_SECONDS)
            last_rows = {
                str(project.root): _evaluation_history(project.root)
                for project in projects
            }
            return last_rows, first_visible, all_visible
        time.sleep(QUERY_POLL_INTERVAL_SECONDS)
    missing = sorted(set(expected_by_input) - set(all_visible))
    raise SystemsHarnessError(
        f"{len(missing)} events did not reach all expected evaluations in {timeout:.1f}s"
    )


def _process_tree_snapshot(pid: int) -> dict[str, Any]:
    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {
            "processes": 0,
            "rss_bytes": 0,
            "cpu_seconds": 0.0,
            "file_descriptors": None,
        }
    rss = 0
    cpu = 0.0
    descriptors = 0
    descriptor_supported = True
    alive = 0
    for process in processes:
        try:
            rss += int(process.memory_info().rss)
            times = process.cpu_times()
            cpu += float(times.user + times.system)
            if hasattr(process, "num_fds"):
                descriptors += int(process.num_fds())
            elif hasattr(process, "num_handles"):
                descriptors += int(process.num_handles())
            else:
                descriptor_supported = False
            alive += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except (NotImplementedError, AttributeError):
            descriptor_supported = False
    return {
        "processes": alive,
        "rss_bytes": rss,
        "cpu_seconds": round(cpu, 6),
        "file_descriptors": descriptors if descriptor_supported else None,
    }


class _ResourceSampler:
    def __init__(self, pid: int, interval: float = RESOURCE_SAMPLE_INTERVAL_SECONDS):
        self.pid = pid
        self.interval = interval
        self.samples: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._sample, name="rap-systems-resources", daemon=True
        )

    def _sample(self) -> None:
        while not self._stop.is_set():
            sample = _process_tree_snapshot(self.pid)
            if sample["processes"] == 0:
                return
            self.samples.append(sample)
            self._stop.wait(self.interval)

    def __enter__(self) -> "_ResourceSampler":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)


def _tree_size(path: Path) -> dict[str, int]:
    files = 0
    size = 0
    if not path.exists():
        return {"files": 0, "bytes": 0}
    for candidate in path.rglob("*"):
        try:
            if candidate.is_file() and not candidate.is_symlink():
                files += 1
                size += int(candidate.stat().st_size)
        except OSError:
            continue
    return {"files": files, "bytes": size}


def _storage_snapshot(fixture: RunningFixture) -> dict[str, Any]:
    state = _tree_size(fixture.isolated_root / "state")
    project_logs = {
        str(project.root): _tree_size(
            project.root / ".codex" / "rules-as-programs" / "log"
        )
        for project in fixture.projects
    }
    project_rap = {
        str(project.root): _tree_size(project.root / ".codex" / "rules-as-programs")
        for project in fixture.projects
    }
    return {
        "state": state,
        "project_logs": project_logs,
        "project_rap_trees": project_rap,
        "total_runtime_bytes": state["bytes"]
        + sum(item["bytes"] for item in project_logs.values()),
    }


def _storage_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    roots = sorted(set(before["project_logs"]) | set(after["project_logs"]))
    return {
        "state_bytes": after["state"]["bytes"] - before["state"]["bytes"],
        "project_log_bytes": {
            root: after["project_logs"].get(root, {}).get("bytes", 0)
            - before["project_logs"].get(root, {}).get("bytes", 0)
            for root in roots
        },
        "total_runtime_bytes": after["total_runtime_bytes"]
        - before["total_runtime_bytes"],
    }


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[rank - 1]


def _summary(values: list[float]) -> dict[str, Any]:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    return {
        "unit": "ms",
        "count": len(values),
        "minimum": round(min(values), 3),
        "mean": round(sum(values) / len(values), 3),
        "p50_nearest_rank": round(_nearest_rank(values, 50), 3),
        "p95_nearest_rank": round(_nearest_rank(values, 95), 3),
        "p99_nearest_rank": round(_nearest_rank(values, 99), 3),
        "maximum": round(max(values), 3),
    }


def _build_events(
    fixture: RunningFixture,
    condition_id: str,
    event_count: int,
    schedule: str = "round_robin_across_projects",
) -> list[tuple[InstalledProject, dict[str, Any], str, str]]:
    if schedule not in TRAFFIC_PATTERNS:
        raise ValueError(f"unsupported traffic schedule {schedule!r}")
    events = []
    for sequence in range(event_count):
        project = (
            fixture.projects[sequence % len(fixture.projects)]
            if schedule == "round_robin_across_projects"
            else fixture.projects[0]
        )
        probe = fixture.artifacts[sequence % len(fixture.artifacts)].probe_tool_input
        raw = _raw_event(
            project.root,
            project_index=project.index,
            sequence=sequence,
            condition_id=condition_id,
            tool_input=probe,
        )
        expected_input = _expected_input(raw)
        input_hash = _sha256_bytes(expected_input.encode("utf-8"))
        events.append((project, raw, expected_input, input_hash))
    hashes = [item[3] for item in events]
    if len(set(hashes)) != len(hashes):
        raise SystemsHarnessError("event generator did not create unique inputs")
    return events


def _expected_for_events(
    events: Sequence[tuple[InstalledProject, dict[str, Any], str, str]],
    artifacts: Sequence[RuleArtifact],
) -> list[ExpectedEvaluation]:
    return [
        ExpectedEvaluation(
            case_id=str((raw["tool_input"]["_rap_systems_probe"])["case_id"]),
            project_root=str(project.root),
            input_sha256=input_hash,
            rule_id=artifact.rule_id,
        )
        for project, raw, _expected_input_text, input_hash in events
        for artifact in artifacts
    ]


def _invoke_event_group(
    fixture: RunningFixture,
    events: Sequence[tuple[InstalledProject, dict[str, Any], str, str]],
    *,
    mode: str,
    timeout: float,
    max_workers: int,
) -> tuple[
    list[dict[str, Any]], list[ExpectedEvaluation], dict[str, list[dict[str, Any]]]
]:
    expected = _expected_for_events(events, fixture.artifacts)
    samples: list[dict[str, Any]] = []
    if mode == "sequential":
        for project, raw, _text, input_hash in events:
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            one_expected = [
                item for item in expected if item.input_sha256 == input_hash
            ]
            rows, first, complete = _wait_for_expected(
                fixture.projects,
                one_expected,
                {input_hash: hook["started_ns"]},
                timeout,
            )
            samples.append(
                {
                    "case_id": raw["tool_input"]["_rap_systems_probe"]["case_id"],
                    "project_root": str(project.root),
                    "input_sha256": input_hash,
                    "hook_exit_ms": round(
                        (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
                    ),
                    "event_to_first_query_visible_evaluation_ms": round(
                        (first[input_hash] - hook["started_ns"]) / 1_000_000, 3
                    ),
                    "event_to_all_query_visible_evaluations_ms": round(
                        (complete[input_hash] - hook["started_ns"]) / 1_000_000, 3
                    ),
                }
            )
        final_rows = {
            str(project.root): _evaluation_history(project.root)
            for project in fixture.projects
        }
        return samples, expected, final_rows
    if mode != "burst":
        raise ValueError(f"unsupported event-group mode {mode!r}")
    hooks: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(events)),
        thread_name_prefix="rap-systems-hooks",
    ) as executor:
        futures = {
            executor.submit(_invoke_raw, project.wrapper, raw, fixture.environment): (
                project,
                raw,
                input_hash,
            )
            for project, raw, _text, input_hash in events
        }
        for future in as_completed(futures):
            _project, _raw, input_hash = futures[future]
            hooks[input_hash] = future.result()
    rows, first, complete = _wait_for_expected(
        fixture.projects,
        expected,
        {input_hash: hook["started_ns"] for input_hash, hook in hooks.items()},
        timeout,
    )
    for project, raw, _text, input_hash in events:
        hook = hooks[input_hash]
        samples.append(
            {
                "case_id": raw["tool_input"]["_rap_systems_probe"]["case_id"],
                "project_root": str(project.root),
                "input_sha256": input_hash,
                "hook_exit_ms": round(
                    (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
                ),
                "event_to_first_query_visible_evaluation_ms": round(
                    (first[input_hash] - hook["started_ns"]) / 1_000_000, 3
                ),
                "event_to_all_query_visible_evaluations_ms": round(
                    (complete[input_hash] - hook["started_ns"]) / 1_000_000, 3
                ),
            }
        )
    samples.sort(key=lambda item: item["case_id"])
    return samples, expected, rows


def _warm_fixture(
    fixture: RunningFixture, warmups_per_project: int, timeout: float
) -> None:
    for project in fixture.projects:
        for warmup in range(warmups_per_project):
            probe = fixture.artifacts[warmup % len(fixture.artifacts)].probe_tool_input
            raw = _raw_event(
                project.root,
                project_index=project.index,
                sequence=warmup,
                condition_id=f"warmup-{project.index}",
                tool_input=probe,
            )
            expected_input = _expected_input(raw)
            input_hash = _sha256_bytes(expected_input.encode("utf-8"))
            started_wall_time = time.time()
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            expected = [
                ExpectedEvaluation(
                    case_id=f"warmup-{project.index}-{warmup}",
                    project_root=str(project.root),
                    input_sha256=input_hash,
                    rule_id=artifact.rule_id,
                )
                for artifact in fixture.artifacts
            ]
            rows, _first, _complete = _wait_for_expected(
                fixture.projects,
                expected,
                {input_hash: hook["started_ns"]},
                timeout,
            )
            accounting = account_evaluations(
                rows,
                expected,
                fixture.artifacts,
                started_wall_time=started_wall_time,
            )
            _assert_clean_accounting(accounting, "warmup")


def _assert_clean_accounting(accounting: dict[str, Any], label: str) -> None:
    keys = (
        "loss_count",
        "duplicate_count",
        "unexpected_count",
        "cross_project_contamination_count",
        "failed_count",
        "running_count",
        "provenance_mismatch_count",
    )
    failures = {key: accounting.get(key) for key in keys if accounting.get(key)}
    if failures:
        raise SystemsHarnessError(
            f"{label} exact evaluation accounting failed: {failures}"
        )


def run_condition(
    artifacts: Sequence[RuleArtifact],
    *,
    rule_count: int,
    project_count: int,
    mode: str,
    event_count: int,
    repeat: int,
    warmups_per_project: int,
    timeout: float,
    max_hook_workers: int,
    schedule: str = "round_robin_across_projects",
    strict: bool = True,
) -> dict[str, Any]:
    selected = tuple(artifacts[:rule_count])
    if len(selected) != rule_count:
        raise ValueError("not enough rule artifacts for requested condition")
    condition_id = (
        f"r{rule_count}-p{project_count}-{schedule}-{mode}{event_count}-rep{repeat}"
    )
    with _running_fixture(selected, project_count) as fixture:
        _warm_fixture(fixture, warmups_per_project, timeout)
        resources_before = _process_tree_snapshot(fixture.daemon.pid)
        storage_before = _storage_snapshot(fixture)
        started_wall_time = time.time()
        events = _build_events(
            fixture, condition_id, event_count, schedule=schedule
        )
        workload_started_ns = time.perf_counter_ns()
        with _ResourceSampler(fixture.daemon.pid) as sampler:
            samples, expected, rows = _invoke_event_group(
                fixture,
                events,
                mode=mode,
                timeout=timeout,
                max_workers=max_hook_workers,
            )
        workload_finished_ns = time.perf_counter_ns()
        accounting = account_evaluations(
            rows,
            expected,
            selected,
            started_wall_time=started_wall_time,
        )
        if strict:
            _assert_clean_accounting(accounting, condition_id)
        resources_after = _process_tree_snapshot(fixture.daemon.pid)
        storage_after = _storage_snapshot(fixture)
        all_resource_samples = [resources_before, *sampler.samples, resources_after]
        fd_values = [
            int(item["file_descriptors"])
            for item in all_resource_samples
            if item.get("file_descriptors") is not None
        ]
        hook_latencies = [float(item["hook_exit_ms"]) for item in samples]
        first_latencies = [
            float(item["event_to_first_query_visible_evaluation_ms"])
            for item in samples
        ]
        complete_latencies = [
            float(item["event_to_all_query_visible_evaluations_ms"]) for item in samples
        ]
        complete_by_project: dict[str, list[float]] = defaultdict(list)
        for item in samples:
            complete_by_project[str(item["project_root"])].append(
                float(item["event_to_all_query_visible_evaluations_ms"])
            )
        project_p95 = {
            project: round(_nearest_rank(values, 95), 3)
            for project, values in sorted(complete_by_project.items())
        }
        wall_seconds = (workload_finished_ns - workload_started_ns) / 1_000_000_000
        return {
            "condition_id": condition_id,
            "rule_count": rule_count,
            "project_count": project_count,
            "mode": mode,
            "event_count": event_count,
            "repeat": repeat,
            "fresh_daemon": True,
            "fresh_state": True,
            "schedule": schedule,
            "rule_ids": [artifact.rule_id for artifact in selected],
            "daemon_identity": fixture.identity,
            "wall_seconds": round(wall_seconds, 3),
            "event_throughput_per_second": round(event_count / wall_seconds, 3),
            "evaluation_throughput_per_second": round(
                (event_count * rule_count) / wall_seconds, 3
            ),
            "hook_process_exit": _summary(hook_latencies),
            "event_to_first_query_visible_evaluation": _summary(first_latencies),
            "event_to_all_query_visible_evaluations": _summary(complete_latencies),
            "per_project_event_to_all_p95_ms": project_p95,
            "per_project_p95_fairness_range_ms": (
                round(max(project_p95.values()) - min(project_p95.values()), 3)
                if project_p95
                else 0.0
            ),
            "accounting": accounting,
            "resources": {
                "scope": "daemon plus recursive child processes",
                "before": resources_before,
                "after": resources_after,
                "cpu_seconds_delta": round(
                    max(
                        0.0,
                        float(resources_after["cpu_seconds"])
                        - float(resources_before["cpu_seconds"]),
                    ),
                    6,
                ),
                "peak_sampled_rss_bytes": max(
                    int(item["rss_bytes"]) for item in all_resource_samples
                ),
                "peak_sampled_file_descriptors": max(fd_values) if fd_values else None,
                "sampling_interval_ms": int(RESOURCE_SAMPLE_INTERVAL_SECONDS * 1000),
                "sample_count": len(sampler.samples),
            },
            "storage": {
                "scope": (
                    "isolated RAP_STATE_DIR plus each synthetic project's RAP log tree; "
                    "installed sources/hooks are reported separately"
                ),
                "before": storage_before,
                "after": storage_after,
                "delta": _storage_delta(storage_before, storage_after),
            },
            "samples": samples,
        }


def run_soak(
    artifacts: Sequence[RuleArtifact],
    *,
    rule_count: int,
    project_count: int,
    event_count: int,
    batch_size: int,
    warmups_per_project: int,
    timeout: float,
    max_hook_workers: int,
    strict: bool = True,
) -> dict[str, Any]:
    selected = tuple(artifacts[:rule_count])
    if batch_size * rule_count >= EVALUATION_HISTORY_LIMIT:
        raise ValueError("soak batch is too large for exact online accounting")
    with _running_fixture(selected, project_count) as fixture:
        _warm_fixture(fixture, warmups_per_project, timeout)
        resources_before = _process_tree_snapshot(fixture.daemon.pid)
        storage_before = _storage_snapshot(fixture)
        batches = []
        total_accounting: Counter[str] = Counter()
        all_hook: list[float] = []
        all_complete: list[float] = []
        started_ns = time.perf_counter_ns()
        with _ResourceSampler(fixture.daemon.pid) as sampler:
            offset = 0
            while offset < event_count:
                size = min(batch_size, event_count - offset)
                condition_id = f"soak-r{rule_count}-p{project_count}-offset{offset}"
                events = _build_events(fixture, condition_id, size)
                batch_wall = time.time()
                samples, expected, rows = _invoke_event_group(
                    fixture,
                    events,
                    mode="burst",
                    timeout=timeout,
                    max_workers=max_hook_workers,
                )
                accounting = account_evaluations(
                    rows, expected, selected, started_wall_time=batch_wall
                )
                if strict:
                    _assert_clean_accounting(accounting, condition_id)
                for name in (
                    "evaluations_expected",
                    "evaluations_observed_for_expected_keys",
                    "loss_count",
                    "duplicate_count",
                    "unexpected_count",
                    "cross_project_contamination_count",
                    "failed_count",
                    "running_count",
                    "provenance_mismatch_count",
                ):
                    total_accounting[name] += int(accounting.get(name, 0))
                all_hook.extend(float(item["hook_exit_ms"]) for item in samples)
                all_complete.extend(
                    float(item["event_to_all_query_visible_evaluations_ms"])
                    for item in samples
                )
                batches.append(
                    {
                        "offset": offset,
                        "events": size,
                        "accounting": accounting,
                    }
                )
                offset += size
        finished_ns = time.perf_counter_ns()
        resources_after = _process_tree_snapshot(fixture.daemon.pid)
        storage_after = _storage_snapshot(fixture)
        samples = [resources_before, *sampler.samples, resources_after]
        return {
            "rule_count": rule_count,
            "project_count": project_count,
            "events": event_count,
            "batch_size": batch_size,
            "fresh_daemon": True,
            "wall_seconds": round((finished_ns - started_ns) / 1_000_000_000, 3),
            "hook_process_exit": _summary(all_hook),
            "event_to_all_query_visible_evaluations": _summary(all_complete),
            "accounting_totals": dict(total_accounting),
            "resources": {
                "before": resources_before,
                "after": resources_after,
                "peak_sampled_rss_bytes": max(
                    int(item["rss_bytes"]) for item in samples
                ),
                "rss_change_bytes": int(resources_after["rss_bytes"])
                - int(resources_before["rss_bytes"]),
                "cpu_seconds_delta": round(
                    max(
                        0.0,
                        float(resources_after["cpu_seconds"])
                        - float(resources_before["cpu_seconds"]),
                    ),
                    6,
                ),
            },
            "storage": {
                "before": storage_before,
                "after": storage_after,
                "delta": _storage_delta(storage_before, storage_after),
            },
            "batches": batches,
        }


def _network_blocker(root: Path) -> tuple[Path, Path]:
    blocker = root / "offline-python"
    blocker.mkdir()
    log_path = root / "blocked-network.jsonl"
    source = """import json
import os
import socket
import time

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_create_connection = socket.create_connection

def _blocked(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        path = os.environ.get("RAP_OFFLINE_BLOCK_LOG", "")
        if path:
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps({
                        "pid": os.getpid(), "time": time.time(),
                        "family": int(sock.family), "address": repr(address),
                    }) + "\\n")
            except OSError:
                pass
        raise OSError("RAP systems offline probe blocked an Internet socket")

def _connect(sock, address):
    _blocked(sock, address)
    return _real_connect(sock, address)

def _connect_ex(sock, address):
    _blocked(sock, address)
    return _real_connect_ex(sock, address)

def _create_connection(address, *args, **kwargs):
    raise OSError("RAP systems offline probe blocked socket.create_connection")

socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex
socket.create_connection = _create_connection
"""
    (blocker / "sitecustomize.py").write_text(source, encoding="utf-8")
    return blocker, log_path


def run_offline_after_prepare(
    artifacts: Sequence[RuleArtifact],
    *,
    rule_count: int,
    timeout: float,
) -> dict[str, Any]:
    selected = tuple(artifacts[:rule_count])
    with tempfile.TemporaryDirectory(prefix="rap-offline-", dir="/tmp") as temporary:
        isolated_root = Path(temporary)
        with integrated._isolated_environment(isolated_root) as base_environment:
            base_environment = _subprocess_environment(base_environment)
            projects = _install_projects(isolated_root, selected, 1)
            diagnostics = isolated_root / "daemon-output.log"
            online, online_identity = integrated._start_daemon(
                base_environment, diagnostics, timeout
            )
            fixture = RunningFixture(
                isolated_root,
                dict(base_environment),
                projects,
                selected,
                diagnostics,
                online,
                online_identity,
            )
            try:
                _warm_fixture(fixture, 1, timeout)
            finally:
                integrated._stop_daemon(online)
            blocker, block_log = _network_blocker(isolated_root)
            offline_environment = dict(base_environment)
            offline_environment.update(
                {
                    "PYTHONPATH": str(blocker)
                    + os.pathsep
                    + offline_environment.get("PYTHONPATH", ""),
                    "RAP_OFFLINE_BLOCK_LOG": str(block_log),
                    "HF_HUB_OFFLINE": "1",
                    "TRANSFORMERS_OFFLINE": "1",
                }
            )
            offline, offline_identity = integrated._start_daemon(
                offline_environment, diagnostics, timeout
            )
            offline_fixture = RunningFixture(
                isolated_root,
                offline_environment,
                projects,
                selected,
                diagnostics,
                offline,
                offline_identity,
            )
            try:
                started_wall = time.time()
                events = _build_events(offline_fixture, "offline-after-prepare", 1)
                samples, expected, rows = _invoke_event_group(
                    offline_fixture,
                    events,
                    mode="sequential",
                    timeout=timeout,
                    max_workers=1,
                )
                accounting = account_evaluations(
                    rows, expected, selected, started_wall_time=started_wall
                )
                _assert_clean_accounting(accounting, "offline-after-prepare")
                blocked_attempts = _jsonl(block_log) if block_log.exists() else []
                return {
                    "prepared_online": True,
                    "fresh_offline_daemon": True,
                    "rule_count": rule_count,
                    "online_daemon_identity": online_identity,
                    "offline_daemon_identity": offline_identity,
                    "network_control": (
                        "Python AF_INET/AF_INET6 connect paths blocked via sitecustomize; "
                        "common model-hub offline flags also set"
                    ),
                    "blocked_internet_attempts": len(blocked_attempts),
                    "blocked_attempt_records": blocked_attempts,
                    "accounting": accounting,
                    "sample": samples[0],
                    "limitation": (
                        "This is process-level Python socket blocking, not an OS network "
                        "namespace; native libraries that bypass Python sockets are outside "
                        "the injected boundary."
                    ),
                }
            finally:
                integrated._stop_daemon(offline)


def _wait_for_any_daemon(timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        details = ipc.ping_details(timeout=0.25)
        if details:
            return details
        time.sleep(0.05)
    raise SystemsHarnessError("auto-respawned daemon did not become ready")


def _single_event(
    fixture: RunningFixture,
    condition_id: str,
    *,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started_wall = time.time()
    events = _build_events(fixture, condition_id, 1)
    samples, expected, rows = _invoke_event_group(
        fixture,
        events,
        mode="sequential",
        timeout=timeout,
        max_workers=1,
    )
    accounting = account_evaluations(
        rows, expected, fixture.artifacts, started_wall_time=started_wall
    )
    return samples[0], accounting


def _fault_daemon_crash(artifact: RuleArtifact, timeout: float) -> dict[str, Any]:
    with _running_fixture((artifact,), 1) as fixture:
        _warm_fixture(fixture, 1, timeout)
        old_pid = fixture.daemon.pid
        os.killpg(old_pid, signal.SIGKILL)
        fixture.daemon.wait(timeout=3.0)
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="daemon-crash-lost-event",
            tool_input=artifact.probe_tool_input,
        )
        expected_input = _expected_input(raw)
        expected_hash = _sha256_bytes(expected_input.encode("utf-8"))
        hook = _invoke_raw(project.wrapper, raw, fixture.environment)
        respawned = _wait_for_any_daemon(timeout)
        time.sleep(0.2)
        lost_rows = [
            row
            for row in _evaluation_history(project.root)
            if _input_hash_from_row(row) == expected_hash
        ]
        recovery_fixture = RunningFixture(
            fixture.isolated_root,
            fixture.environment,
            fixture.projects,
            fixture.artifacts,
            fixture.diagnostics,
            fixture.daemon,
            respawned,
        )
        recovery_sample, recovery_accounting = _single_event(
            recovery_fixture, "daemon-crash-recovery", timeout=timeout
        )
        _assert_clean_accounting(recovery_accounting, "daemon crash recovery")
        return {
            "old_pid": old_pid,
            "new_pid": int(respawned.get("pid", -1)),
            "faulting_hook_exit_ms": round(
                (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
            ),
            "faulting_hook_contract_preserved": True,
            "faulting_event_evaluations": len(lost_rows),
            "faulting_event_expected_loss": len(lost_rows) == 0,
            "interpretation": (
                "An event that cannot reach the daemon is not queued for replay; the "
                "hook fails open and starts a replacement daemon."
            ),
            "recovery": {
                "sample": recovery_sample,
                "accounting": recovery_accounting,
            },
        }


def _fault_worker_exit(artifact: RuleArtifact, timeout: float) -> dict[str, Any]:
    with _running_fixture((artifact,), 1) as fixture:
        _warm_fixture(fixture, 1, timeout)
        killed = integrated._kill_inference_worker(fixture.daemon.pid)
        sample, accounting = _single_event(
            fixture, "worker-exit-recovery", timeout=timeout
        )
        _assert_clean_accounting(accounting, "worker exit recovery")
        new_pids = [
            pid
            for _rss, process in integrated._inference_workers(fixture.daemon.pid)
            if (pid := process.pid)
        ]
        return {
            **killed,
            "new_worker_pids": new_pids,
            "worker_replaced": killed["old_worker_pid"] not in new_pids
            and bool(new_pids),
            "recovery": {"sample": sample, "accounting": accounting},
        }


def _wait_for_conversation(
    project: Path,
    conversation_id: str,
    timeout: float,
    *,
    require_terminal: bool,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = next(
            (
                row
                for row in _evaluation_history(project)
                if str(row.get("conversation_id", "")) == conversation_id
            ),
            None,
        )
        if last is not None and (
            not require_terminal
            or str(last.get("status", "")) in ("completed", "failed")
        ):
            return last
        time.sleep(QUERY_POLL_INTERVAL_SECONDS)
    return last


def _fault_worker_timeout(artifact: RuleArtifact, timeout: float) -> dict[str, Any]:
    with _running_fixture((artifact,), 1) as fixture:
        _warm_fixture(fixture, 1, timeout)
        candidates = integrated._inference_workers(fixture.daemon.pid)
        if not candidates:
            raise SystemsHarnessError("could not identify worker for timeout probe")
        _rss, worker = max(candidates, key=lambda item: item[0])
        old_pid = worker.pid
        worker.send_signal(signal.SIGSTOP)
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="worker-timeout",
            tool_input=artifact.probe_tool_input,
        )
        started = time.perf_counter_ns()
        try:
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            row = _wait_for_conversation(
                project.root,
                str(raw["session_id"]),
                max(timeout, 12.0),
                require_terminal=True,
            )
        finally:
            try:
                if worker.is_running():
                    worker.send_signal(signal.SIGCONT)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if row is None or str(row.get("status", "")) != "failed":
            raise SystemsHarnessError(
                "paused worker did not produce a failed timeout outcome"
            )
        recovery_sample, recovery_accounting = _single_event(
            fixture, "worker-timeout-recovery", timeout=max(timeout, 12.0)
        )
        _assert_clean_accounting(recovery_accounting, "worker timeout recovery")
        new_pids = [
            process.pid
            for _rss, process in integrated._inference_workers(fixture.daemon.pid)
        ]
        return {
            "old_worker_pid": old_pid,
            "faulting_hook_exit_ms": round(
                (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
            ),
            "time_to_failed_outcome_ms": round(
                (time.perf_counter_ns() - started) / 1_000_000, 3
            ),
            "failed_outcome": {
                "status": row.get("status"),
                "error_code": (row.get("outcome") or {}).get("error_code"),
                "error": (row.get("outcome") or {}).get("error"),
            },
            "new_worker_pids": new_pids,
            "worker_replaced": old_pid not in new_pids and bool(new_pids),
            "recovery": {
                "sample": recovery_sample,
                "accounting": recovery_accounting,
            },
        }


def _fault_sqlite_lock(timeout: float) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1) as fixture:
        _warm_fixture(fixture, 1, timeout)
        database = rap_config.db_path()
        lock = sqlite3.connect(str(database), timeout=1.0, isolation_level=None)
        lock.execute("BEGIN EXCLUSIVE")
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="sqlite-lock",
            tool_input=artifact.probe_tool_input,
        )
        try:
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            time.sleep(SQLITE_BUSY_TIMEOUT_SECONDS + 1.0)
        finally:
            lock.execute("ROLLBACK")
            lock.close()
        row = _wait_for_conversation(
            project.root, str(raw["session_id"]), 1.0, require_terminal=False
        )
        snapshot = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
        recovery_sample, recovery_accounting = _single_event(
            fixture, "sqlite-lock-recovery", timeout=timeout
        )
        _assert_clean_accounting(recovery_accounting, "SQLite lock recovery")
        return {
            "lock_mode": "BEGIN EXCLUSIVE",
            "held_seconds": SQLITE_BUSY_TIMEOUT_SECONDS + 1.0,
            "production_sqlite_timeout_seconds": SQLITE_BUSY_TIMEOUT_SECONDS,
            "faulting_hook_exit_ms": round(
                (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
            ),
            "faulting_hook_contract_preserved": True,
            "faulting_evaluation_status": (row or {}).get("status", "missing"),
            "faulting_evaluation_outcome": (row or {}).get("outcome", {}),
            "health_issues": list(snapshot.get("health_issues") or []),
            "recovery": {"sample": recovery_sample, "accounting": recovery_accounting},
        }


def _fault_malformed_payload(timeout: float) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1) as fixture:
        project = fixture.projects[0]
        before = len(_evaluation_history(project.root))
        malformed = _invoke_payload(
            project.wrapper, project.root, "{not-json", fixture.environment
        )
        time.sleep(0.2)
        after = len(_evaluation_history(project.root))
        oversized = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="oversized-payload",
            tool_input={"command": "x" * 2048},
        )
        oversized_hook = _invoke_raw(project.wrapper, oversized, fixture.environment)
        oversized_row = _wait_for_conversation(
            project.root,
            str(oversized["session_id"]),
            timeout,
            require_terminal=True,
        )
        if oversized_row is None:
            raise SystemsHarnessError(
                "oversized input did not reach evaluation history"
            )
        recovery_sample, recovery_accounting = _single_event(
            fixture, "malformed-recovery", timeout=timeout
        )
        _assert_clean_accounting(recovery_accounting, "malformed payload recovery")
        return {
            "invalid_json": {
                "hook_exit_ms": round(
                    (malformed["exited_ns"] - malformed["started_ns"]) / 1_000_000,
                    3,
                ),
                "hook_contract_preserved": True,
                "evaluation_history_delta": after - before,
            },
            "oversized_trigger_field": {
                "bytes": 2048,
                "rule_max_input_bytes": 1024,
                "hook_exit_ms": round(
                    (oversized_hook["exited_ns"] - oversized_hook["started_ns"])
                    / 1_000_000,
                    3,
                ),
                "status": oversized_row.get("status"),
                "error_code": (oversized_row.get("outcome") or {}).get("error_code"),
            },
            "recovery": {"sample": recovery_sample, "accounting": recovery_accounting},
        }


def _fault_duplicate_delivery(timeout: float) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1) as fixture:
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="duplicate-delivery",
            tool_input=artifact.probe_tool_input,
        )
        expected_input = _expected_input(raw)
        input_hash = _sha256_bytes(expected_input.encode("utf-8"))
        before = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
        with ThreadPoolExecutor(max_workers=2) as executor:
            hooks = list(
                executor.map(
                    lambda _index: _invoke_raw(
                        project.wrapper, raw, fixture.environment
                    ),
                    range(2),
                )
            )
        expected = [
            ExpectedEvaluation(
                case_id="duplicate-delivery",
                project_root=str(project.root),
                input_sha256=input_hash,
                rule_id=artifact.rule_id,
            )
        ]
        rows, _first, _complete = _wait_for_expected(
            fixture.projects,
            expected,
            {input_hash: min(item["started_ns"] for item in hooks)},
            timeout,
        )
        relevant = [
            row
            for row in rows[str(project.root)]
            if _input_hash_from_row(row) == input_hash
            and str((row.get("rule") or {}).get("id", "")) == artifact.rule_id
        ]
        findings = integrated._query_findings(project.root)
        finding_count = sum(
            1
            for finding in findings
            if str(
                ((finding.get("evaluation") or {}).get("input") or {}).get("sha256", "")
            )
            == input_hash
        )
        after = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
        before_count = int(((before.get("daemon") or {}).get("ingress_duplicates", 0)))
        after_count = int(((after.get("daemon") or {}).get("ingress_duplicates", 0)))
        return {
            "deliveries": 2,
            "hook_contracts_preserved": len(hooks) == 2,
            "evaluations": len(relevant),
            "findings": finding_count,
            "ingress_duplicate_counter_delta": after_count - before_count,
            "exactly_once_within_live_daemon_window": (
                len(relevant) == 1
                and finding_count == 1
                and after_count - before_count == 1
            ),
            "scope": (
                "byte-identical concurrent redelivery while one daemon and its "
                "short-window admission cache remain live"
            ),
        }


def _seed_compiler_catalog() -> None:
    rap_config.compiler_catalog_path().write_text(
        json.dumps(
            {
                "fetched_at": time.time(),
                "compilers": [
                    {
                        "name": "",
                        "description": "synthetic cached default",
                        "default": True,
                        "supports_local_sdk": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _fault_deployment_failure(timeout: float) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1) as fixture:
        _seed_compiler_catalog()
        project = fixture.projects[0]
        prepared = ipc.send_request(
            {
                "type": "prepare_deployment",
                "rule_id": artifact.rule_id,
                "project_root": str(project.root),
                "source": artifact.source,
                "source_changed": False,
                "expected_active_hash": artifact.source_sha256,
                "coverage": {
                    "mode": "selected",
                    "selected_projects": [str(project.root)],
                },
            },
            timeout=5.0,
        )
        if not prepared or not prepared.get("ok"):
            raise SystemsHarnessError(
                f"deployment prepare failed unexpectedly: {prepared}"
            )
        changed_source = artifact.source.replace(
            'name="Synthetic systems fault probe"',
            'name="Changed after prepare"',
        )
        saved = rules_api.save_rule(
            artifact.rule_id, changed_source, "project", str(project.root)
        )
        if not saved.get("ok"):
            raise SystemsHarnessError(f"could not change prepared draft: {saved}")
        committed = ipc.send_request(
            {"type": "commit_deployment", "token": str(prepared["token"])},
            timeout=5.0,
        )
        if committed and committed.get("ok"):
            raise SystemsHarnessError("stale deployment token unexpectedly committed")
        sample, accounting = _single_event(
            fixture, "deployment-failure-active-revision", timeout=timeout
        )
        _assert_clean_accounting(accounting, "deployment failure active revision")
        return {
            "prepare_ok": True,
            "working_source_changed_after_prepare": True,
            "commit_ok": bool((committed or {}).get("ok")),
            "commit_error": str((committed or {}).get("error", "")),
            "previous_active_source_sha256": artifact.source_sha256,
            "post_failure_accounting": accounting,
            "post_failure_sample": sample,
            "previous_active_revision_remained_effective": (
                accounting["provenance_mismatch_count"] == 0
                and accounting["failed_count"] == 0
            ),
        }


def run_fault_suite(
    external_artifacts: Sequence[RuleArtifact],
    fault_names: Sequence[str],
    *,
    timeout: float,
    repetitions: int = DEFAULT_FAULT_REPETITIONS,
    strict: bool = True,
) -> dict[str, Any]:
    if repetitions < 1:
        raise ValueError("fault repetitions must be positive")
    unknown = sorted(set(fault_names) - set(FAULT_CAPABILITIES))
    if unknown:
        raise ValueError(f"unknown fault probes: {unknown}")
    external = external_artifacts[0]
    runners = {
        "daemon_crash": lambda: _fault_daemon_crash(external, timeout),
        "worker_exit": lambda: _fault_worker_exit(external, timeout),
        "worker_timeout": lambda: _fault_worker_timeout(external, timeout),
        "sqlite_lock": lambda: _fault_sqlite_lock(timeout),
        "malformed_payload": lambda: _fault_malformed_payload(timeout),
        "duplicate_delivery": lambda: _fault_duplicate_delivery(timeout),
        "deployment_failure": lambda: _fault_deployment_failure(timeout),
    }
    results = {}
    for name in fault_names:
        capability = FAULT_CAPABILITIES[name]
        if not capability.get("feasible"):
            results[name] = {"status": "not_run", **capability}
            continue
        attempts = []
        for repetition in range(repetitions):
            try:
                attempts.append(
                    {
                        "repetition": repetition,
                        "status": "completed",
                        "result": runners[name](),
                    }
                )
            except Exception as exc:
                attempts.append(
                    {
                        "repetition": repetition,
                        "status": "error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                if strict:
                    raise SystemsHarnessError(
                        f"fault probe {name} repetition {repetition} failed: {exc}"
                    ) from exc
        results[name] = {
            "status": (
                "completed"
                if all(item["status"] == "completed" for item in attempts)
                else "completed_with_errors"
            ),
            "capability": capability,
            "repetitions_planned": repetitions,
            "repetitions_completed": sum(
                item["status"] == "completed" for item in attempts
            ),
            "attempts": attempts,
        }
    for name, capability in FAULT_CAPABILITIES.items():
        if name not in results and not capability.get("feasible"):
            results[name] = {"status": "not_run", **capability}
    return results


def _measurement_boundary() -> dict[str, Any]:
    return {
        "hook_start": "parent immediately before exact installed wrapper process launch",
        "hook_end": "parent immediately after the installed wrapper exits",
        "evaluation_start": (
            "same parent timestamp immediately before installed wrapper process launch"
        ),
        "evaluation_first_end": (
            "first successful daemon Evaluation History query containing any terminal "
            "expected rule evaluation for the exact input"
        ),
        "evaluation_all_end": (
            "first successful daemon Evaluation History query containing every terminal "
            "expected (project, exact input hash, rule ID) tuple"
        ),
        "included": [
            "installed project hook wrapper",
            "Codex adapter normalization",
            "Unix-socket request and acknowledgement",
            "daemon ingress and ledger append",
            "production per-project rule loading and trigger matching",
            "serialized local PAW inference in the supervised subprocess",
            "all-outcome evaluation journal persistence",
            "finding SQLite persistence when a rule returns a finding",
            "daemon Evaluation History query and polling",
        ],
        "excluded": [
            "Codex scheduling of its asynchronous hook",
            "rendering or human perception of the menu-bar UI",
            "remote PAW compilation because public program IDs are already frozen",
        ],
        "interpretation": (
            "installed-path, query-visible all-evaluation latency; not Codex turn or UI latency"
        ),
        "query_poll_interval_ms": int(QUERY_POLL_INTERVAL_SECONDS * 1000),
    }


def run_study(
    bundle: ArtifactBundle,
    config: MatrixConfig,
    *,
    fault_names: Sequence[str],
    run_offline_probe: bool,
    strict: bool,
    formal: bool = False,
) -> dict[str, Any]:
    config.validate(len(bundle.artifacts))
    plan = build_matrix_plan(config)
    matrix = []
    for item in plan:
        matrix.append(
            run_condition(
                bundle.artifacts,
                rule_count=int(item["rule_count"]),
                project_count=int(item["project_count"]),
                mode=str(item["mode"]),
                event_count=int(item["events"]),
                repeat=int(item["repeat"]),
                warmups_per_project=config.warmups_per_project,
                timeout=config.timeout_seconds,
                max_hook_workers=config.max_hook_workers,
                schedule=str(item["schedule"]),
                strict=strict,
            )
        )
    soak = None
    if config.soak_events:
        soak = run_soak(
            bundle.artifacts,
            rule_count=config.soak_rule_count,
            project_count=config.soak_project_count,
            event_count=config.soak_events,
            batch_size=config.soak_batch_size,
            warmups_per_project=config.warmups_per_project,
            timeout=config.timeout_seconds,
            max_hook_workers=config.max_hook_workers,
            strict=strict,
        )
    offline = (
        run_offline_after_prepare(
            bundle.artifacts,
            rule_count=max(config.rule_counts),
            timeout=config.timeout_seconds,
        )
        if run_offline_probe
        else None
    )
    faults = run_fault_suite(
        bundle.artifacts,
        fault_names,
        timeout=config.timeout_seconds,
        repetitions=config.fault_repetitions,
        strict=strict,
    )
    return {
        "schema_version": 1,
        "status": (
            "formal_protocol_v3_amendment_004"
            if formal
            else "candidate_noncanonical"
        ),
        "study_mode": "formal" if formal else "candidate_noncanonical",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measurement_boundary": _measurement_boundary(),
        "config": asdict(config),
        "plan": plan,
        "artifact_provenance": bundle.provenance,
        "protocol_amendment": (
            {
                "path": str(FORMAL_AMENDMENT.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(FORMAL_AMENDMENT),
            }
            if formal
            else None
        ),
        "rules": [
            {
                key: value
                for key, value in asdict(artifact).items()
                if key not in ("source", "probe_tool_input")
            }
            for artifact in bundle.artifacts
        ],
        "matrix": matrix,
        "soak": soak,
        "offline_after_prepare": offline,
        "faults": faults,
        "fault_capabilities": FAULT_CAPABILITIES,
        "machine": {
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
            "python": sys.version,
            "cpu_count_logical": os.cpu_count(),
        },
        "packages": {
            "rules-as-programs": integrated._package_version("rules-as-programs"),
            "programasweights": integrated._package_version("programasweights"),
            "llama-cpp-python": integrated._package_version("llama-cpp-python"),
            "psutil": integrated._package_version("psutil"),
        },
        "git": integrated._git_state(),
        "slurm": {
            "job_id": os.environ.get("SLURM_JOB_ID", ""),
            "partition": os.environ.get("SLURM_JOB_PARTITION", ""),
            "node_list": os.environ.get("SLURM_JOB_NODELIST", ""),
        },
        "runner": {
            "path": str(Path(__file__).resolve().relative_to(REPO_ROOT)),
            "sha256": _sha256_file(Path(__file__).resolve()),
        },
    }


def _validate_output_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(FROZEN_OUTPUT_DIR)
    except ValueError:
        return resolved
    raise SystemsHarnessError(
        "this candidate harness cannot write into outputs/frozen; amend the protocol first"
    )


def _validate_formal_config(
    config: MatrixConfig,
    *,
    fault_names: Sequence[str],
    run_offline_probe: bool,
    strict: bool,
    require_partition: bool,
) -> None:
    if _sha256_file(FORMAL_AMENDMENT) != FORMAL_AMENDMENT_SHA256:
        raise SystemsHarnessError("protocol-v3 amendment 004 bytes changed")
    expected = {
        "rule_counts": DEFAULT_RULE_COUNTS,
        "project_counts": DEFAULT_PROJECT_COUNTS,
        "burst_sizes": DEFAULT_BURST_SIZES,
        "repeats": DEFAULT_REPEATS,
        "sequential_events": DEFAULT_SEQUENTIAL_EVENTS,
        "soak_events": DEFAULT_SOAK_EVENTS,
        "soak_rule_count": 8,
        "soak_project_count": 8,
        "fault_repetitions": DEFAULT_FAULT_REPETITIONS,
    }
    observed = asdict(config)
    mismatches = {
        name: {"expected": value, "observed": observed[name]}
        for name, value in expected.items()
        if observed[name] != value
    }
    feasible_faults = tuple(
        name for name, value in FAULT_CAPABILITIES.items() if value["feasible"]
    )
    if tuple(fault_names) != feasible_faults:
        mismatches["fault_names"] = {
            "expected": feasible_faults,
            "observed": tuple(fault_names),
        }
    if not run_offline_probe:
        mismatches["offline_probe"] = {"expected": True, "observed": False}
    if not strict:
        mismatches["strict"] = {"expected": True, "observed": False}
    if mismatches:
        raise SystemsHarnessError(
            "formal configuration differs from protocol v3: "
            + json.dumps(mismatches, sort_keys=True)
        )
    if require_partition and os.environ.get("SLURM_JOB_PARTITION", "") != "ALL":
        raise SystemsHarnessError(
            "formal watgpu execution requires SLURM_JOB_PARTITION='ALL'"
        )


def _fault_names(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "none":
        return ()
    if value.strip().lower() == "all":
        return tuple(
            name
            for name, capability in FAULT_CAPABILITIES.items()
            if capability["feasible"]
        )
    names = tuple(item.strip() for item in value.split(",") if item.strip())
    unknown = sorted(set(names) - set(FAULT_CAPABILITIES))
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown fault names: {','.join(unknown)}")
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rule-counts",
        type=lambda value: parse_int_tuple(value, allowed=set(DEFAULT_RULE_COUNTS)),
        default=DEFAULT_RULE_COUNTS,
    )
    parser.add_argument(
        "--project-counts",
        type=lambda value: parse_int_tuple(value, allowed=set(DEFAULT_PROJECT_COUNTS)),
        default=DEFAULT_PROJECT_COUNTS,
    )
    parser.add_argument(
        "--burst-sizes",
        type=lambda value: parse_int_tuple(value, allowed=set(DEFAULT_BURST_SIZES)),
        default=DEFAULT_BURST_SIZES,
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument(
        "--sequential-events", type=int, default=DEFAULT_SEQUENTIAL_EVENTS
    )
    parser.add_argument(
        "--warmups-per-project", type=int, default=DEFAULT_WARMUPS_PER_PROJECT
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--max-hook-workers", type=int, default=DEFAULT_MAX_HOOK_WORKERS
    )
    parser.add_argument("--soak-events", type=int, default=0)
    parser.add_argument("--soak-rule-count", type=int, default=8)
    parser.add_argument("--soak-project-count", type=int, default=8)
    parser.add_argument("--soak-batch-size", type=int, default=DEFAULT_SOAK_BATCH_SIZE)
    parser.add_argument(
        "--fault-repetitions", type=int, default=DEFAULT_FAULT_REPETITIONS
    )
    parser.add_argument("--faults", type=_fault_names, default=_fault_names("all"))
    parser.add_argument("--skip-offline-probe", action="store_true")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="record fault-probe errors instead of stopping (matrix accounting stays strict)",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print the deterministic plan and capabilities without running experiments",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--formal",
        action="store_true",
        help="enforce the exact protocol-v3 design and ALL-partition execution",
    )
    args = parser.parse_args()
    config = MatrixConfig(
        rule_counts=tuple(args.rule_counts),
        project_counts=tuple(args.project_counts),
        burst_sizes=tuple(args.burst_sizes),
        repeats=args.repeats,
        sequential_events=args.sequential_events,
        warmups_per_project=args.warmups_per_project,
        timeout_seconds=args.timeout,
        max_hook_workers=args.max_hook_workers,
        soak_events=args.soak_events,
        soak_rule_count=args.soak_rule_count,
        soak_project_count=args.soak_project_count,
        soak_batch_size=args.soak_batch_size,
        fault_repetitions=args.fault_repetitions,
    )
    config.validate()
    if args.formal:
        _validate_formal_config(
            config,
            fault_names=args.faults,
            run_offline_probe=not args.skip_offline_probe,
            strict=not args.continue_on_error,
            require_partition=not args.plan,
        )
    if args.plan:
        result = {
            "status": "plan_only",
            "config": asdict(config),
            "matrix": build_matrix_plan(config),
            "faults_selected": list(args.faults),
            "fault_capabilities": FAULT_CAPABILITIES,
            "offline_after_prepare_selected": not args.skip_offline_probe,
            "measurement_boundary": _measurement_boundary(),
        }
    else:
        bundle = load_external_artifacts()
        result = run_study(
            bundle,
            config,
            fault_names=args.faults,
            run_offline_probe=not args.skip_offline_probe,
            strict=not args.continue_on_error,
            formal=args.formal,
        )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = _validate_output_path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, output)
        print(output)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
