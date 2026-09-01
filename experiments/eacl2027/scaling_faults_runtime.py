"""Runtime and cache receipts for the formal systems study."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import multiprocessing
import os
import platform
import re
import shutil
import stat as stat_module
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


class RuntimeContractError(RuntimeError):
    """The process does not match the preregistered formal runtime profile."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_socket_preflight_receipt(
    value: Mapping[str, Any],
    *,
    socket_root: Path,
    raw_attempt_id: str,
    job_id: str,
    retained_runtime_root: Path,
) -> dict[str, Any]:
    """Recompute the amendment-007 pre-launch AF_UNIX capability receipt."""
    expected_root = Path(f"/tmp/rf3-{job_id}")
    if socket_root != expected_root:
        raise RuntimeContractError(
            f"formal socket root must equal {expected_root}, got {socket_root}"
        )
    try:
        root_stat = socket_root.lstat()
    except OSError as exc:
        raise RuntimeContractError(
            f"formal socket root is unavailable: {socket_root}: {exc}"
        ) from exc
    if (
        stat_module.S_ISLNK(root_stat.st_mode)
        or not stat_module.S_ISDIR(root_stat.st_mode)
        or int(root_stat.st_uid) != os.geteuid()
        or stat_module.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise RuntimeContractError(
            "formal socket root must be a non-symlink directory owned by the "
            "effective user with mode 0700"
        )
    digest_input = {
        "schema_version": 1,
        "raw_attempt_id": raw_attempt_id,
        "component": "preflight",
        "unit_id": "socket-canary",
        "retained_runtime_root": str(retained_runtime_root),
    }
    endpoint_digest = hashlib.sha256(
        json.dumps(
            digest_input,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    endpoint = socket_root / f"{endpoint_digest}.sock"
    expected = {
        "schema_version": 1,
        "digest_input": digest_input,
        "endpoint_digest": endpoint_digest,
        "endpoint": str(endpoint),
        "encoded_pathname_bytes": len(os.fsencode(endpoint)),
        "maximum_encoded_pathname_bytes": 107,
        "socket_root": {
            "path": str(socket_root),
            "owner_uid": int(root_stat.st_uid),
            "mode": stat_module.S_IMODE(root_stat.st_mode),
            "device": int(root_stat.st_dev),
        },
        "bind_connect_accept_payload_equal": True,
        "endpoint_removed_after_probe": True,
    }
    if expected["encoded_pathname_bytes"] > 107:
        raise RuntimeContractError(
            "formal socket canary endpoint exceeds the AF_UNIX pathname limit"
        )
    if os.path.lexists(endpoint):
        raise RuntimeContractError(
            f"formal socket canary endpoint still exists after preflight: {endpoint}"
        )
    if dict(value) != expected:
        raise RuntimeContractError(
            "formal socket preflight receipt mismatch: "
            + json.dumps(
                {"expected": expected, "observed": dict(value)}, sort_keys=True
            )
        )
    return expected


def _file_receipt(path: Path, *, relative_to: Path | None = None) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    stat = resolved.stat()
    return {
        "path": str(path.relative_to(relative_to) if relative_to else path),
        "resolved_path": str(resolved),
        "bytes": int(stat.st_size),
        "sha256": sha256_file(resolved),
    }


def _symlink_chain(path: Path) -> list[str]:
    current = path
    chain = [str(current)]
    seen: set[Path] = set()
    while current.is_symlink():
        if current in seen:
            raise RuntimeContractError(f"symlink cycle at {current}")
        seen.add(current)
        target = Path(os.readlink(current))
        current = target if target.is_absolute() else current.parent / target
        current = Path(os.path.normpath(current))
        chain.append(str(current))
    chain.append(str(current.resolve(strict=True)))
    return list(dict.fromkeys(chain))


def _reject_symlink_components(path: Path, *, label: str) -> None:
    lexical = path.expanduser()
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    parts = lexical.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                raise RuntimeContractError(
                    f"{label} contains a symlink component: {current}"
                )
        except OSError as exc:
            raise RuntimeContractError(f"could not inspect {label}: {current}") from exc


def _parse_memory_mib(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]?)\s*", value, re.I)
    if not match:
        raise RuntimeContractError(f"cannot parse Slurm memory value {value!r}")
    amount = float(match.group(1))
    suffix = match.group(2).upper()
    multiplier = {"": 1, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1024**2}[suffix]
    return int(amount * multiplier)


def _parse_duration_seconds(value: str) -> int:
    if value.upper() in {"UNLIMITED", "INFINITE"}:
        return 2**63 - 1
    days = 0
    clock = value
    if "-" in value:
        day_text, clock = value.split("-", 1)
        days = int(day_text)
    fields = [int(item) for item in clock.split(":")]
    if len(fields) == 3:
        hours, minutes, seconds = fields
    elif len(fields) == 2:
        hours, minutes, seconds = 0, fields[0], fields[1]
    else:
        raise RuntimeContractError(f"cannot parse Slurm duration {value!r}")
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _scontrol_record(job_id: str) -> tuple[str, dict[str, str]]:
    completed = subprocess.run(
        ["scontrol", "show", "job", "-o", job_id],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeContractError(
            f"could not obtain real Slurm job receipt for {job_id}: "
            f"{completed.stderr.strip()}"
        )
    raw = completed.stdout.strip()
    fields = {
        key: value
        for token in raw.split()
        if "=" in token
        for key, value in [token.split("=", 1)]
    }
    return raw, fields


def scheduler_receipt(
    profile: Mapping[str, Any],
    *,
    environ: Mapping[str, str] | None = None,
    affinity: Sequence[int] | None = None,
    scontrol_raw: str | None = None,
) -> dict[str, Any]:
    env = dict(os.environ if environ is None else environ)
    scheduler = dict(profile["scheduler"])
    job_id = env.get("SLURM_JOB_ID", "")
    if not re.fullmatch(r"\d+(?:_[0-9]+)?", job_id):
        raise RuntimeContractError("formal execution requires a real numeric SLURM_JOB_ID")
    if scontrol_raw is None:
        scontrol_raw, fields = _scontrol_record(job_id)
    else:
        fields = {
            key: value
            for token in scontrol_raw.split()
            if "=" in token
            for key, value in [token.split("=", 1)]
        }
    expected = {
        "SLURM_JOB_PARTITION": str(scheduler["partition"]),
        "SLURM_JOB_NODELIST": str(scheduler["node_list"]),
        "SLURM_CPUS_PER_TASK": str(scheduler["cpus_per_task"]),
    }
    mismatches = {
        name: {"expected": wanted, "observed": env.get(name)}
        for name, wanted in expected.items()
        if env.get(name) != wanted
    }
    for field, wanted in (
        ("Partition", str(scheduler["partition"])),
        ("NodeList", str(scheduler["node_list"])),
    ):
        if fields.get(field) != wanted:
            mismatches[f"scontrol.{field}"] = {
                "expected": wanted,
                "observed": fields.get(field),
            }
    if platform.node().split(".", 1)[0] != str(scheduler["node_list"]):
        mismatches["hostname"] = {
            "expected": scheduler["node_list"],
            "observed": platform.node(),
        }
    if fields.get("JobId", "").split("_")[0] != job_id.split("_")[0]:
        mismatches["scontrol.JobId"] = {
            "expected": job_id,
            "observed": fields.get("JobId"),
        }
    cpus = int(env["SLURM_CPUS_PER_TASK"])
    if fields.get("NumCPUs") != str(cpus):
        mismatches["scontrol.NumCPUs"] = {
            "expected": cpus,
            "observed": fields.get("NumCPUs"),
        }
    memory_mib = (
        _parse_memory_mib(env["SLURM_MEM_PER_NODE"])
        if env.get("SLURM_MEM_PER_NODE")
        else _parse_memory_mib(env.get("SLURM_MEM_PER_CPU", "0")) * cpus
    )
    if memory_mib < int(scheduler["minimum_memory_mib"]):
        mismatches["memory_mib"] = {
            "minimum": scheduler["minimum_memory_mib"],
            "observed": memory_mib,
        }
    time_limit = fields.get("TimeLimit", "")
    try:
        time_limit_seconds = _parse_duration_seconds(time_limit)
    except (RuntimeContractError, ValueError):
        time_limit_seconds = 0
    if time_limit_seconds < int(scheduler["minimum_time_limit_seconds"]):
        mismatches["scontrol.TimeLimit"] = {
            "minimum_seconds": scheduler["minimum_time_limit_seconds"],
            "observed": time_limit,
        }
    slurm_gpu_env_names = (
        "SLURM_JOB_GPUS",
        "SLURM_STEP_GPUS",
        "SLURM_GPUS",
        "SLURM_GPUS_ON_NODE",
    )
    gpu_values = {name: env.get(name) for name in slurm_gpu_env_names}
    if any(
        value not in {None, "", "0", "-1", "NoDevFiles", "none", "None"}
        for value in gpu_values.values()
    ):
        mismatches["slurm_gpu_allocation_environment"] = gpu_values
    cuda_visible = env.get("CUDA_VISIBLE_DEVICES")
    if cuda_visible not in {None, "", "-1", "NoDevFiles", "none", "None"}:
        mismatches["CUDA_VISIBLE_DEVICES"] = {
            "expected": "no visible device",
            "observed": cuda_visible,
        }
    if "gres/gpu" in fields.get("AllocTRES", "").lower():
        mismatches["scontrol.AllocTRES"] = fields.get("AllocTRES")
    affinity_ids = sorted(
        int(value)
        for value in (
            affinity
            if affinity is not None
            else os.sched_getaffinity(0)  # type: ignore[attr-defined]
        )
    )
    if len(affinity_ids) != int(profile["cpu_and_inference"]["affinity_cardinality"]):
        mismatches["affinity_cardinality"] = {
            "expected": profile["cpu_and_inference"]["affinity_cardinality"],
            "observed": len(affinity_ids),
        }
    if mismatches:
        raise RuntimeContractError(
            "formal Slurm runtime mismatch: " + json.dumps(mismatches, sort_keys=True)
        )
    return {
        "job_id": job_id,
        "environment": {
            name: env.get(name)
            for name in (
                *expected,
                "SLURM_MEM_PER_NODE",
                "SLURM_MEM_PER_CPU",
                "SLURM_JOB_CPUS_PER_NODE",
                "SLURM_CPUS_ON_NODE",
                *slurm_gpu_env_names,
                "CUDA_VISIBLE_DEVICES",
            )
        },
        "memory_mib": memory_mib,
        "time_limit_seconds": time_limit_seconds,
        "affinity_ids": affinity_ids,
        "affinity_cardinality": len(affinity_ids),
        "scontrol_selected": {
            name: fields.get(name)
            for name in (
                "JobId",
                "JobState",
                "Partition",
                "NodeList",
                "NumCPUs",
                "MinMemoryNode",
                "AllocTRES",
                "TimeLimit",
            )
        },
        "scontrol_raw_sha256": hashlib.sha256(scontrol_raw.encode()).hexdigest(),
        "shared_node_contention_uncontrolled": True,
        "exclusive_node_claimed": False,
    }


def python_receipt(profile: Mapping[str, Any], job_id: str) -> dict[str, Any]:
    required = dict(profile["python"])
    invocation = Path(sys.executable)
    base = Path(getattr(sys, "_base_executable", ""))
    observed_minor = [sys.version_info.major, sys.version_info.minor]
    mismatches: dict[str, Any] = {}
    expected_invocation = str(required["invoked_executable_template"]).replace(
        "${SLURM_JOB_ID}", job_id
    )
    if str(invocation) != expected_invocation:
        mismatches["sys.executable"] = str(invocation)
    if observed_minor != list(required["required_major_minor"]):
        mismatches["python_major_minor"] = observed_minor
    if str(base.resolve(strict=True)) != required["required_base_executable_resolved"]:
        mismatches["sys._base_executable_resolved"] = str(base.resolve(strict=True))
    if mismatches:
        raise RuntimeContractError(
            "formal Python runtime mismatch: " + json.dumps(mismatches, sort_keys=True)
        )
    return {
        "version": sys.version,
        "version_info": list(sys.version_info),
        "implementation": platform.python_implementation(),
        "cache_tag": sys.implementation.cache_tag,
        "invocation": {
            "symlink_chain": _symlink_chain(invocation),
            **_file_receipt(invocation),
        },
        "base": {"symlink_chain": _symlink_chain(base), **_file_receipt(base)},
    }


def package_receipts(packages: Mapping[str, str]) -> dict[str, Any]:
    receipts: dict[str, Any] = {}
    for distribution_name, module_name in packages.items():
        distribution = importlib.metadata.distribution(distribution_name)
        metadata_files: dict[str, Any] = {}
        for entry in distribution.files or ():
            name = str(entry)
            if not name.endswith(("/METADATA", "/RECORD", "/direct_url.json")):
                continue
            path = Path(distribution.locate_file(entry))
            if path.is_file():
                metadata_files[Path(name).name] = _file_receipt(path)
        spec = importlib.util.find_spec(module_name)
        origin = Path(spec.origin) if spec and spec.origin else None
        semantic_modules: dict[str, Any] = {}
        if module_name == "programasweights":
            for qualified in ("programasweights.config", "programasweights.cache"):
                semantic_spec = importlib.util.find_spec(qualified)
                semantic_origin = (
                    Path(semantic_spec.origin)
                    if semantic_spec and semantic_spec.origin
                    else None
                )
                if semantic_origin is None or not semantic_origin.is_file():
                    raise RuntimeContractError(
                        f"formal runtime cannot bind installed module {qualified}"
                    )
                semantic_modules[qualified] = _file_receipt(semantic_origin)
        receipts[distribution_name] = {
            "version": distribution.version,
            "distribution_root": str(Path(distribution.locate_file(".")).resolve()),
            "metadata_files": metadata_files,
            "module_origin": (
                _file_receipt(origin) if origin and origin.is_file() else None
            ),
            "semantic_modules": semantic_modules,
        }
    return receipts


def cache_receipt(
    cache_root: Path,
    program_ids: Sequence[str],
    *,
    required_n_ctx: int,
) -> dict[str, Any]:
    """Inventory the direct ProgramAsWeights content root.

    ``programasweights.config`` interprets ``PAW_CACHE_DIR`` as the directory
    that directly contains ``base_models``, ``programs``, and ``runtimes``.
    Do not append a package-named child here: doing so would validate a
    different tree from the one used by direct ``programasweights`` calls.
    """

    _reject_symlink_components(cache_root, label="formal PAW_CACHE_DIR")
    content_root = cache_root.resolve(strict=True)
    root_stat = content_root.stat(follow_symlinks=False)
    if not stat_module.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid():
        raise RuntimeContractError(
            "formal PAW direct root must be a directory owned by the effective user"
        )
    required_children = ("base_models", "programs", "runtimes")
    observed_children = sorted(path.name for path in content_root.iterdir())
    if observed_children != sorted(required_children):
        raise RuntimeContractError(
            "formal PAW direct children differ from the exact contract: "
            + json.dumps(
                {
                    "expected": sorted(required_children),
                    "observed": observed_children,
                },
                sort_keys=True,
            )
        )
    for name in required_children:
        child = content_root / name
        if child.is_symlink() or not child.is_dir():
            raise RuntimeContractError(
                f"formal PAW direct child is not a regular directory: {child}"
            )
    symlinks = [path for path in content_root.rglob("*") if path.is_symlink()]
    if symlinks:
        raise RuntimeContractError(
            "formal PAW cache contains unbound symlinks: "
            + ", ".join(str(path) for path in symlinks[:10])
        )
    programs: dict[str, Any] = {}
    models: dict[str, Any] = {}
    runtime_manifests: dict[str, Any] = {}
    for program_id in program_ids:
        directory = (content_root / "programs" / program_id).resolve(strict=True)
        if content_root not in directory.parents:
            raise RuntimeContractError(f"program cache escapes PAW_CACHE_DIR: {directory}")
        inventory = [
            _file_receipt(path, relative_to=content_root)
            for path in sorted(directory.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        required_names = {"adapter.gguf", "prompt_template.txt", "meta.json"}
        if not required_names.issubset({Path(item["path"]).name for item in inventory}):
            raise RuntimeContractError(f"incomplete cached program {program_id}")
        meta_path = directory / "meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if str(meta.get("program_id", "")) != program_id:
            raise RuntimeContractError(f"cached program ID mismatch for {program_id}")
        runtime = dict(meta.get("runtime") or {})
        observed_n_ctx = (runtime.get("local_sdk") or {}).get("n_ctx")
        if observed_n_ctx != required_n_ctx:
            raise RuntimeContractError(
                f"cached runtime n_ctx mismatch for {program_id}: "
                f"expected {required_n_ctx}, observed {observed_n_ctx!r}"
            )
        runtime_id = str(runtime.get("runtime_id") or meta.get("runtime_id") or "")
        runtime_bytes = json.dumps(
            runtime, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        cached_runtime = content_root / "runtimes" / f"{runtime_id}.json"
        if not runtime or not cached_runtime.is_file():
            raise RuntimeContractError(f"missing runtime manifest for {program_id}")
        cached_runtime_value = json.loads(cached_runtime.read_text(encoding="utf-8"))
        cached_runtime_bytes = json.dumps(
            cached_runtime_value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        embedded_sha = hashlib.sha256(runtime_bytes).hexdigest()
        cached_canonical_sha = hashlib.sha256(cached_runtime_bytes).hexdigest()
        if embedded_sha != cached_canonical_sha:
            raise RuntimeContractError(
                f"embedded/cached runtime manifest mismatch for {runtime_id}"
            )
        runtime_manifests[runtime_id] = {
            "embedded_canonical_sha256": embedded_sha,
            "cached_canonical_sha256": cached_canonical_sha,
            "canonical_json_equal": True,
            "cached": _file_receipt(cached_runtime, relative_to=content_root),
        }
        model = dict(((runtime.get("local_sdk") or {}).get("base_model") or {}))
        model_name = str(model.get("file", ""))
        model_path = content_root / "base_models" / model_name
        if not model_name or not model_path.is_file():
            raise RuntimeContractError(f"missing base model for {program_id}")
        model_receipt = _file_receipt(model_path, relative_to=content_root)
        if model.get("size_bytes") is not None and int(model["size_bytes"]) != model_receipt["bytes"]:
            raise RuntimeContractError(f"base-model size mismatch for {model_name}")
        if model.get("sha256") and str(model["sha256"]) != model_receipt["sha256"]:
            raise RuntimeContractError(f"base-model hash mismatch for {model_name}")
        models[model_name] = {"declared": model, "local": model_receipt}
        programs[program_id] = {"files": inventory, "runtime_id": runtime_id}
    return {
        "declared_root": str(cache_root),
        "root": str(content_root),
        "root_symlink_chain": _symlink_chain(cache_root),
        "direct_children": observed_children,
        "required_direct_children": list(required_children),
        "raw_tree": raw_tree_receipt(content_root),
        "complete_tree": tree_receipt(content_root),
        "programs": programs,
        "runtime_manifests": runtime_manifests,
        "base_models": models,
    }


def tree_receipt(root: Path) -> dict[str, Any]:
    if root.is_symlink():
        raise RuntimeContractError(f"formal inventory root may not be a symlink: {root}")
    resolved = root.resolve(strict=True)
    symlinks = [path for path in resolved.rglob("*") if path.is_symlink()]
    if symlinks:
        raise RuntimeContractError(
            "formal inventory contains unbound symlinks: "
            + ", ".join(str(path) for path in symlinks[:10])
        )
    files = [
        _file_receipt(path, relative_to=resolved)
        for path in sorted(resolved.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "root": str(resolved),
        "file_count": len(files),
        "total_bytes": sum(int(item["bytes"]) for item in files),
        "inventory_sha256": hashlib.sha256(canonical).hexdigest(),
        "files": files,
    }


def _canonical_sha256(value: Any) -> str:
    rendered = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _lstat_entry_type(mode: int) -> str:
    """Return the lossless portable label for an ``lstat`` mode."""
    if stat_module.S_ISREG(mode):
        return "regular"
    if stat_module.S_ISDIR(mode):
        return "directory"
    if stat_module.S_ISLNK(mode):
        return "symlink"
    if stat_module.S_ISFIFO(mode):
        return "fifo"
    if stat_module.S_ISSOCK(mode):
        return "socket"
    if stat_module.S_ISBLK(mode):
        return "block_device"
    if stat_module.S_ISCHR(mode):
        return "character_device"
    return "other"


def _raw_lstat_entry(
    path: Path,
    relative: str,
    *,
    errors: list[dict[str, str]],
) -> tuple[dict[str, Any] | None, bool]:
    """Describe one path without following it and say whether to descend."""
    try:
        observed = path.lstat()
    except OSError as exc:
        errors.append(
            {
                "path": relative,
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )
        return None, False

    entry_type = _lstat_entry_type(observed.st_mode)
    entry: dict[str, Any] = {
        "path": relative,
        "type": entry_type,
        "mode": int(stat_module.S_IMODE(observed.st_mode)),
        "uid": int(observed.st_uid),
        "gid": int(observed.st_gid),
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
        "link_count": int(observed.st_nlink),
        "mtime_ns": int(observed.st_mtime_ns),
        "ctime_ns": int(observed.st_ctime_ns),
    }
    if entry_type == "regular":
        entry["bytes"] = int(observed.st_size)
        try:
            entry["sha256"] = sha256_file(path)
            closed_over = path.lstat()
            if any(
                getattr(closed_over, name) != getattr(observed, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_uid",
                    "st_gid",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            ):
                raise RuntimeContractError("file changed while hashing")
        except OSError as exc:
            # The lstat evidence remains useful even when the bytes race away or
            # cannot be read.  Never silently drop the entry on a hash failure.
            entry["sha256"] = None
            errors.append(
                {
                    "path": relative,
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        except RuntimeContractError as exc:
            entry["sha256"] = None
            errors.append(
                {
                    "path": relative,
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
    elif entry_type == "symlink":
        try:
            entry["target"] = os.readlink(path)
        except OSError as exc:
            entry["target"] = None
            errors.append(
                {
                    "path": relative,
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
    elif entry_type in {"block_device", "character_device"}:
        entry["device_major"] = int(os.major(observed.st_rdev))
        entry["device_minor"] = int(os.minor(observed.st_rdev))
    return entry, entry_type == "directory"


def raw_tree_receipt(root: Path) -> dict[str, Any]:
    """Inventory without following symlinks, retaining unreadable-entry errors."""
    entries: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    root_entry, descend = _raw_lstat_entry(root, ".", errors=errors)
    if root_entry is None:
        missing = bool(errors and errors[0]["type"] == "FileNotFoundError")
        root_type = "missing" if missing else "unreadable"
    else:
        root_type = str(root_entry["type"])

    pending = [root] if descend else []
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as scan:
                children = sorted(scan, key=lambda item: item.name)
        except OSError as exc:
            relative = "." if directory == root else str(directory.relative_to(root))
            errors.append(
                {
                    "path": relative,
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            continue
        child_directories: list[Path] = []
        for child in children:
            path = directory / child.name
            relative = str(path.relative_to(root))
            entry, child_descend = _raw_lstat_entry(path, relative, errors=errors)
            if entry is not None:
                entries.append(entry)
            if child_descend:
                child_directories.append(path)
        pending.extend(reversed(child_directories))

    entries.sort(key=lambda item: (str(item["path"]), str(item["type"])))
    errors.sort(key=lambda item: (item["path"], item["type"], item["message"]))
    receipt: dict[str, Any] = {
        "declared_root": str(root),
        "root_type": root_type,
        "root_entry": root_entry,
        "entries": entries,
        "errors": errors,
        "inventory_sha256": _canonical_sha256(
            {"root_entry": root_entry, "entries": entries}
        ),
    }
    if root_type == "symlink" and root_entry is not None:
        # Preserve the original top-level convenience field.
        receipt["root_symlink_target"] = root_entry.get("target")
    return receipt


def validate_runtime_lock(
    lock_path: Path,
    *,
    wheelhouse: Mapping[str, Any],
    paw_cache: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind mutable external runtime bytes through a clean tracked lock file."""
    if lock_path.is_symlink():
        raise RuntimeContractError("formal runtime lock may not be a symlink")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key {key!r}")
            value[key] = child
        return value

    try:
        lock = json.loads(
            lock_path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeContractError(f"invalid formal runtime lock: {exc}") from exc
    mismatches: dict[str, Any] = {}
    lock_value = lock if isinstance(lock, dict) else {}
    if not isinstance(lock, dict) or set(lock) != {
        "schema_version",
        "wheelhouse",
        "paw_cache",
    }:
        mismatches["fields"] = sorted(lock) if isinstance(lock, dict) else type(lock).__name__
    if lock_value.get("schema_version") != 1:
        mismatches["schema_version"] = lock_value.get("schema_version")
    for name, observed in (("wheelhouse", wheelhouse), ("paw_cache", paw_cache)):
        locked = lock_value.get(name)
        if locked != observed:
            mismatches[name] = {
                "locked_sha256": _canonical_sha256(locked),
                "observed_sha256": _canonical_sha256(observed),
            }
    if mismatches:
        raise RuntimeContractError(
            "formal runtime lock mismatch: " + json.dumps(mismatches, sort_keys=True)
        )
    return {
        "file": _file_receipt(lock_path),
        "content": lock_value,
        "wheelhouse_receipt_sha256": _canonical_sha256(wheelhouse),
        "paw_cache_receipt_sha256": _canonical_sha256(paw_cache),
    }


def retain_cache_end_receipt(
    profile: Mapping[str, Any],
    program_ids: Sequence[str],
    *,
    launch_receipt: Mapping[str, Any],
    changed_files_root: Path,
) -> dict[str, Any]:
    """Inventory post-run cache state and losslessly retain changed/new bytes."""
    dependency = dict(profile["cache_and_dependency_receipt"])
    cache_root = Path(dependency["formal_cache_dir"])
    content_path = cache_root
    raw_after = raw_tree_receipt(content_path)
    validation_error: dict[str, str] | None = None
    try:
        after = cache_receipt(
            cache_root,
            program_ids,
            required_n_ctx=int(profile["cpu_and_inference"]["paw_function_n_ctx"]),
        )
    except BaseException as exc:
        after = None
        validation_error = {
            "type": type(exc).__name__,
            "message": str(exc),
        }

    # Prefer the raw tree captured as part of the strict receipt so the strict
    # and raw evidence describe the same best-effort snapshot.
    if after is not None and isinstance(after.get("raw_tree"), dict):
        raw_after = dict(after["raw_tree"])

    raw_before_value = launch_receipt.get("raw_tree")
    prelaunch_raw_tree_missing = not isinstance(raw_before_value, Mapping)
    raw_before = (
        dict(raw_before_value)
        if isinstance(raw_before_value, Mapping)
        else {
            "root_type": "directory",
            "root_entry": {"path": ".", "type": "directory"},
            "entries": [
                dict(item)
                for item in (launch_receipt.get("complete_tree") or {}).get(
                    "files", []
                )
                if isinstance(item, Mapping)
            ],
            "errors": [],
        }
    )

    def indexed_raw_entries(receipt: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        root_entry = receipt.get("root_entry")
        if isinstance(root_entry, Mapping):
            indexed["."] = dict(root_entry)
        for item in receipt.get("entries") or []:
            if isinstance(item, Mapping) and item.get("path") is not None:
                indexed[str(item["path"])] = dict(item)
        return indexed

    before_entries = indexed_raw_entries(raw_before)
    all_after_entries = indexed_raw_entries(raw_after)
    entry_changes: list[dict[str, Any]] = []
    permitted_runtime_manifest_temporal_changes: list[dict[str, Any]] = []
    allow_runtime_manifest_temporal_change = dependency.get("runtime_lock_path") == (
        "experiments/eacl2027/formal-runtime-lock-v9.json"
    )
    for path in sorted(all_after_entries):
        current = all_after_entries[path]
        previous = before_entries.get(path)
        if previous is None:
            entry_changes.append(
                {
                    "path": path,
                    "change": "added",
                    "before": None,
                    "after": current,
                }
            )
        elif previous != current:
            changed_fields = sorted(
                key
                for key in set(previous) | set(current)
                if previous.get(key) != current.get(key)
            )
            if (
                allow_runtime_manifest_temporal_change
                and path == "runtimes/qwen3-0.6b-q6_k.json"
                and changed_fields
                and set(changed_fields).issubset({"mtime_ns", "ctime_ns"})
                and previous.get("type") == "regular"
                and current.get("type") == "regular"
            ):
                permitted_runtime_manifest_temporal_changes.append(
                    {
                        "path": path,
                        "changed_fields": changed_fields,
                        "before": previous,
                        "after": current,
                        "bytes_sha256_and_identity_unchanged": True,
                    }
                )
                continue
            entry_changes.append(
                {
                    "path": path,
                    "change": (
                        "type_changed"
                        if previous.get("type") != current.get("type")
                        else "modified"
                    ),
                    "before": previous,
                    "after": current,
                }
            )
    deleted_entries = [
        before_entries[path]
        for path in sorted(set(before_entries) - set(all_after_entries))
    ]
    special_entries = [
        all_after_entries[path]
        for path in sorted(all_after_entries)
        if all_after_entries[path].get("type") not in {"regular", "directory"}
    ]

    # These regular-file-only views retain the v3 field semantics.  The
    # exhaustive structural comparison lives in entry_changes/deleted_entries.
    before_files = {
        str(item["path"]): dict(item)
        for item in (launch_receipt.get("complete_tree") or {}).get("files", [])
    }
    after_files = {
        str(item["path"]): dict(item)
        for item in raw_after.get("entries", [])
        if item.get("type") == "regular"
    }
    changed_or_new = sorted(
        path
        for path, receipt in after_files.items()
        if {
            key: receipt.get(key) for key in ("path", "bytes", "sha256")
        }
        != {
            key: (before_files.get(path) or {}).get(key)
            for key in ("path", "bytes", "sha256")
        }
    )
    deleted = sorted(set(before_files) - set(after_files))
    non_regular_or_symlink = [str(item["path"]) for item in special_entries]
    copies: list[dict[str, Any]] = []
    copy_errors: list[dict[str, str]] = []
    if changed_or_new:
        changed_files_root.mkdir(parents=True, exist_ok=False)
        try:
            safe_cache_root = cache_root.resolve(strict=True)
        except OSError:
            safe_cache_root = cache_root
        for relative in changed_or_new:
            try:
                declared_source = content_path / relative
                if declared_source.is_symlink():
                    raise RuntimeContractError("source is a symlink")
                source = declared_source.resolve(strict=True)
                if safe_cache_root != source and safe_cache_root not in source.parents:
                    raise RuntimeContractError("source escapes cache root")
                if not source.is_file():
                    raise RuntimeContractError("source is not a regular file")
                destination = changed_files_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source.open("rb") as reader, destination.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
                    writer.flush()
                    os.fsync(writer.fileno())
                copied = _file_receipt(destination, relative_to=changed_files_root)
                if copied["sha256"] != after_files[relative]["sha256"]:
                    raise RuntimeContractError("retained copy hash mismatch")
                copies.append(copied)
            except BaseException as exc:
                copy_errors.append(
                    {
                        "path": relative,
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )
    comparison_errors = (
        ["launch receipt has no prelaunch raw_tree"]
        if prelaunch_raw_tree_missing
        else []
    )
    unchanged = bool(
        not entry_changes
        and not deleted_entries
        and not special_entries
        and not raw_before.get("errors")
        and not raw_after.get("errors")
        and not comparison_errors
        and validation_error is None
    )
    retained_root_relative: dict[str, str] | None = None
    if (
        changed_or_new
        and changed_files_root.name == "cache-end-changed-files"
        and changed_files_root.parent.name == "runtime"
    ):
        retained_root_relative = {
            "base": "attempt_root",
            "path": "runtime/cache-end-changed-files",
        }
    return {
        "status": "completed" if unchanged else "system_violation",
        "unchanged": unchanged,
        "launch_receipt_sha256": _canonical_sha256(launch_receipt),
        "end_receipt_sha256": _canonical_sha256(after or raw_after),
        "changed_or_new": changed_or_new,
        "deleted": deleted,
        "non_regular_or_symlink": non_regular_or_symlink,
        "entry_changes": entry_changes,
        "permitted_runtime_manifest_temporal_changes": (
            permitted_runtime_manifest_temporal_changes
        ),
        "deleted_entries": deleted_entries,
        "special_entries": special_entries,
        "prelaunch_raw_tree_missing": prelaunch_raw_tree_missing,
        "prelaunch_raw_tree_errors": list(raw_before.get("errors") or []),
        "comparison_errors": comparison_errors,
        "raw_end_tree": raw_after,
        "strict_validation_error": validation_error,
        "retained_changed_files_root": (
            str(changed_files_root) if changed_or_new else None
        ),
        "retained_changed_files_root_relative": retained_root_relative,
        "retained_changed_files": copies,
        "retained_copy_errors": copy_errors,
        "end_receipt": after,
    }


def formal_runtime_receipt(
    profile: Mapping[str, Any],
    program_ids: Sequence[str],
    *,
    raw_attempt_id: str,
    expected_replacement_chain: Mapping[str, Any],
) -> dict[str, Any]:
    env = os.environ
    dependency = dict(profile["cache_and_dependency_receipt"])
    cache_path = str(dependency["formal_cache_dir"])
    mismatches: dict[str, Any] = {}
    job_id = env.get("SLURM_JOB_ID", "")
    if not re.fullmatch(r"\d+(?:_[0-9]+)?", job_id):
        mismatches["SLURM_JOB_ID"] = {
            "expected": "real numeric Slurm job ID",
            "observed": job_id,
        }
    if env.get("PAW_CACHE_DIR") != cache_path:
        mismatches["PAW_CACHE_DIR"] = {
            "expected": cache_path,
            "observed": env.get("PAW_CACHE_DIR"),
        }
    if "PROGRAMASWEIGHTS_CACHE_DIR" in env:
        mismatches["PROGRAMASWEIGHTS_CACHE_DIR"] = {
            "expected": "UNSET",
            "observed": env.get("PROGRAMASWEIGHTS_CACHE_DIR"),
        }
    if env.get("PAW_GPU_LAYERS") != str(
        profile["cpu_and_inference"]["paw_gpu_layers_environment"]
    ):
        mismatches["PAW_GPU_LAYERS"] = env.get("PAW_GPU_LAYERS")
    for name, expected in dict(profile["thread_environment"]).items():
        if expected == "UNSET" and name in env:
            mismatches[name] = {"expected": "UNSET", "observed": env.get(name)}
    if os.cpu_count() != int(profile["cpu_and_inference"]["host_logical_cpu_count"]):
        mismatches["os.cpu_count"] = os.cpu_count()
    if multiprocessing.cpu_count() != int(
        profile["cpu_and_inference"]["multiprocessing_cpu_count"]
    ):
        mismatches["multiprocessing.cpu_count"] = multiprocessing.cpu_count()
    launch_script = Path(env.get("RAP_EACL_LAUNCH_SCRIPT", ""))
    if not launch_script.is_file():
        mismatches["RAP_EACL_LAUNCH_SCRIPT"] = env.get("RAP_EACL_LAUNCH_SCRIPT")
    setup_receipt = Path(env.get("RAP_EACL_SETUP_RECEIPT", ""))
    if not setup_receipt.is_file():
        mismatches["RAP_EACL_SETUP_RECEIPT"] = env.get("RAP_EACL_SETUP_RECEIPT")
    setup_log = Path(env.get("RAP_EACL_SETUP_LOG", ""))
    if not setup_log.is_file():
        mismatches["RAP_EACL_SETUP_LOG"] = env.get("RAP_EACL_SETUP_LOG")
    expected_launch_script = (
        Path(dependency["formal_repository"])
        / "experiments"
        / "eacl2027"
        / "run_scaling_faults_watgpu.sbatch"
    )
    if launch_script.is_file() and launch_script.resolve() != expected_launch_script:
        mismatches["RAP_EACL_LAUNCH_SCRIPT"] = {
            "expected": str(expected_launch_script),
            "observed": str(launch_script.resolve()),
        }
    scheduler_root = Path(
        dependency.get(
            "formal_scheduler_dir",
            Path(dependency["formal_repository"]).parent / "scheduler",
        )
    ).resolve()
    for name, path in (
        ("RAP_EACL_SETUP_RECEIPT", setup_receipt),
        ("RAP_EACL_SETUP_LOG", setup_log),
    ):
        if path.is_file() and path.resolve().parent != scheduler_root:
            mismatches[name] = {
                "expected_parent": str(scheduler_root),
                "observed": str(path.resolve()),
            }
    if re.fullmatch(r"\d+(?:_[0-9]+)?", job_id):
        node_root = Path(f"/tmp/rap-eacl-systems-formal-v3-{job_id}")
        if env.get("HOME") != str(node_root / "home"):
            mismatches["HOME"] = {
                "expected": str(node_root / "home"),
                "observed": env.get("HOME"),
            }
        expected_socket_root = Path(f"/tmp/rf3-{job_id}")
        if env.get("RAP_EACL_SOCKET_ROOT") != str(expected_socket_root):
            mismatches["RAP_EACL_SOCKET_ROOT"] = {
                "expected": str(expected_socket_root),
                "observed": env.get("RAP_EACL_SOCKET_ROOT"),
            }
    if mismatches:
        raise RuntimeContractError(
            "formal process environment mismatch: " + json.dumps(mismatches, sort_keys=True)
        )
    try:
        import llama_cpp

        gpu_offload = bool(llama_cpp.llama_supports_gpu_offload())
    except (ImportError, AttributeError):
        gpu_offload = None
    wheelhouse = tree_receipt(Path(dependency["formal_wheelhouse"]))
    paw_cache = cache_receipt(
        Path(cache_path),
        program_ids,
        required_n_ctx=int(profile["cpu_and_inference"]["paw_function_n_ctx"]),
    )
    formal_repository = Path(dependency["formal_repository"]).resolve(strict=True)
    declared_runtime_lock = formal_repository / str(dependency["runtime_lock_path"])
    if declared_runtime_lock.is_symlink():
        raise RuntimeContractError("formal runtime lock may not be a symlink")
    runtime_lock_path = declared_runtime_lock.resolve(strict=True)
    if formal_repository not in runtime_lock_path.parents:
        raise RuntimeContractError("formal runtime lock escapes repository")
    runtime_lock = validate_runtime_lock(
        runtime_lock_path,
        wheelhouse=wheelhouse,
        paw_cache=paw_cache,
    )
    try:
        setup_value = json.loads(setup_receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeContractError(f"invalid setup receipt JSON: {exc}") from exc
    socket_root = Path(str(env.get("RAP_EACL_SOCKET_ROOT", "")))
    retained_preflight_root = (
        Path(dependency["formal_attempt_root"]).resolve()
        / raw_attempt_id
        / "runtime"
        / "preflight"
    )
    socket_preflight = validate_socket_preflight_receipt(
        dict(setup_value.get("socket_preflight") or {}),
        socket_root=socket_root,
        raw_attempt_id=raw_attempt_id,
        job_id=job_id,
        retained_runtime_root=retained_preflight_root,
    )
    expected_invocation = str(profile["python"]["invoked_executable_template"]).replace(
        "${SLURM_JOB_ID}", job_id
    )
    setup_mismatches: dict[str, Any] = {}
    required_setup = {
        "schema_version": 1,
        "slurm_job_id": job_id,
        "raw_attempt_id": raw_attempt_id,
        "study_mode": "formal_protocol_v3_amendment_008",
        "wheelhouse_path": str(Path(dependency["formal_wheelhouse"]).resolve()),
        "wheelhouse_inventory_sha256": wheelhouse["inventory_sha256"],
        "venv_executable": expected_invocation,
        "base_executable_resolved": str(
            profile["python"]["required_base_executable_resolved"]
        ),
        "setup_log_path": str(setup_log.resolve()),
        "setup_log_sha256": sha256_file(setup_log),
        "setup_log_content": setup_log.read_text(encoding="utf-8"),
        "wheelhouse_files": wheelhouse["files"],
        "launch_script_path": str(launch_script.resolve()),
        "node_runtime_root": str(Path(expected_invocation).parents[2]),
        "home": str(Path(expected_invocation).parents[2] / "home"),
        "socket_root": str(socket_root),
        "socket_preflight": socket_preflight,
        "replacement_chain": dict(expected_replacement_chain),
    }
    for name, expected in required_setup.items():
        if setup_value.get(name) != expected:
            setup_mismatches[name] = {
                "expected": expected,
                "observed": setup_value.get(name),
            }
    offline_pip = dict(setup_value.get("offline_pip") or {})
    offline_argv = [str(item) for item in offline_pip.get("argv") or []]
    if (
        offline_pip.get("returncode") != 0
        or "--no-index" not in offline_argv
        or "--find-links" not in offline_argv
        or str(Path(dependency["formal_wheelhouse"])) not in offline_argv
    ):
        setup_mismatches["offline_pip"] = offline_pip
    import_preflight = dict(setup_value.get("import_preflight") or {})
    if import_preflight.get("returncode") != 0:
        setup_mismatches["import_preflight"] = import_preflight
    pip_freeze = dict(setup_value.get("pip_freeze") or {})
    if pip_freeze.get("returncode") != 0:
        setup_mismatches["pip_freeze"] = pip_freeze
    if setup_mismatches:
        raise RuntimeContractError(
            "formal setup receipt mismatch: "
            + json.dumps(setup_mismatches, sort_keys=True)
        )
    return {
        "scheduler": scheduler_receipt(profile),
        "python": python_receipt(profile, job_id),
        "process": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "os_cpu_count": os.cpu_count(),
            "multiprocessing_cpu_count": multiprocessing.cpu_count(),
            "llama_cpp_implied_n_threads": profile["cpu_and_inference"][
                "llama_cpp_n_threads"
            ],
            "llama_cpp_implied_n_threads_batch": profile["cpu_and_inference"][
                "llama_cpp_n_threads_batch"
            ],
            "llama_cpp_gpu_offload_supported": gpu_offload,
            "oversubscription_limitation": profile["cpu_and_inference"][
                "oversubscription_limit"
            ],
        },
        "named_environment": {
            name: env.get(name)
            for name in (
                "PAW_CACHE_DIR",
                "PROGRAMASWEIGHTS_CACHE_DIR",
                "PAW_GPU_LAYERS",
                "HOME",
                "RAP_EACL_SOCKET_ROOT",
                *profile["thread_environment"].keys(),
            )
        },
        "launch_script": _file_receipt(launch_script),
        "setup_preflight_receipt": {
            "file": _file_receipt(setup_receipt),
            "content": setup_value,
        },
        "setup_preflight_log": _file_receipt(setup_log),
        "packages": package_receipts(
            {
                "rules-as-programs": "rules_as_programs",
                "programasweights": "programasweights",
                "llama-cpp-python": "llama_cpp",
                "psutil": "psutil",
            }
        ),
        "wheelhouse": wheelhouse,
        "paw_cache": paw_cache,
        "runtime_lock": runtime_lock,
    }
