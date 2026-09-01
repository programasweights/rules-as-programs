from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = REPO_ROOT / "experiments/eacl2027/run_scaling_faults_watgpu.sbatch"
FORMAL_ROOT = "/u4/yuntian/rap-eacl-systems-formal-v3"


def _source() -> str:
    return LAUNCHER.read_text(encoding="utf-8")


def _directives(source: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in source.splitlines():
        match = re.fullmatch(r"#SBATCH\s+--([a-z-]+)=(.+)", line)
        if match:
            key, value = match.groups()
            assert key not in result, f"duplicate Slurm directive: {key}"
            result[key] = value
    return result


def _formal_command(source: str) -> list[str]:
    logical_source = re.sub(r"\\\n[ \t]*", " ", source)
    command = next(
        line.strip()
        for line in logical_source.splitlines()
        if line.strip().startswith('"${VENV_ROOT}/bin/python"')
        and '"${RUNNER}"' in line
    )
    return shlex.split(command)


def _receipt_python(source: str) -> str:
    match = re.search(
        r'"\$\{VENV_ROOT\}/bin/python" -c \'\n(?P<code>.*?)\n\' \\\n'
        r'    "\$\{SETUP_RECEIPT\}"',
        source,
        re.DOTALL,
    )
    assert match is not None
    return match.group("code")


def test_launcher_has_exact_cpu_only_slurm_profile_and_valid_bash():
    source = _source()
    assert source.startswith("#!/bin/bash\n")
    assert os.access(LAUNCHER, os.X_OK)

    completed = subprocess.run(
        ["/bin/bash", "-n", str(LAUNCHER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr

    assert _directives(source) == {
        "job-name": "rap-eacl-systems-v3",
        "partition": "ALL",
        "nodelist": "watgpu108",
        "nodes": "1",
        "ntasks": "1",
        "cpus-per-task": "8",
        "mem": "16G",
        "time": "7-00:00:00",
        "chdir": f"{FORMAL_ROOT}/repo",
        "output": f"{FORMAL_ROOT}/scheduler/%x-%j.stdout.log",
        "error": f"{FORMAL_ROOT}/scheduler/%x-%j.stderr.log",
        "export": "RAP_EACL_ATTEMPT_ID,RAP_EACL_REPLACEMENT_RECEIPT",
    }
    assert not re.search(
        r"(?mi)^#SBATCH\s+--(?:gres|gpu|gpus|gpu-bind|gpu-freq)(?:=|\s|$)",
        source,
    )


def test_launcher_pins_sanitized_environment_and_contains_no_secret_material():
    source = _source()
    assert 'export PATH="/usr/local/bin:/usr/bin:/bin"' in source
    assert 'export PATH="${VENV_ROOT}/bin:/usr/local/bin:/usr/bin:/bin"' in source
    assert "$PATH" not in source and "${PATH}" not in source
    assert "export PAW_GPU_LAYERS=0" in source
    assert "export CUDA_VISIBLE_DEVICES=" in source
    assert (
        f'export PAW_CACHE_DIR="{FORMAL_ROOT}/runtime/cache/formal-v3-r07-programasweights"'
        in source
    )
    assert 'unset OMP_NUM_THREADS OPENBLAS_NUM_THREADS MKL_NUM_THREADS' in source
    assert 'unset VECLIB_MAXIMUM_THREADS NUMEXPR_NUM_THREADS' in source
    assert "export PIP_NO_INDEX=1" in source
    assert 'export PIP_FIND_LINKS="${WHEELHOUSE_ROOT}"' in source
    assert 'export RAP_EACL_LAUNCH_SCRIPT="${LAUNCH_SCRIPT}"' in source
    assert 'export RAP_EACL_SETUP_LOG="${SETUP_LOG}"' in source
    assert 'export RAP_EACL_SETUP_RECEIPT="${SETUP_RECEIPT}"' in source
    assert 'export RAP_EACL_SOCKET_ROOT="${SOCKET_ROOT}"' in source
    assert (
        'readonly LAUNCH_SCRIPT="${REPO_ROOT}/'
        'experiments/eacl2027/run_scaling_faults_watgpu.sbatch"'
    ) in source
    assert (
        'readonly RUNTIME_LOCK="${REPO_ROOT}/'
            'experiments/eacl2027/formal-runtime-lock-v11.json"'
    ) in source
    assert '! -f "${RUNTIME_LOCK}"' in source

    unset_names: list[str] = []
    for line in source.splitlines():
        if line.startswith("unset "):
            unset_names.extend(shlex.split(line)[1:])
    assert unset_names == [
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "PROGRAMASWEIGHTS_CACHE_DIR",
    ]
    for marker in (
        "API_KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "AUTHORIZATION",
        "PRIVATE_KEY",
    ):
        assert marker not in source.upper()


def test_launcher_requires_a_new_validated_external_attempt_id_without_creating_it():
    source = _source()
    assert (
        "# sbatch --export=RAP_EACL_ATTEMPT_ID=formal-v3-YYYYMMDDTHHMMSSZ-r01"
        in source
    )
    assert (
        ': "${RAP_EACL_ATTEMPT_ID:?set RAP_EACL_ATTEMPT_ID to a new '
        'formal-attempt slug}"'
    ) in source
    assert (
        '[[ ! "${RAP_EACL_ATTEMPT_ID}" =~ '
        "^[a-z0-9][a-z0-9._-]{0,63}$ ]]"
    ) in source
    assert '[[ ! "${RAP_EACL_ATTEMPT_ID}" =~ ^(.+)-r([0-9]{2})$ ]]' in source
    assert "r01 requires RAP_EACL_REPLACEMENT_RECEIPT" in source
    assert "r02+ requires RAP_EACL_REPLACEMENT_RECEIPT" in source
    assert '[[ -L "${replacement_receipt}" || ! -f "${replacement_receipt}" ]]' in source
    assert '[[ "${replacement_receipt##*/}" != "replacement.json" ]]' in source
    assert "replacement_launch_binding" in _receipt_python(source)
    assert "allowed_scheduler_states" not in _receipt_python(source)
    assert f'readonly FORMAL_ROOT="{FORMAL_ROOT}"' in source
    assert 'readonly RAW_ATTEMPTS_ROOT="${FORMAL_ROOT}/attempts"' in source
    assert (
        'readonly ATTEMPT_DIR="${RAW_ATTEMPTS_ROOT}/${RAP_EACL_ATTEMPT_ID}"'
        in source
    )
    assert '[[ -e "${ATTEMPT_DIR}" ]]' in source
    assert not re.search(
        r"(?m)^\s*(?:/usr/bin/)?(?:mkdir|install\s+-d)\b.*"
        r"(?:ATTEMPT_DIR|RAW_ATTEMPTS_ROOT)",
        source,
    )


def test_launcher_builds_a_fresh_hashed_node_local_environment_offline():
    source = _source()
    compile(_receipt_python(source), str(LAUNCHER), "exec")
    assert 'readonly WHEELHOUSE_ROOT="${FORMAL_ROOT}/runtime/wheelhouse"' in source
    assert (
        'readonly NODE_RUNTIME_ROOT="/tmp/rap-eacl-systems-formal-v3-'
        '${SLURM_JOB_ID}"'
    ) in source
    assert 'readonly SOCKET_ROOT="/tmp/rf3-${SLURM_JOB_ID}"' in source
    assert 'readonly HOME_ROOT="${NODE_RUNTIME_ROOT}/home"' in source
    assert 'readonly VENV_ROOT="${NODE_RUNTIME_ROOT}/venv"' in source
    assert '[[ -e "${NODE_RUNTIME_ROOT}" ]]' in source
    assert '[[ -e "${SOCKET_ROOT}" || -L "${SOCKET_ROOT}" ]]' in source
    assert '/usr/bin/mkdir --mode=700 -- "${NODE_RUNTIME_ROOT}"' in source
    assert '/usr/bin/mkdir --mode=700 -- "${SOCKET_ROOT}"' in source
    assert '/usr/bin/mkdir --mode=700 -- "${HOME_ROOT}"' in source
    assert 'export HOME="${HOME_ROOT}"' in source
    assert "SLURM_TMPDIR" not in source
    assert f"{FORMAL_ROOT}/runtime/.venv" not in source
    assert (
        'run_setup_command /usr/bin/python3.10 -m venv --without-pip '
        '"${VENV_ROOT}"'
    ) in source
    assert '--no-index --find-links "${WHEELHOUSE_ROOT}" --no-deps --upgrade' in source
    for pinned_wheel in (
        "pip-26.1.2-py3-none-any.whl",
        "rules_as_programs-0.1.0-py3-none-any.whl",
        "programasweights-0.4.2-py3-none-any.whl",
        "llama_cpp_python-0.3.19-cp310-cp310-linux_x86_64.whl",
        "psutil-7.2.2-cp36-abi3-manylinux2010_x86_64.manylinux_2_12_x86_64.manylinux_2_28_x86_64.whl",
    ):
        assert pinned_wheel in source

    assert (
        'readonly SETUP_LOG="${SCHEDULER_ROOT}/${RAP_EACL_ATTEMPT_ID}-'
        '${SLURM_JOB_ID}.setup.log"'
    ) in source
    assert (
        'readonly SETUP_RECEIPT="${SCHEDULER_ROOT}/${RAP_EACL_ATTEMPT_ID}-'
        '${SLURM_JOB_ID}.setup-receipt.json"'
    ) in source
    setup_function = source.split("run_setup_command() {", 1)[1].split("\n}\n", 1)[0]
    assert "SETUP_RECEIPT" not in setup_function
    assert 'with receipt_path.open("x", encoding="utf-8")' in source
    for required_json_field in (
        '"schema_version": 1',
        '"slurm_job_id": job_id',
        '"raw_attempt_id": raw_attempt_id',
        '"study_mode": FORMAL_STUDY_MODE',
        '"replacement_chain": replacement_chain',
        '"wheelhouse_path": str(wheelhouse)',
        '"wheelhouse_inventory_sha256":',
        '"venv_executable": str(venv_executable)',
        '"base_executable_resolved": str(base_executable)',
        '"offline_pip": {"argv": offline_pip_argv, "returncode": 0}',
        '"import_preflight": {',
        '"setup_log_path": str(setup_log)',
        '"setup_log_sha256": sha256_file(setup_log)',
        '"setup_log_content": setup_log.read_text(encoding="utf-8")',
        '"socket_root": str(socket_root)',
        '"socket_preflight": socket_preflight',
    ):
        assert required_json_field in source

    receipt_code = _receipt_python(source)
    for capability_check in (
        'socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        'server.bind(str(socket_endpoint))',
        'server.listen(1)',
        'client.connect(str(socket_endpoint))',
        'accepted, _ = server.accept()',
        'socket_endpoint.unlink()',
        '"maximum_encoded_pathname_bytes": 107',
        '"bind_connect_accept_payload_equal": received == payload',
        '"endpoint_removed_after_probe": not os.path.lexists(socket_endpoint)',
    ):
        assert capability_check in receipt_code


def test_launcher_passes_the_exact_explicit_formal_cli():
    source = _source()
    formal_command = _formal_command(source)
    assert formal_command == [
        "${VENV_ROOT}/bin/python",
        "${RUNNER}",
        "--supervise",
        "--formal",
        "--attempt-dir",
        "${ATTEMPT_DIR}",
        "--rule-counts",
        "1,2,4,8",
        "--project-counts",
        "1,4,8",
        "--burst-sizes",
        "24,64",
        "--repeats",
        "4",
        "--sequential-events",
        "20",
        "--warmups-per-project",
        "1",
        "--timeout",
        "30",
        "--drain-timeout",
        "1200",
        "--max-hook-workers",
        "24",
        "--soak-events",
        "10000",
        "--soak-rule-count",
        "8",
        "--soak-project-count",
        "8",
        "--soak-batch-size",
        "64",
        "--fault-repetitions",
        "20",
        "--faults",
        (
            "daemon_crash,worker_exit,worker_timeout,sqlite_lock,"
            "malformed_payload,duplicate_delivery,deployment_failure"
        ),
    ]
    assert "--skip-offline-probe" not in source
    assert "--continue-on-error" not in source
    assert "--output" not in formal_command
