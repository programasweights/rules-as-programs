#!/bin/bash
#SBATCH --job-name=rap-eacl-systems-v3
#SBATCH --partition=ALL
#SBATCH --nodelist=watgpu108
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=7-00:00:00
#SBATCH --chdir=/u4/yuntian/rap-eacl-systems-formal-v3/repo
#SBATCH --output=/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/%x-%j.stdout.log
#SBATCH --error=/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/%x-%j.stderr.log
#SBATCH --export=RAP_EACL_ATTEMPT_ID,RAP_EACL_REPLACEMENT_RECEIPT

# Submit with no caller environment except a new immutable attempt ID:
# sbatch --export=RAP_EACL_ATTEMPT_ID=formal-v3-YYYYMMDDTHHMMSSZ-r01 \
#   /u4/yuntian/rap-eacl-systems-formal-v3/repo/experiments/eacl2027/run_scaling_faults_watgpu.sbatch
# A replacement r02+ also exports a pre-existing immutable replacement.json:
# sbatch --export=RAP_EACL_ATTEMPT_ID=formal-v3-YYYYMMDDTHHMMSSZ-r02,RAP_EACL_REPLACEMENT_RECEIPT=/durable/replacement.json \
#   /u4/yuntian/rap-eacl-systems-formal-v3/repo/experiments/eacl2027/run_scaling_faults_watgpu.sbatch
# The repo, wheelhouse, cache, attempts root, and scheduler root must already exist.
# The runner, rather than this shell launcher, exclusively creates the attempt directory.

set -euo pipefail
umask 077

readonly FORMAL_ROOT="/u4/yuntian/rap-eacl-systems-formal-v3"
readonly REPO_ROOT="${FORMAL_ROOT}/repo"
readonly WHEELHOUSE_ROOT="${FORMAL_ROOT}/runtime/wheelhouse"
readonly RAW_ATTEMPTS_ROOT="${FORMAL_ROOT}/attempts"
readonly SCHEDULER_ROOT="${FORMAL_ROOT}/scheduler"
readonly RUNNER="${REPO_ROOT}/experiments/eacl2027/run_scaling_faults.py"
readonly RUNTIME_LOCK="${REPO_ROOT}/experiments/eacl2027/formal-runtime-lock-v10.json"
readonly LAUNCH_SCRIPT="${REPO_ROOT}/experiments/eacl2027/run_scaling_faults_watgpu.sbatch"

export PATH="/usr/local/bin:/usr/bin:/bin"
export PAW_GPU_LAYERS=0
export CUDA_VISIBLE_DEVICES=
export PAW_CACHE_DIR="/u4/yuntian/rap-eacl-systems-formal-v3/runtime/cache/programasweights"
export PIP_CONFIG_FILE=/dev/null
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_FIND_LINKS="${WHEELHOUSE_ROOT}"
export PIP_NO_INDEX=1
export PIP_NO_INPUT=1
export PIP_REQUIRE_VIRTUALENV=1
export PYTHONNOUSERSITE=1
export LC_ALL=C
unset OMP_NUM_THREADS OPENBLAS_NUM_THREADS MKL_NUM_THREADS
unset VECLIB_MAXIMUM_THREADS NUMEXPR_NUM_THREADS
unset PROGRAMASWEIGHTS_CACHE_DIR

: "${RAP_EACL_ATTEMPT_ID:?set RAP_EACL_ATTEMPT_ID to a new formal-attempt slug}"
if [[ ! "${RAP_EACL_ATTEMPT_ID}" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
    echo "RAP_EACL_ATTEMPT_ID must match ^[a-z0-9][a-z0-9._-]{0,63}$" >&2
    exit 64
fi
if [[ ! "${RAP_EACL_ATTEMPT_ID}" =~ ^(.+)-r([0-9]{2})$ ]]; then
    echo "formal attempt ID must end in the exact revision suffix -rNN" >&2
    exit 64
fi
readonly ATTEMPT_REVISION_TEXT="${BASH_REMATCH[2]}"
readonly ATTEMPT_REVISION=$((10#${ATTEMPT_REVISION_TEXT}))
if (( ATTEMPT_REVISION < 1 )); then
    echo "formal attempt revision must be at least r01" >&2
    exit 64
fi
replacement_receipt="${RAP_EACL_REPLACEMENT_RECEIPT:-}"
if (( ATTEMPT_REVISION == 1 )); then
    if [[ -n "${replacement_receipt}" ]]; then
        echo "r01 requires RAP_EACL_REPLACEMENT_RECEIPT to be absent or empty" >&2
        exit 64
    fi
else
    if [[ -z "${replacement_receipt}" ]]; then
        echo "r02+ requires RAP_EACL_REPLACEMENT_RECEIPT" >&2
        exit 64
    fi
    if [[ -L "${replacement_receipt}" || ! -f "${replacement_receipt}" ]]; then
        echo "replacement receipt must be a pre-existing regular non-symlink file" >&2
        exit 66
    fi
    if [[ "${replacement_receipt##*/}" != "replacement.json" ]]; then
        echo "replacement receipt basename must be replacement.json" >&2
        exit 64
    fi
fi
readonly RAP_EACL_REPLACEMENT_RECEIPT="${replacement_receipt}"
export RAP_EACL_REPLACEMENT_RECEIPT
: "${SLURM_JOB_ID:?SLURM_JOB_ID must be supplied by a real Slurm allocation}"
if [[ ! "${SLURM_JOB_ID}" =~ ^[0-9]+$ ]]; then
    echo "SLURM_JOB_ID must be numeric for a formal launch" >&2
    exit 64
fi

readonly ATTEMPT_DIR="${RAW_ATTEMPTS_ROOT}/${RAP_EACL_ATTEMPT_ID}"
readonly NODE_RUNTIME_ROOT="/tmp/rap-eacl-systems-formal-v3-${SLURM_JOB_ID}"
readonly SOCKET_ROOT="/tmp/rf3-${SLURM_JOB_ID}"
readonly HOME_ROOT="${NODE_RUNTIME_ROOT}/home"
readonly VENV_ROOT="${NODE_RUNTIME_ROOT}/venv"
readonly SETUP_LOG="${SCHEDULER_ROOT}/${RAP_EACL_ATTEMPT_ID}-${SLURM_JOB_ID}.setup.log"
readonly SETUP_RECEIPT="${SCHEDULER_ROOT}/${RAP_EACL_ATTEMPT_ID}-${SLURM_JOB_ID}.setup-receipt.json"
readonly PIP_WHEEL="${WHEELHOUSE_ROOT}/pip-26.1.2-py3-none-any.whl"
readonly -a PACKAGE_WHEELS=(
    "${WHEELHOUSE_ROOT}/anyio-4.14.2-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/certifi-2026.7.22-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/diskcache-5.6.3-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/exceptiongroup-1.3.1-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/h11-0.16.0-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/httpcore-1.0.9-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/httpx-0.28.1-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/idna-3.19-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/jinja2-3.1.6-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/llama_cpp_python-0.3.19-cp310-cp310-linux_x86_64.whl"
    "${WHEELHOUSE_ROOT}/markupsafe-3.0.3-cp310-cp310-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
    "${WHEELHOUSE_ROOT}/numpy-2.2.6-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    "${WHEELHOUSE_ROOT}/pillow-12.3.0-cp310-cp310-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
    "${WHEELHOUSE_ROOT}/programasweights-0.4.2-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/psutil-7.2.2-cp36-abi3-manylinux2010_x86_64.manylinux_2_12_x86_64.manylinux_2_28_x86_64.whl"
    "${WHEELHOUSE_ROOT}/pystray-0.19.5-py2.py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/python_xlib-0.33-py2.py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/rules_as_programs-0.1.0-py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/six-1.17.0-py2.py3-none-any.whl"
    "${WHEELHOUSE_ROOT}/typing_extensions-4.16.0-py3-none-any.whl"
)

for required_directory in \
    "${REPO_ROOT}" \
    "${WHEELHOUSE_ROOT}" \
    "${PAW_CACHE_DIR}" \
    "${RAW_ATTEMPTS_ROOT}" \
    "${SCHEDULER_ROOT}"
do
    if [[ ! -d "${required_directory}" ]]; then
        echo "required formal directory is absent: ${required_directory}" >&2
        exit 66
    fi
done
if [[ ! -x /usr/bin/python3.10 ]]; then
    echo "formal base Python is absent or not executable: /usr/bin/python3.10" >&2
    exit 66
fi
if [[ ! -f "${RUNNER}" || ! -f "${LAUNCH_SCRIPT}" || ! -f "${RUNTIME_LOCK}" ]]; then
    echo "formal runner, launch script, or runtime lock is absent from ${REPO_ROOT}" >&2
    exit 66
fi
if [[ -e "${ATTEMPT_DIR}" ]]; then
    echo "refusing to reuse formal attempt directory: ${ATTEMPT_DIR}" >&2
    exit 73
fi
if [[ -e "${NODE_RUNTIME_ROOT}" ]]; then
    echo "refusing to reuse node-local runtime: ${NODE_RUNTIME_ROOT}" >&2
    exit 73
fi
if [[ -e "${SOCKET_ROOT}" || -L "${SOCKET_ROOT}" ]]; then
    echo "refusing to reuse node-local socket root: ${SOCKET_ROOT}" >&2
    exit 73
fi
if [[ -e "${SETUP_LOG}" || -e "${SETUP_RECEIPT}" ]]; then
    echo "refusing to replace durable setup evidence for this attempt and job" >&2
    exit 73
fi
for required_wheel in "${PIP_WHEEL}" "${PACKAGE_WHEELS[@]}"; do
    if [[ ! -f "${required_wheel}" ]]; then
        echo "required pinned wheel is absent: ${required_wheel}" >&2
        exit 66
    fi
done

/usr/bin/mkdir --mode=700 -- "${NODE_RUNTIME_ROOT}"
/usr/bin/mkdir --mode=700 -- "${SOCKET_ROOT}"
/usr/bin/mkdir --mode=700 -- "${HOME_ROOT}"
export HOME="${HOME_ROOT}"
: >"${SETUP_LOG}"

record_command_line() {
    local destination="$1"
    shift
    printf 'command=' >>"${destination}"
    printf '%q ' "$@" >>"${destination}"
    printf '\n' >>"${destination}"
}

run_setup_command() {
    local status
    record_command_line "${SETUP_LOG}" "$@"
    if "$@" >>"${SETUP_LOG}" 2>&1; then
        status=0
    else
        status=$?
    fi
    printf 'exit_status=%d\n' "${status}" >>"${SETUP_LOG}"
    return "${status}"
}

run_setup_command /usr/bin/python3.10 -m venv --without-pip "${VENV_ROOT}"
run_setup_command \
    /usr/bin/env "PYTHONPATH=${PIP_WHEEL}" \
    "${VENV_ROOT}/bin/python" -m pip install \
    --no-index --find-links "${WHEELHOUSE_ROOT}" --no-deps --upgrade "${PIP_WHEEL}"
readonly -a OFFLINE_PIP_ARGV=(
    "${VENV_ROOT}/bin/python" -m pip install \
    --no-index --find-links "${WHEELHOUSE_ROOT}" --no-deps --upgrade \
    "${PACKAGE_WHEELS[@]}"
)
run_setup_command "${OFFLINE_PIP_ARGV[@]}"
readonly IMPORT_PREFLIGHT_CODE='import importlib.metadata as m; import llama_cpp, programasweights, psutil, rules_as_programs; print({name: m.version(name) for name in ("rules-as-programs", "programasweights", "llama-cpp-python", "psutil")}); print("llama_gpu_offload_supported=", llama_cpp.llama_supports_gpu_offload())'
readonly -a IMPORT_PREFLIGHT_ARGV=(
    "${VENV_ROOT}/bin/python" -c \
    "${IMPORT_PREFLIGHT_CODE}"
)

"${VENV_ROOT}/bin/python" -c '
import datetime
import hashlib
import json
import os
import pathlib
import socket
import stat
import subprocess
import sys

receipt_path = pathlib.Path(sys.argv[1])
job_id, raw_attempt_id = sys.argv[2:4]
replacement_argument = sys.argv[4]
raw_attempts_root = pathlib.Path(sys.argv[5]).resolve(strict=True)
repo_root = pathlib.Path(sys.argv[6]).resolve(strict=True)
wheelhouse = pathlib.Path(sys.argv[7]).resolve(strict=True)
venv_executable = pathlib.Path(sys.argv[8])
base_executable = pathlib.Path(sys.argv[9]).resolve(strict=True)
setup_log = pathlib.Path(sys.argv[10]).resolve(strict=True)
node_runtime_root = pathlib.Path(sys.argv[11])
socket_root = pathlib.Path(sys.argv[12])
launch_script = pathlib.Path(sys.argv[13]).resolve(strict=True)
marker = sys.argv.index("--receipt-import-argv")
offline_pip_argv = sys.argv[14:marker]
import_preflight_argv = sys.argv[marker + 1:]

sys.path.insert(0, str(repo_root))
from experiments.eacl2027.scaling_faults_attempts import replacement_launch_binding
from experiments.eacl2027.run_scaling_faults import FORMAL_STUDY_MODE

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

replacement_chain = replacement_launch_binding(
    raw_attempts_root / raw_attempt_id,
    replacement_argument or None,
)

expected_socket_root = pathlib.Path(f"/tmp/rf3-{job_id}")
if socket_root != expected_socket_root:
    raise SystemExit(
        f"socket root must equal {expected_socket_root}, got {socket_root}"
    )
socket_root_stat = socket_root.lstat()
if (
    stat.S_ISLNK(socket_root_stat.st_mode)
    or not stat.S_ISDIR(socket_root_stat.st_mode)
    or socket_root_stat.st_uid != os.geteuid()
    or stat.S_IMODE(socket_root_stat.st_mode) != 0o700
):
    raise SystemExit(
        "socket root must be a non-symlink directory owned by the effective "
        "user with mode 0700"
    )
socket_digest_input = {
    "schema_version": 1,
    "raw_attempt_id": raw_attempt_id,
    "component": "preflight",
    "unit_id": "socket-canary",
    "retained_runtime_root": str(
        raw_attempts_root / raw_attempt_id / "runtime" / "preflight"
    ),
}
socket_digest = hashlib.sha256(
    json.dumps(
        socket_digest_input,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
).hexdigest()
socket_endpoint = socket_root / f"{socket_digest}.sock"
socket_endpoint_bytes = len(os.fsencode(socket_endpoint))
if socket_endpoint_bytes > 107 or os.path.lexists(socket_endpoint):
    raise SystemExit(
        "socket canary endpoint is too long or already exists: "
        f"{socket_endpoint_bytes} bytes at {socket_endpoint}"
    )
payload = b"rap-eacl-socket-canary-v1"
received = b""
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.settimeout(5.0)
client.settimeout(5.0)
accepted = None
try:
    server.bind(str(socket_endpoint))
    server.listen(1)
    client.connect(str(socket_endpoint))
    client.sendall(payload)
    accepted, _ = server.accept()
    accepted.settimeout(5.0)
    while len(received) < len(payload):
        chunk = accepted.recv(len(payload) - len(received))
        if not chunk:
            break
        received += chunk
finally:
    if accepted is not None:
        accepted.close()
    client.close()
    server.close()
    if os.path.lexists(socket_endpoint):
        socket_endpoint.unlink()
socket_root_fd = os.open(socket_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(socket_root_fd)
finally:
    os.close(socket_root_fd)
socket_preflight = {
    "schema_version": 1,
    "digest_input": socket_digest_input,
    "endpoint_digest": socket_digest,
    "endpoint": str(socket_endpoint),
    "encoded_pathname_bytes": socket_endpoint_bytes,
    "maximum_encoded_pathname_bytes": 107,
    "socket_root": {
        "path": str(socket_root),
        "owner_uid": socket_root_stat.st_uid,
        "mode": stat.S_IMODE(socket_root_stat.st_mode),
        "device": socket_root_stat.st_dev,
    },
    "bind_connect_accept_payload_equal": received == payload,
    "endpoint_removed_after_probe": not os.path.lexists(socket_endpoint),
}
if not socket_preflight["bind_connect_accept_payload_equal"]:
    raise SystemExit("socket canary payload mismatch")

wheelhouse_files = []
for path in sorted(wheelhouse.rglob("*")):
    if path.is_symlink():
        raise SystemExit(f"wheelhouse contains a symlink: {path}")
    if not path.is_file():
        continue
    resolved = path.resolve(strict=True)
    wheelhouse_files.append(
        {
            "path": str(path.relative_to(wheelhouse)),
            "resolved_path": str(resolved),
            "bytes": resolved.stat().st_size,
            "sha256": sha256_file(resolved),
        }
    )
canonical_inventory = json.dumps(
    wheelhouse_files, sort_keys=True, separators=(",", ":")
).encode()
import_result = subprocess.run(
    import_preflight_argv, capture_output=True, text=True, check=False
)
freeze_argv = [str(venv_executable), "-m", "pip", "freeze", "--all"]
freeze_result = subprocess.run(
    freeze_argv, capture_output=True, text=True, check=False
)
receipt = {
    "schema_version": 1,
    "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "slurm_job_id": job_id,
    "raw_attempt_id": raw_attempt_id,
    "study_mode": FORMAL_STUDY_MODE,
    "replacement_chain": replacement_chain,
    "wheelhouse_path": str(wheelhouse),
    "wheelhouse_inventory_sha256": hashlib.sha256(canonical_inventory).hexdigest(),
    "wheelhouse_files": wheelhouse_files,
    "venv_executable": str(venv_executable),
    "base_executable_resolved": str(base_executable),
    "node_runtime_root": str(node_runtime_root),
    "socket_root": str(socket_root),
    "socket_preflight": socket_preflight,
    "home": str(node_runtime_root / "home"),
    "launch_script_path": str(launch_script),
    "setup_log_path": str(setup_log),
    "setup_log_sha256": sha256_file(setup_log),
    "setup_log_content": setup_log.read_text(encoding="utf-8"),
    "offline_pip": {"argv": offline_pip_argv, "returncode": 0},
    "import_preflight": {
        "argv": import_preflight_argv,
        "returncode": import_result.returncode,
        "stdout": import_result.stdout,
        "stderr": import_result.stderr,
    },
    "pip_freeze": {
        "argv": freeze_argv,
        "returncode": freeze_result.returncode,
        "stdout": freeze_result.stdout,
        "stderr": freeze_result.stderr,
    },
}
with receipt_path.open("x", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
if import_result.returncode or freeze_result.returncode:
    raise SystemExit("node-local environment preflight failed")
' \
    "${SETUP_RECEIPT}" \
    "${SLURM_JOB_ID}" \
    "${RAP_EACL_ATTEMPT_ID}" \
    "${RAP_EACL_REPLACEMENT_RECEIPT}" \
    "${RAW_ATTEMPTS_ROOT}" \
    "${REPO_ROOT}" \
    "${WHEELHOUSE_ROOT}" \
    "${VENV_ROOT}/bin/python" \
    /usr/bin/python3.10 \
    "${SETUP_LOG}" \
    "${NODE_RUNTIME_ROOT}" \
    "${SOCKET_ROOT}" \
    "${LAUNCH_SCRIPT}" \
    "${OFFLINE_PIP_ARGV[@]}" \
    --receipt-import-argv \
    "${IMPORT_PREFLIGHT_ARGV[@]}"

export PATH="${VENV_ROOT}/bin:/usr/local/bin:/usr/bin:/bin"
export RAP_EACL_LAUNCH_SCRIPT="${LAUNCH_SCRIPT}"
export RAP_EACL_SETUP_LOG="${SETUP_LOG}"
export RAP_EACL_SETUP_RECEIPT="${SETUP_RECEIPT}"
export RAP_EACL_SOCKET_ROOT="${SOCKET_ROOT}"

cd "${REPO_ROOT}"
"${VENV_ROOT}/bin/python" "${RUNNER}" \
    --supervise \
    --formal \
    --attempt-dir "${ATTEMPT_DIR}" \
    --rule-counts 1,2,4,8 \
    --project-counts 1,4,8 \
    --burst-sizes 24,64 \
    --repeats 4 \
    --sequential-events 20 \
    --warmups-per-project 1 \
    --timeout 30 \
    --drain-timeout 1200 \
    --max-hook-workers 24 \
    --soak-events 10000 \
    --soak-rule-count 8 \
    --soak-project-count 8 \
    --soak-batch-size 64 \
    --fault-repetitions 20 \
    --faults daemon_crash,worker_exit,worker_timeout,sqlite_lock,malformed_payload,duplicate_delivery,deployment_failure
