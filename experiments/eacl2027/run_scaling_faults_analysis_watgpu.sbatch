#!/bin/bash
#SBATCH --job-name=rap-eacl-analysis-v3
#SBATCH --partition=ALL
#SBATCH --nodelist=watgpu108
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --chdir=/u4/yuntian/rap-eacl-systems-formal-v3/repo
#SBATCH --output=/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/%x-%j.stdout.log
#SBATCH --error=/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/%x-%j.stderr.log
#SBATCH --export=NONE

# Exactly three positional arguments are required:
#   1. the immutable attempts root containing the exact r01/r02 ledger
#   2. a new analysis ID
#   3. a new evidence-bundle directory outside Git

set -euo pipefail
umask 077

if (( $# != 3 )); then
    echo "usage: sbatch $0 ATTEMPTS_ROOT ANALYSIS_ID NEW_BUNDLE_OUTPUT" >&2
    exit 64
fi

readonly ATTEMPTS_ROOT="$1"
readonly ANALYSIS_ID="$2"
readonly BUNDLE_OUTPUT="$3"
readonly FORMAL_ROOT="/u4/yuntian/rap-eacl-systems-formal-v3"
readonly REPO_ROOT="${FORMAL_ROOT}/repo"
readonly WHEELHOUSE_ROOT="${FORMAL_ROOT}/runtime/wheelhouse"
readonly RUNTIME_LOCK="${REPO_ROOT}/experiments/eacl2027/formal-runtime-lock-v3.json"
readonly BASE_PYTHON="/usr/bin/python3.10"
readonly H3_COMMIT="efea2a704433602fdfa159429ba7b4620b22fc62"
readonly H3_ROOT_TREE_GIT_SHA1="d2bd96663a8f3aac144fec74738c86ae720539a0"
readonly H3_EXPERIMENTS_TREE_GIT_SHA1="f098ebb90df90dd349c9fb8ec3689cda19035087"
readonly H3_EXPERIMENTS_INVENTORY_SHA256="383b1bbf033a6237a24de3115c68f73499e1428d130373e8c557761e6fbecd0f"

: "${SLURM_JOB_ID:?a real Slurm allocation is required}"
: "${SLURM_JOB_PARTITION:?Slurm partition receipt is required}"
if [[ ! "${SLURM_JOB_ID}" =~ ^[0-9]+$ ]]; then
    echo "SLURM_JOB_ID must be numeric" >&2
    exit 64
fi
if [[ "${SLURM_JOB_PARTITION}" != "ALL" ]]; then
    echo "formal analysis requires partition ALL" >&2
    exit 64
fi
if [[ ! -x "${BASE_PYTHON}" ]]; then
    echo "required Python is absent: ${BASE_PYTHON}" >&2
    exit 66
fi
if [[ ! -d "${REPO_ROOT}" || ! -d "${WHEELHOUSE_ROOT}" ]]; then
    echo "formal repository or locked wheelhouse is absent" >&2
    exit 66
fi
if [[ -L "${RUNTIME_LOCK}" || ! -f "${RUNTIME_LOCK}" ]]; then
    echo "formal runtime lock is absent or a symlink" >&2
    exit 66
fi

readonly NODE_ROOT="/tmp/rap-eacl-analysis-${SLURM_JOB_ID}"
readonly VENV_ROOT="${NODE_ROOT}/venv"
readonly GUARD_ROOT="${NODE_ROOT}/network-guard"
readonly SNAPSHOT_WHEELHOUSE="${NODE_ROOT}/wheelhouse"
readonly WHEEL_LIST="${NODE_ROOT}/locked-wheels.txt"
readonly H3_SOURCE_ROOT="${NODE_ROOT}/h3-source"
if [[ -e "${NODE_ROOT}" || -L "${NODE_ROOT}" ]]; then
    echo "refusing to reuse node-local analysis runtime: ${NODE_ROOT}" >&2
    exit 73
fi
/usr/bin/mkdir --mode=700 -- "${NODE_ROOT}"
/usr/bin/mkdir --mode=700 -- "${GUARD_ROOT}"
/usr/bin/mkdir --mode=700 -- "${SNAPSHOT_WHEELHOUSE}"
/usr/bin/mkdir --mode=700 -- "${H3_SOURCE_ROOT}"

cleanup_node_root() {
    /usr/bin/chmod -R u+w -- "${NODE_ROOT}" 2>/dev/null || true
    /usr/bin/rm -rf -- "${NODE_ROOT}"
}
trap cleanup_node_root EXIT

export PATH="/usr/local/bin:/usr/bin:/bin"
export HOME="${NODE_ROOT}/home"
/usr/bin/mkdir --mode=700 -- "${HOME}"
export LC_ALL=C
export PYTHONNOUSERSITE=1
export PIP_CONFIG_FILE=/dev/null
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_FIND_LINKS="${WHEELHOUSE_ROOT}"
export PIP_NO_INDEX=1
export PIP_NO_INPUT=1
export PIP_REQUIRE_VIRTUALENV=1
export CUDA_VISIBLE_DEVICES=
export PAW_GPU_LAYERS=0
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy NO_PROXY no_proxy

# Materialize the exact H3 experiments tree into a node-local, read-only source
# root.  It intentionally contains no working-tree rules_as_programs package;
# analyzer imports therefore resolve RAP only from the locked installed wheel.
if [[ "$(/usr/bin/git -C "${REPO_ROOT}" rev-parse --verify "${H3_COMMIT}^{commit}")" != "${H3_COMMIT}" ]]; then
    echo "H3 commit object is unavailable" >&2
    exit 66
fi
if [[ "$(/usr/bin/git -C "${REPO_ROOT}" rev-parse "${H3_COMMIT}^{tree}")" != "${H3_ROOT_TREE_GIT_SHA1}" ]]; then
    echo "H3 root tree identity mismatch" >&2
    exit 66
fi
if [[ "$(/usr/bin/git -C "${REPO_ROOT}" rev-parse "${H3_COMMIT}:experiments")" != "${H3_EXPERIMENTS_TREE_GIT_SHA1}" ]]; then
    echo "H3 experiments tree identity mismatch" >&2
    exit 66
fi
/usr/bin/git -C "${REPO_ROOT}" archive --format=tar "${H3_COMMIT}" experiments \
    | /bin/tar -xf - -C "${H3_SOURCE_ROOT}"

"${BASE_PYTHON}" - "${H3_SOURCE_ROOT}" "${H3_EXPERIMENTS_INVENTORY_SHA256}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
expected_inventory = sys.argv[2]
if sorted(item.name for item in root.iterdir()) != ["experiments"]:
    raise SystemExit("H3 source snapshot top-level inventory mismatch")
receipts = []
directories = []
for current, directory_names, file_names in os.walk(root, followlinks=False):
    current_path = pathlib.Path(current)
    directories.append(current_path)
    for name in sorted(directory_names):
        child = current_path / name
        info = child.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SystemExit(f"H3 source snapshot has an unsafe directory: {child}")
    for name in sorted(file_names):
        path = current_path / name
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"H3 source snapshot has an unsafe file: {path}")
        digest = hashlib.sha256()
        byte_count = 0
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
            closed = os.fstat(handle.fileno())
        if (
            opened.st_dev != closed.st_dev
            or opened.st_ino != closed.st_ino
            or opened.st_size != closed.st_size
            or byte_count != closed.st_size
        ):
            raise SystemExit(f"H3 source file changed while hashing: {path}")
        receipts.append(
            {
                "path": str(path.relative_to(root)),
                "bytes": byte_count,
                "sha256": digest.hexdigest(),
            }
        )
receipts.sort(key=lambda item: item["path"])
inventory = hashlib.sha256(
    json.dumps(receipts, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
if (
    len(receipts) != 102
    or sum(item["bytes"] for item in receipts) != 3_993_510
    or inventory != expected_inventory
):
    raise SystemExit("H3 source snapshot complete inventory mismatch")
for receipt in receipts:
    path = root / receipt["path"]
    os.chmod(path, 0o400, follow_symlinks=False)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
    os.chmod(directory, 0o500, follow_symlinks=False)
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PY

# Validate every locked wheel before creating the fresh venv.  The module will
# independently revalidate the runtime-lock bytes and all scientific sources.
"${BASE_PYTHON}" - "${RUNTIME_LOCK}" "${WHEELHOUSE_ROOT}" "${WHEEL_LIST}" "${SNAPSHOT_WHEELHOUSE}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

lock_path = pathlib.Path(sys.argv[1])
wheelhouse = pathlib.Path(sys.argv[2]).resolve(strict=True)
destination = pathlib.Path(sys.argv[3])
snapshot = pathlib.Path(sys.argv[4]).resolve(strict=True)
lock = json.loads(lock_path.read_text(encoding="utf-8"))
if lock.get("schema_version") != 1:
    raise SystemExit("runtime lock schema mismatch")
declared = lock.get("wheelhouse")
if not isinstance(declared, dict) or declared.get("root") != str(wheelhouse):
    raise SystemExit("runtime lock wheelhouse root mismatch")
files = declared.get("files")
if not isinstance(files, list) or len(files) != declared.get("file_count"):
    raise SystemExit("runtime lock wheel inventory shape mismatch")
total = 0
for item in files:
    if not isinstance(item, dict) or set(item) != {
        "bytes", "path", "resolved_path", "sha256"
    }:
        raise SystemExit("runtime lock wheel entry shape mismatch")
    path = wheelhouse / item["path"]
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"locked wheel is not a regular non-symlink file: {path}")
    if str(path.resolve(strict=True)) != item["resolved_path"]:
        raise SystemExit(f"locked wheel resolved path mismatch: {path}")
    digest = hashlib.sha256()
    byte_count = 0
    copied = snapshot / item["path"]
    copied_fd = os.open(copied, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(copied_fd, view)
                    if written <= 0:
                        raise SystemExit(f"short wheel snapshot write: {copied}")
                    view = view[written:]
            closed = os.fstat(handle.fileno())
        os.fsync(copied_fd)
        os.fchmod(copied_fd, 0o400)
        copied_info = os.fstat(copied_fd)
    finally:
        os.close(copied_fd)
    if (
        opened.st_dev != closed.st_dev
        or opened.st_ino != closed.st_ino
        or opened.st_size != closed.st_size
        or byte_count != closed.st_size
    ):
        raise SystemExit(f"locked wheel changed while snapshotting: {path}")
    if byte_count != item["bytes"] or digest.hexdigest() != item["sha256"]:
        raise SystemExit(f"locked wheel identity mismatch: {path}")
    if copied_info.st_size != byte_count:
        raise SystemExit(f"snapshotted wheel size mismatch: {copied}")
    total += byte_count
if total != declared.get("total_bytes"):
    raise SystemExit("runtime lock wheelhouse total mismatch")
inventory = hashlib.sha256(
    json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
if inventory != declared.get("inventory_sha256"):
    raise SystemExit("runtime lock wheelhouse inventory hash mismatch")
live_entries = sorted(wheelhouse.iterdir(), key=lambda item: item.name)
if any(
    entry.is_symlink() or not stat.S_ISREG(entry.lstat().st_mode)
    for entry in live_entries
):
    raise SystemExit("live wheelhouse contains a non-regular or symlink entry")
if [entry.name for entry in live_entries] != sorted(item["path"] for item in files):
    raise SystemExit("live wheelhouse contains missing or extra files")
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    for item in files:
        handle.write(str(snapshot / item["path"]) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
snapshot_fd = os.open(snapshot, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(snapshot_fd)
finally:
    os.close(snapshot_fd)
PY

mapfile -t LOCKED_WHEELS <"${WHEEL_LIST}"
if (( ${#LOCKED_WHEELS[@]} != 21 )); then
    echo "locked wheel list must contain exactly 21 files" >&2
    exit 66
fi
PIP_WHEEL=""
for wheel in "${LOCKED_WHEELS[@]}"; do
    if [[ "${wheel##*/}" == pip-*.whl ]]; then
        PIP_WHEEL="${wheel}"
    fi
done
if [[ -z "${PIP_WHEEL}" ]]; then
    echo "locked pip wheel is absent" >&2
    exit 66
fi
export PIP_FIND_LINKS="${SNAPSHOT_WHEELHOUSE}"

"${BASE_PYTHON}" -m venv --without-pip "${VENV_ROOT}"
PYTHONPATH="${PIP_WHEEL}" "${VENV_ROOT}/bin/python" -m pip install \
    --no-index --no-deps --upgrade "${PIP_WHEEL}"
"${VENV_ROOT}/bin/python" -m pip install \
    --no-index --no-deps --upgrade "${LOCKED_WHEELS[@]}"

# This guard blocks Python IPv4/IPv6 connection APIs in the runner and reducer.
# Its exact bytes are carried in RAP_ANALYSIS_NETWORK_GUARD and environment.json.
"${BASE_PYTHON}" - "${GUARD_ROOT}/sitecustomize.py" <<'PY'
import os
import pathlib
import sys

source = '''import errno
import socket

_original_socket = socket.socket

def _deny(*args, **kwargs):
    raise PermissionError(errno.EPERM, "formal analysis Python network guard")

class _GuardedSocket(_original_socket):
    def connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            return _deny(address)
        return super().connect(address)

    def connect_ex(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            return _deny(address)
        return super().connect_ex(address)

    def sendto(self, *args, **kwargs):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            return _deny(*args, **kwargs)
        return super().sendto(*args, **kwargs)

socket.socket = _GuardedSocket
socket.create_connection = _deny
socket.getaddrinfo = _deny
socket.gethostbyname = _deny
socket.gethostbyname_ex = _deny
socket.gethostbyaddr = _deny
'''
path = pathlib.Path(sys.argv[1])
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(source)
    handle.flush()
    os.fsync(handle.fileno())
PY

GUARD_SHA256="$(/usr/bin/sha256sum "${GUARD_ROOT}/sitecustomize.py" | /usr/bin/awk '{print $1}')"
readonly GUARD_SHA256
export RAP_ANALYSIS_NETWORK_GUARD="python-inet-deny-v1:${GUARD_SHA256}"
export RAP_ANALYSIS_H3_SOURCE_ROOT="${H3_SOURCE_ROOT}"
export PYTHONPATH="${GUARD_ROOT}:${REPO_ROOT}"

"${VENV_ROOT}/bin/python" -c \
    'import socket; raise SystemExit(0 if socket.create_connection.__module__ == "sitecustomize" else 1)'

set +e
"${VENV_ROOT}/bin/python" -m \
    experiments.eacl2027.run_scaling_faults_analysis_bundle \
    "${ATTEMPTS_ROOT}" "${ANALYSIS_ID}" "${BUNDLE_OUTPUT}"
status=$?
set -e
exit "${status}"
