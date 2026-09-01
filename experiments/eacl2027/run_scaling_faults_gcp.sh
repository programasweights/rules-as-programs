#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 ATTEMPT_ID [--plan]" >&2
    exit 64
fi

readonly ATTEMPT_ID="$1"
readonly MODE="${2:-run}"
if [[ ! "${ATTEMPT_ID}" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
    echo "ATTEMPT_ID must be a lowercase filesystem-safe slug" >&2
    exit 64
fi
if [[ "${MODE}" != "run" && "${MODE}" != "--plan" ]]; then
    echo "second argument must be --plan when present" >&2
    exit 64
fi

readonly EXPERIMENT_ROOT="${RAP_EACL_GCP_ROOT:-/mnt/rap-eacl}"
readonly REPO_ROOT="${EXPERIMENT_ROOT}/repo-gcp"
readonly VENV_ROOT="${EXPERIMENT_ROOT}/venv"
readonly CACHE_ROOT="${EXPERIMENT_ROOT}/runtime/cache/formal-v3-r07-programasweights"
readonly ATTEMPTS_ROOT="${EXPERIMENT_ROOT}/attempts"
readonly RUNNER="${REPO_ROOT}/experiments/eacl2027/run_scaling_faults.py"
readonly SOCKET_PATH="/tmp/rg1-${ATTEMPT_ID}.sock"

for path in "${REPO_ROOT}" "${VENV_ROOT}" "${CACHE_ROOT}" "${ATTEMPTS_ROOT}"; do
    if [[ ! -d "${path}" ]]; then
        echo "required GCP experiment directory is absent: ${path}" >&2
        exit 66
    fi
done
if [[ ! -f "${RUNNER}" || ! -x "${VENV_ROOT}/bin/python" ]]; then
    echo "runner or Python environment is unavailable" >&2
    exit 66
fi
if [[ "$(nproc)" != "8" ]]; then
    echo "GCP protocol requires exactly 8 visible CPUs" >&2
    exit 66
fi
if (( ${#SOCKET_PATH} > 100 )); then
    echo "bounded Unix socket path exceeds 100 characters" >&2
    exit 64
fi
if [[ -e "${SOCKET_PATH}" || -L "${SOCKET_PATH}" ]]; then
    echo "socket path already exists: ${SOCKET_PATH}" >&2
    exit 73
fi

export HOME="${EXPERIMENT_ROOT}/home-${ATTEMPT_ID}"
export RAP_SOCKET_PATH="${SOCKET_PATH}"
export RAP_PAW_N_THREADS=8
export RAP_PAW_N_THREADS_BATCH=8
export PAW_CACHE_DIR="${CACHE_ROOT}"
export PAW_GPU_LAYERS=0
export CUDA_VISIBLE_DEVICES=
export OMP_NUM_THREADS=8
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export PYTHONNOUSERSITE=1
unset PROGRAMASWEIGHTS_CACHE_DIR

mkdir -p "${HOME}"
cd "${REPO_ROOT}"

readonly -a STUDY_ARGS=(
    --rule-counts 1,2,4,8
    --project-counts 1,4,8
    --burst-sizes 24,64
    --repeats 4
    --sequential-events 20
    --warmups-per-project 1
    --timeout 30
    --drain-timeout 1200
    --max-hook-workers 24
    --soak-events 10000
    --soak-rule-count 8
    --soak-project-count 8
    --soak-batch-size 64
    --fault-repetitions 20
    --faults daemon_crash,worker_exit,worker_timeout,sqlite_lock,malformed_payload,duplicate_delivery,deployment_failure
)

if [[ "${MODE}" == "--plan" ]]; then
    readonly PLAN_DIR="${EXPERIMENT_ROOT}/plans"
    mkdir -p "${PLAN_DIR}"
    exec "${VENV_ROOT}/bin/python" "${RUNNER}" \
        "${STUDY_ARGS[@]}" --plan --output "${PLAN_DIR}/${ATTEMPT_ID}.json"
fi

readonly ATTEMPT_DIR="${ATTEMPTS_ROOT}/${ATTEMPT_ID}"
if [[ -e "${ATTEMPT_DIR}" || -L "${ATTEMPT_DIR}" ]]; then
    echo "refusing to reuse attempt path: ${ATTEMPT_DIR}" >&2
    exit 73
fi
exec "${VENV_ROOT}/bin/python" "${RUNNER}" \
    "${STUDY_ARGS[@]}" --attempt-dir "${ATTEMPT_DIR}"
