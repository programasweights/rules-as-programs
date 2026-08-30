# EACL 2027 demonstration experiments

This directory contains the frozen, reproducible evaluation for the Rules as
Programs EACL 2027 system-demonstration paper.  It is intentionally separate
from mutable user rules and generated `.codex/` state.

The submission core uses evidence that can be reproduced without private
traces or human-subject claims:

1. a controlled contrastive benchmark with labels fixed by construction;
2. strict local PAW and deterministic-baseline scoring;
3. native-Codex trace inventory and duplicate analysis, with private text kept
   outside Git;
4. explicitly bounded hook-process, IPC, fail-open, and ingress-dedup probes;
   and
5. a deterministic finding-to-revision provenance workflow.

The controlled benchmark is not presented as a naturally distributed corpus
or as human annotation.  Native events may be used only after manual privacy
review and, if labeled, must record the real annotation procedure.

## Reproduce

Use the persistent Python environment that runs RAP:

```bash
PY=python  # after activating the persistent environment that runs RAP

$PY experiments/eacl2027/build_controlled_dataset.py
$PY experiments/eacl2027/validate_dataset.py \
  experiments/eacl2027/data/public/controlled.jsonl

$PY experiments/eacl2027/run_benchmark.py \
  --dataset experiments/eacl2027/data/public/controlled.jsonl \
  --system always-ok \
  --output experiments/eacl2027/outputs/always-ok.jsonl

$PY experiments/eacl2027/run_benchmark.py \
  --dataset experiments/eacl2027/data/public/controlled.jsonl \
  --system lexical \
  --output experiments/eacl2027/outputs/lexical.jsonl
```

The deterministic provenance workflow uses a synthetic `Stop` event and fixed
fixture judgments to exercise exact-input storage, finding and evaluation
linkage, Save-as-test, revision identity, stale-finding detection, and replay.
It tests record linkage, not judge quality or human usability. Verify that a
fresh isolated run exactly matches the frozen result with:

```bash
$PY experiments/eacl2027/run_provenance_workflow.py
```

Maintainers intentionally refreshing the frozen output use `--write` and then
rerun the command without it.

PAW runs additionally require `--system paw --compiler <compiler-name>`.
Every compilation goes through `PawRuntime`, whose compile calls explicitly set
`public=True` and `ephemeral=False`.

The independent Qwen baseline runs on a CUDA node with `torch` and
`transformers`. Pin the model to an immutable Hugging Face commit; the runner
fails rather than silently truncating a rule specification or observed input:

```bash
$PY experiments/eacl2027/run_open_judge.py \
  --dataset experiments/eacl2027/data/public/controlled.jsonl \
  --model Qwen/Qwen3-4B-Instruct-2507 \
  --revision <40-character-model-commit> \
  --output experiments/eacl2027/outputs/qwen3-4b.jsonl
```

Summaries are generated only from versioned run files:

```bash
$PY experiments/eacl2027/summarize.py \
  experiments/eacl2027/outputs/*.jsonl \
  --json experiments/eacl2027/outputs/summary.json \
  --latex experiments/eacl2027/outputs/quality-table.tex
```

## Local operational probes

The operational harness uses synthetic events and a temporary
`RAP_STATE_DIR`; it does not read native traces or contact PAW. Run it from the
repository root:

```bash
$PY experiments/eacl2027/run_operational.py \
  --output experiments/eacl2027/outputs/operational.json
```

The hook handoff timer starts in the parent immediately before the hook
subprocess launch call and stops when the local Unix-socket mock has received a
complete request. The report separately records launch-call-to-hook-exit wall
duration and mock service duration. Because normal Codex hooks are
asynchronous, none of these measurements is user-visible turn latency.

The daemon-unavailable probe exercises `hook_client.main` with an absent
socket and intercepts the subsequent daemon spawn after recording the attempt;
its timing therefore excludes interpreter startup and real daemon startup. The
deduplication probe uses injected logical timestamps and reports ingress
admission decisions only—not ledger, rule-evaluation, or PAW latency. All raw
fixtures are synthetic and temporary state is removed after the run.

## Private native-event inventory

The exporter streams the ledger corpus and never copies raw payloads.  It keeps
only the exact `Stop` or `PreToolUse` input, pseudonymizes session/turn IDs, and
writes into a Git-ignored directory:

```bash
$PY experiments/eacl2027/export_native.py \
  --ledger-dir ~/.cache/rules-as-programs/ledgers \
  --output experiments/eacl2027/data/private/native-candidates.jsonl \
  --inventory experiments/eacl2027/outputs/native-inventory.json \
  --salt LOCAL_STUDY_SALT
```

Private text must never be committed.  A public release requires manual review
and redaction of every retained input. The exporter refuses to write its raw
candidate file to a tracked or normally stageable path inside this repository.

## Frozen protocol

`protocol.json` is the frozen analysis contract. Version 1.1.0 documents the
post-smoke-test measurement-scope amendment and the addition of the independent
Qwen3-4B-Instruct-2507 baseline before the final clean-commit run. The rule
sources, inputs, labels, existing systems, primary metric, and bootstrap
procedure were unchanged. Any later change to those elements requires a new
protocol version and an explicit deviation note.
