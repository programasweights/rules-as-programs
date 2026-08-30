# EACL 2027 demonstration experiments

This directory contains the frozen, reproducible evaluation for the Rules as
Programs EACL 2027 system-demonstration paper.  It is intentionally separate
from mutable user rules and generated `.codex/` state.

The submission core uses evidence that can be reproduced without private
traces or human-subject claims:

1. a controlled contrastive benchmark with labels fixed by construction;
2. a narrow challenge set built from eight purposively selected, externally
   sourced instruction atoms and synthetic contrastive events;
3. strict local PAW, deterministic, and independently prompted open-model
   scoring;
4. paired comparisons over the frozen controlled predictions;
5. an installed-hook-to-query-visible-finding integration experiment;
6. native-Codex trace inventory and duplicate analysis, with private text kept
   outside Git;
7. explicitly bounded hook-process, IPC, fail-open, and ingress-dedup probes;
   and
8. a deterministic finding-to-revision provenance workflow.

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

Build and validate the selected external-instruction challenge set separately:

```bash
$PY experiments/eacl2027/build_external_dataset.py
$PY experiments/eacl2027/validate_dataset.py \
  experiments/eacl2027/data/public/external.jsonl

$PY experiments/eacl2027/run_benchmark.py \
  --dataset experiments/eacl2027/data/public/external.jsonl \
  --system always-ok \
  --output experiments/eacl2027/outputs/external-always-ok.jsonl

$PY experiments/eacl2027/run_benchmark.py \
  --dataset experiments/eacl2027/data/public/external.jsonl \
  --system lexical \
  --output experiments/eacl2027/outputs/external-lexical.jsonl
```

The instruction source is `reporails/30k-corpus` at commit
`00272e946b95765654ef06fe1e7f8ae7aa7e0535`, licensed CC BY 4.0. The checked-in
eight-record snapshot retains the exact corpus fields, raw source paths, and
physical CSV line endpoints; normalized repository paths are separate. The
events and labels are new synthetic adaptations, and several records are
explicitly narrowed to one observable sub-rule. This is neither a random nor
representative corpus sample. Specifications and cases were co-designed; the
validator forbids exact reuse of embedded specification examples, not broader
lexical overlap.

After obtaining that commit's `validation_key.csv`, verify the snapshot against
the complete pinned file without regenerating anything:

```bash
$PY experiments/eacl2027/build_external_dataset.py \
  --verify-source-csv /path/to/validation_key.csv \
  --verify-only
```

Source: <https://github.com/reporails/30k-corpus/tree/00272e946b95765654ef06fe1e7f8ae7aa7e0535>.
License: <https://creativecommons.org/licenses/by/4.0/>. RAP changes the source
records by extracting one observable instruction atom when necessary and by
authoring new synthetic event pairs and executable rule specifications; it does
not redistribute the source corpus as an unchanged benchmark.

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

Substitute `data/public/external.jsonl` and an `external-qwen3-4b.jsonl` output
for the selected-rule study. On `watgpu`, every study submission must declare
`#SBATCH --partition=ALL`; the frozen manifest and Slurm record must confirm
that partition. Pass `--require-slurm-partition ALL` so the runner fails rather
than silently accepting a job on another partition.

Controlled summaries use complete contrast-pair resampling. External primary
summaries keep all eight purposively selected rules fixed and resample complete
pairs within each rule. Hierarchical rule-then-pair resampling is exploratory
only; it must not be interpreted as population-level uncertainty. Summaries
are generated only from versioned run files:

```bash
$PY experiments/eacl2027/summarize.py \
  experiments/eacl2027/outputs/*.jsonl \
  --json experiments/eacl2027/outputs/summary.json \
  --latex experiments/eacl2027/outputs/quality-table.tex

$PY experiments/eacl2027/summarize.py \
  experiments/eacl2027/outputs/external-*.jsonl \
  --resampling stratified-rule-pair \
  --seed 20270831 \
  --json experiments/eacl2027/outputs/external-summary.json \
  --latex experiments/eacl2027/outputs/external-quality-table.tex
```

The post-hoc paired controlled comparison is independently reproducible and
byte-checks its versioned artifacts:

```bash
$PY experiments/eacl2027/analyze_paired.py
```

The publication snapshot is checked in under `outputs/frozen/`. Its
`README.md` indexes the exact clean source commit, hashes, system metrics,
hardware, and measurement boundaries. In particular, the independent Qwen run
used its immutable model commit on Slurm partition `ALL`; the manifest records
the NVIDIA L40S and software versions. Root-level output files remain ignored
scratch space so reruns cannot silently replace the frozen evidence.

## Local operational probes

The integrated experiment crosses the installed project hook wrapper, real
Unix socket, production daemon and rule loader, frozen local PAW artifact,
ledger, SQLite finding store, and verdict query API. It uses only isolated
synthetic state. Its timer begins immediately before the parent launches the
hook process and ends at the first successful query returning the exact input;
it is not Codex turn latency or rendered interface latency. Reproduce a scratch
run, or intentionally create the frozen artifact, with:

```bash
$PY experiments/eacl2027/run_integrated.py \
  --output experiments/eacl2027/outputs/integrated-scratch.json

$PY experiments/eacl2027/run_integrated.py --write-frozen
```

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

`protocol.json` is the analysis contract. Version 1.1.0 documents the
post-smoke-test measurement-scope amendment and the addition of the independent
Qwen3-4B-Instruct-2507 baseline before the final clean-commit run. The rule
sources, inputs, labels, existing systems, primary metric, and bootstrap
procedure were unchanged. Version 2.0.0 freezes the selected external-rule and
integrated-runtime studies before their first scored/final runs; it does not
retroactively describe the completed controlled study as pre-scoring. Any later
change to a frozen study element requires a new protocol version and an
explicit deviation note.
