# Repository-uniform held-out study scaffold

This is a prospective scaffold for a new study. It is not part of the frozen
EACL evidence, contains no model predictions, and does not change
`protocol.json`. Do not describe any packet, fixture, author intent, or
agent-generated response as a human label. Human data collection should begin
only after the authors obtain the appropriate institutional ethics
determination.

The implementation is `uniform_heldout.py`. Its fixed study identity is
`rap-reporails-repository-uniform-heldout-v1`; its seed is `20270902`.

## Design invariants

- The only source is `reporails/30k-corpus` commit
  `00272e946b95765654ef06fe1e7f8ae7aa7e0535`, file
  `validation_key.csv`, SHA-256
  `82dd3d2f1c02ae3e4045f4312e4c0b39c5d8f92b427b9e9da842a3e075676130`.
- Repository identity is the exact source `project` value; case and whitespace
  are preserved. Inside each project, record order is
  `SHA256(seed + NUL + "record" + NUL + project + NUL + id)`. Project order is
  `SHA256(seed + NUL + "project" + NUL + project)`. These independent formulas
  ensure that a project with more source records receives no selection
  advantage.
- All 399 exact project values are fixed in hash order and packetized into
  complete batches of 80 (the final exhaustive batch has 79). Screening stops
  after the first complete batch that yields at least 24 adjudicated eligible
  records; the first 24 eligible records in fixed order are selected. If the
  corpus is exhausted below 24, the achieved count is retained.
- Screeners evaluate whether one independent behavioral obligation exists. A
  rule atom may be extracted only when doing so does not change its meaning.
  Two independent responses must agree on the atom and observable contract;
  any disagreement is retained and requires explicit adjudication before
  authoring.
- Exclusions use the versioned taxonomy embedded in every packet.
  `other_with_required_explanation` always requires a rationale.
- Specification authors, case authors, labelers, and deterministic-baseline
  authors receive separate packets and must be different actors. Each response
  records one of `human`, `human_with_agent_assistance`, or `agent_generated`.
  A response marked `human` is rejected if it names agent/tool assistance.
- Specification and deterministic-baseline authors see no held-out inputs.
  Case authors see no specification or baseline. Labelers see one randomized
  input but not case intent, pair membership, the paired input, specification,
  baseline, other labels, or model predictions.
- Case-author polarity is `intended_expected`, not a label. Independent labels
  may confirm, reverse, or fail an intended contrast. Every case, annotation,
  disagreement, reversed pair, and failed pair remains in the private
  validation report.
- Private case and label artifacts inside this repository must live under
  `experiments/eacl2027/data/private/`, which is Git-ignored. The CLI refuses a
  normally stageable in-repository path for hidden data.
- A public hidden-data freeze contains only whole-file hashes, byte counts, and
  nonempty-line counts. A deterministic baseline freeze records exact source
  hashes and an attestation that the author used only baseline packets and saw
  no held-out input or label. An unblinding receipt is created only after both
  hidden and baseline bytes are rechecked against their freezes.

## Fixed exclusion taxonomy

The packet-local taxonomy is authoritative:

1. `cross_reference_or_incomplete_fragment`
2. `multiple_obligations_not_safely_separable`
3. `requires_multiple_events_or_order`
4. `requires_filesystem_or_artifact_state`
5. `requires_task_outcome`
6. `unsupported_or_no_scalar_trigger_field`
7. `not_behavioral_or_no_contrast`
8. `ambiguous_normative_target`
9. `sensitive_content`
10. `other_with_required_explanation` (rationale required)

## Prospective workflow

Use an isolated, persistent Python environment. Paths below are illustrative;
do not create response files until real, consented contributors perform the
assigned work.

### 1. Fix repository-uniform screening packets

```bash
python experiments/eacl2027/uniform_heldout.py select \
  --source-csv /path/to/pinned/validation_key.csv \
  --output-dir experiments/eacl2027/data/public/uniform-heldout/setup
```

This verifies the complete CSV before writing `selection-manifest.json`, the
master `screening-packets.jsonl`, and immutable per-batch packet files.
Preserve all exact files. A screening response has `packet_id`, `decision`,
`authorship`, and a rationale where required. `include` additionally has the
agreed `source_atom` and `observable_contract`; `exclude` has
`primary_exclusion`. Authorship is an object with `kind`, pseudonymous
`actor_id`, and `tools`.

Validate two independently collected responses per packet:

```bash
python experiments/eacl2027/uniform_heldout.py validate-screening \
  --packets experiments/eacl2027/data/public/uniform-heldout/setup/screening-packets.jsonl \
  --max-batch 1 \
  --responses experiments/eacl2027/data/private/uniform-heldout/screening-responses.jsonl \
  --output experiments/eacl2027/data/private/uniform-heldout/screening-report.json
```

After adjudication, inspect only `ready_for_authoring` and `stopping_reason`.
If the target is not reached, collect the next complete batch and rerun
validation over the cumulative prefix (`--max-batch 2`, then 3, and so on).
Never select or skip individual records within a batch.

Write explicit adjudications only for disagreements or uncertainty, then run:

```bash
python experiments/eacl2027/uniform_heldout.py finalize-screening \
  --screening-report experiments/eacl2027/data/private/uniform-heldout/screening-report.json \
  --adjudications experiments/eacl2027/data/private/uniform-heldout/screening-adjudications.jsonl \
  --output experiments/eacl2027/data/private/uniform-heldout/screening-finalization.json
```

### 2. Create mutually blinded authoring packets

```bash
python experiments/eacl2027/uniform_heldout.py make-authoring-packets \
  --screening-packets experiments/eacl2027/data/public/uniform-heldout/setup/screening-packets.jsonl \
  --finalization experiments/eacl2027/data/private/uniform-heldout/screening-finalization.json \
  --output-dir experiments/eacl2027/data/private/uniform-heldout/authoring
```

The command writes `spec-packets.jsonl`, `case-packets.jsonl`, and
`baseline-packets.jsonl`. The baseline file is a coordinator template: do not
distribute it until the specification response and routing choice have been
frozen and the exact frozen specification has been added to a separately
hashed baseline-author packet. The current scaffold deliberately does not
automate that human coordination step. Distribute case packets only after the
specification/routing freeze, and never place responses in a shared location.

Each case response contains exactly 8 pairs with `pair_id`,
`intended_violation_input`, `intended_ok_input`, optional rationale, and exact
authorship. Validate without converting intent into a label:

```bash
python experiments/eacl2027/uniform_heldout.py validate-cases \
  --packets experiments/eacl2027/data/private/uniform-heldout/authoring/case-packets.jsonl \
  --responses experiments/eacl2027/data/private/uniform-heldout/case-responses.jsonl \
  --output experiments/eacl2027/data/private/uniform-heldout/case-report.json
```

### 3. Blind and independently label individual inputs

```bash
python experiments/eacl2027/uniform_heldout.py make-label-packets \
  --case-packets experiments/eacl2027/data/private/uniform-heldout/authoring/case-packets.jsonl \
  --case-report experiments/eacl2027/data/private/uniform-heldout/case-report.json \
  --output experiments/eacl2027/data/private/uniform-heldout/label-packets.jsonl
```

Collect two independent labels per packet. Allowed values are `OK`, `INFO`,
`WARNING`, `CRITICAL`, and `UNSURE`. Validate them, optionally supplying a
separate adjudication file:

```bash
python experiments/eacl2027/uniform_heldout.py validate-labels \
  --packets experiments/eacl2027/data/private/uniform-heldout/label-packets.jsonl \
  --case-report experiments/eacl2027/data/private/uniform-heldout/case-report.json \
  --responses experiments/eacl2027/data/private/uniform-heldout/label-responses.jsonl \
  --adjudications experiments/eacl2027/data/private/uniform-heldout/label-adjudications.jsonl \
  --output experiments/eacl2027/data/private/uniform-heldout/label-report.json
```

The validator returns a nonzero status only for structural errors. Substantive
disagreement, `UNSURE`, reversed contrasts, and failed intended contrasts are
valid retained outcomes, not reasons to delete cases.

Check actor separation across completed response files:

```bash
python experiments/eacl2027/uniform_heldout.py validate-role-separation \
  --spec-responses experiments/eacl2027/data/private/uniform-heldout/spec-responses.jsonl \
  --case-responses experiments/eacl2027/data/private/uniform-heldout/case-responses.jsonl \
  --label-responses experiments/eacl2027/data/private/uniform-heldout/label-responses.jsonl \
  --baseline-responses experiments/eacl2027/data/private/uniform-heldout/baseline-responses.jsonl \
  --output experiments/eacl2027/data/private/uniform-heldout/role-separation-report.json
```

The report contains response hashes and pseudonymous authorship provenance,
not case or label content. Keep it private unless every contributor has agreed
to release those pseudonyms.

### 4. Freeze hidden data and deterministic baselines before unblinding

Freeze every private file that can determine study inputs or labels:

```bash
python experiments/eacl2027/uniform_heldout.py freeze-hidden \
  --file cases=experiments/eacl2027/data/private/uniform-heldout/case-report.json \
  --file labels=experiments/eacl2027/data/private/uniform-heldout/label-report.json \
  --file specs=experiments/eacl2027/data/private/uniform-heldout/spec-responses.jsonl \
  --output experiments/eacl2027/data/public/uniform-heldout/hidden-freeze.json
```

Create authorship and attestation JSON objects. The attestation must contain
exactly:

```json
{
  "authored_from_baseline_packets_only": true,
  "heldout_inputs_seen": false,
  "heldout_labels_seen": false
}
```

Freeze deterministic sources:

```bash
python experiments/eacl2027/uniform_heldout.py freeze-baseline \
  --artifact rule-a=/path/to/blinded/baseline-a.py \
  --authoring-packets experiments/eacl2027/data/private/uniform-heldout/authoring/baseline-packets.jsonl \
  --hidden-manifest experiments/eacl2027/data/public/uniform-heldout/hidden-freeze.json \
  --authorship /path/to/baseline-authorship.json \
  --attestation /path/to/baseline-attestation.json \
  --output experiments/eacl2027/data/public/uniform-heldout/baseline-freeze.json

python experiments/eacl2027/uniform_heldout.py check-baseline \
  --manifest experiments/eacl2027/data/public/uniform-heldout/baseline-freeze.json \
  --artifact rule-a=/path/to/blinded/baseline-a.py
```

Only after all freezes and role checks pass, record unblinding. This command
rechecks the exact hidden and deterministic bytes before creating the receipt:

```bash
python experiments/eacl2027/uniform_heldout.py record-unblinding \
  --hidden-manifest experiments/eacl2027/data/public/uniform-heldout/hidden-freeze.json \
  --baseline-manifest experiments/eacl2027/data/public/uniform-heldout/baseline-freeze.json \
  --hidden-file cases=experiments/eacl2027/data/private/uniform-heldout/case-report.json \
  --hidden-file labels=experiments/eacl2027/data/private/uniform-heldout/label-report.json \
  --hidden-file specs=experiments/eacl2027/data/private/uniform-heldout/spec-responses.jsonl \
  --artifact rule-a=/path/to/blinded/baseline-a.py \
  --output experiments/eacl2027/data/public/uniform-heldout/unblinding-receipt.json
```

No prediction runner is provided deliberately. Add model execution and scoring
only after the hidden-data freeze, deterministic freeze, role-separation check,
and unblinding receipt are committed as a new prospective study checkpoint.
