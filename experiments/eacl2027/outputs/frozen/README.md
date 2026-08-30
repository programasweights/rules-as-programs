# Frozen EACL 2027 evidence

This directory contains the completed protocol-1.1.0 controlled study and the
protocol-2.0.0 expansion. The latter adds a selected external-instruction
challenge set and an installed-hook-to-query-visible-finding experiment. The
latency boundaries differ and are not interchangeable.

## Controlled study (protocol 1.1.0)

All five controlled quality runs were executed from clean implementation commit
`91dbb03d6d332678e717bf8f0640110ae1f40402` on the 192-case controlled dataset
with SHA-256
`ce72bb8ef5d8220c73a00974c2107117442c891694c06ecca970f8056f376561`.

| System | Precision | Recall | Macro-F1 | Exact accuracy |
| --- | ---: | ---: | ---: | ---: |
| Always OK | 0.000 | 0.000 | 0.000 | 0.500 |
| Rule-specific lexical diagnostic | 0.987 | 0.771 | 0.863 | 0.880 |
| PAW standard | 0.804 | 0.854 | 0.831 | 0.823 |
| PAW finetuned | 0.923 | 1.000 | 0.961 | 0.958 |
| Qwen3-4B-Instruct-2507 | 0.721 | 0.969 | 0.839 | 0.797 |

`summary.json` contains per-rule metrics, 5,000-sample paired-cluster bootstrap
intervals, and latency summaries. Each JSONL run has a sidecar manifest with
its output hash, exact Git state, package versions, and model or compiler
identity. The Qwen run used model commit
`cdbee75f17c01a7cc42f958dc650907174af0554`, deterministic decoding, no input
truncation, and zero invalid outputs or runtime errors. It ran as Slurm job
`1523653` on partition `ALL` with an NVIDIA L40S, PyTorch 2.9.1+cu130, and
Transformers 4.57.6.

`paired-comparisons-v1.json` is a separately marked post-hoc analysis of these
already frozen predictions. Relative to Qwen3-4B, finetuned PAW is +0.1224
macro-F1 (paired 95% interval [0.0858, 0.1585]) and +0.1615 exact accuracy
([0.1042, 0.2135]); the exact-label cluster randomization test has Holm-adjusted
$p=4.20\times10^{-7}$. Relative to the lexical diagnostic, the corresponding
deltas are +0.0982 ([0.0426, 0.1692]) and +0.0781 ([0.0260, 0.1302]), with
Holm-adjusted $p=.00813$. The tests swap system labels only within complete
two-case contrast pairs. `paired-disagreements-v1.jsonl` inventories every
public case with a prediction disagreement or exact-label error. These analyses
condition on the fixed author-constructed cases and do not represent
author-sampling uncertainty.

## Selected external instructions (protocol 2.0.0)

The frozen challenge set has 160 synthetic cases (80 complete contrastive
pairs) for eight purposively selected instruction atoms, one per repository.
The instruction text comes from `reporails/30k-corpus` at commit
`00272e946b95765654ef06fe1e7f8ae7aa7e0535`; the pinned source CSV has SHA-256
`82dd3d2f1c02ae3e4045f4312e4c0b39c5d8f92b427b9e9da842a3e075676130`.
The checked-in eight-record source snapshot has SHA-256
`c949c3b2607d7f56b0f9cafb7e80869f403f1f5cd3bbed698d5f460105ac8919`,
and the generated case file has SHA-256
`111272280d28c8a7c5e42d8d7b202250ab115e32684715ebba06f1bdf2b6d0ae`.
This is not a random or prevalence sample, and the specifications and synthetic
cases were co-designed. Two source records are represented by explicitly
documented one-field sub-rules.

The completed runs below were produced from clean commit
`9658dde232a3ff1bc39e29e2e73df11d0dbd0fca`. Macro-F1 is the mean positive-class
F1 across the eight fixed rules; the other quality columns are pooled precision,
pooled recall, and exact-label accuracy.

| System | Precision | Recall | Macro-F1 | Exact accuracy |
| --- | ---: | ---: | ---: | ---: |
| Always OK | 0.000 | 0.000 | 0.000 | 0.500 |
| Rule-specific lexical diagnostic | 1.000 | 0.988 | 0.993 | 0.994 |
| PAW standard | 0.821 | 0.863 | 0.840 | 0.838 |
| PAW finetuned | 0.949 | 0.938 | 0.946 | 0.944 |
| Qwen3-4B-Instruct-2507 | 0.795 | 0.875 | 0.845 | 0.819 |

All five runs contain all 160 cases with zero invalid outputs and zero runtime
errors. Their output SHA-256 values are:

- `external-always-ok.jsonl`: `6db2a8a46dca0d0067f026fa051d877573e664b2f57b69905d54d2b7010eac3a`
- `external-lexical.jsonl`: `e5c7e8dfa7598ebd4dee7c596dc545f97f3aa087d21849f08cdcf1c213d7425b`
- `external-paw-standard.jsonl`: `08824e35c8466096ea1a205d7114128dd74cedb050a55b7b2fa4c4bd4710dedd`
- `external-paw-finetuned.jsonl`: `8bd307e7fe7de266e7ec154de5bec8fee73918ebf9ca5a9878ad1f55757d2888`
- `external-qwen3-4b.jsonl`: `ea11fab85d8b57cef3a8089bf427c7a8a5d3cddd793ab779188ab9f3deba4a35`

The lexical diagnostic is bespoke author-written code with rule-specific
regular expressions, path checks, and structured-field logic for these eight
frozen intents and input formats. It is neither generic nor learned, and it was
developed alongside the synthetic cases. Its near-perfect result therefore
measures the selected set's susceptibility to hand-engineered deterministic
logic, not out-of-domain generalization. The Qwen run used model commit
`cdbee75f17c01a7cc42f958dc650907174af0554`, deterministic decoding without
input truncation, and Slurm job `1523668` on partition `ALL` with an NVIDIA
L40S. Preliminary jobs `1523666` and `1523667` failed during environment setup
before model preparation or case scoring; the complete replacement run is the
only Qwen result summarized here.

`external-summary.json` contains the five-system metrics and fixed-rule,
within-rule pair-bootstrap intervals from 5,000 resamples with seed `20270831`.
Its SHA-256 is
`4fe46a3dc2776c36489d498c905a67a2118be086b57a8aea0b217237d1b1e2a3`.
The Qwen judge's principal error concentration is the source-page title rule
(12 of its 29 errors); it is perfect on the package-manager and AI-credit
rules. These patterns are descriptive for the eight fixed rules and are not a
population-level comparison.

The PAW per-case latency fields measure warmed, sequential direct judge calls
after all eight programs were prepared. They exclude compilation, the Codex
hook, daemon/store work, and UI rendering. The lexical and Always-OK timings are
harness function-call timings and are not deployment latency baselines.

## Installed production path (protocol 2.0.0)

`integrated.json` was produced from the same clean commit `9658dde...` and has
SHA-256
`14f6a6b9becb00f54bd0228cbef7353aecf01e7a6d82cf5db39368bf57852d44`.
It pins rule `78v34vpkzm2jp4rx`, compiler `paw-ft-bs48`, compiler snapshot
`paw-ft-bs48-20260530`, and program `b619825b8bc23bab4c07`.

The latency clock starts in the experiment parent immediately before it
synchronously launches the exact installed project hook wrapper. It stops after
the first successful daemon verdict query returns a finding with the exact
evaluated input. Thus it includes wrapper startup, normalization, local-socket
handoff, ledger append, rule loading/matching, local PAW inference, SQLite
persistence, and 5 ms polling queries. It excludes Codex's scheduling of its
normally asynchronous hook, remote compilation, and menu-bar rendering or human
perception; it is not Codex turn latency or rendered UI latency.

| Load | Findings | Query-visible p50 | Query-visible p95 | Maximum | Loss |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sequential | 30 | 264.472 ms | 283.586 ms | 304.795 ms | 0 |
| 24-event burst | 24 | 1851.100 ms | 3058.529 ms | 3185.628 ms | 0 |

Sequential and burst hook-process-exit p95 values were 209.303 ms and
1226.698 ms, respectively. The burst drained in 3.414 s (7.031 findings/s).
Across three excluded warmups, the two measured loads, one admitted duplicate
probe, and two recovery probes, all 60 expected exact inputs produced exactly
60 findings, with zero missing, duplicate, or unexpected findings.

For two identical deliveries, the daemon's ingress-duplicate counter increased
by one and exactly one finding was stored. This is evidence for that bounded
redelivery probe, not a general exactly-once guarantee. After the isolated PAW
worker was terminated, the next event produced a finding in 1485.995 ms with a
distinct worker PID. After the old daemon was stopped and a replacement daemon
became ping-ready, the next event produced a finding in 1209.532 ms; this field
does not include daemon startup time.

Resource measurements cover only the daemon and its recursive child processes.
Warm-idle RSS was 1,111,457,792 bytes and peak sampled RSS was 1,238,646,784
bytes, using 20 ms sampling during the burst plus boundary snapshots. The
daemon tree consumed 4.109 CPU seconds between the pre-sequential and
post-burst snapshots.

## Earlier operational and provenance probes

`operational.json` contains synthetic hook/IPC, unavailable-daemon, and ingress
deduplication probes. It was produced from clean source revision `0b21e08` and
has SHA-256
`10547ae8ab6a2a2cca00ff653228070711f911eb863429d8d1cdb6032559cb51`.
`provenance-workflow.json` contains the deterministic
15-assertion backend provenance trace. `native-inventory.json` contains only
aggregate counts; raw native event text remains private and Git-ignored.

Across this directory, PAW quality runs record warmed sequential judge calls,
Qwen records amortized batch-generation wall time, the earlier operational
probe records narrower hook-process and local-socket boundaries, and the
integrated run records installed-wrapper-to-query-visible-finding latency. They
must not be treated as directly comparable end-to-end agent latencies.
