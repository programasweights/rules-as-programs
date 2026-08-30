# Frozen EACL 2027 evidence

These files are the publication snapshot for protocol 1.1.0. All five quality
runs were executed from clean implementation commit
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

`operational.json` contains synthetic hook/IPC, unavailable-daemon, and ingress
deduplication probes. It was produced from clean source revision `0b21e08` and
has SHA-256
`10547ae8ab6a2a2cca00ff653228070711f911eb863429d8d1cdb6032559cb51`.
`provenance-workflow.json` contains the deterministic
15-assertion backend provenance trace. `native-inventory.json` contains only
aggregate counts; raw native event text remains private and Git-ignored.

The latency fields have different boundaries. PAW records warmed sequential
judge calls; Qwen records amortized batch-generation wall time; the operational
probe records hook-process and local-socket boundaries. They must not be
treated as directly comparable end-to-end agent latencies.
