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

`operational.json` contains synthetic hook/IPC, unavailable-daemon, and ingress
deduplication probes, together with its own clean source revision.
`provenance-workflow.json` contains the deterministic
15-assertion backend provenance trace. `native-inventory.json` contains only
aggregate counts; raw native event text remains private and Git-ignored.

The latency fields have different boundaries. PAW records warmed sequential
judge calls; Qwen records amortized batch-generation wall time; the operational
probe records hook-process and local-socket boundaries. They must not be
treated as directly comparable end-to-end agent latencies.
