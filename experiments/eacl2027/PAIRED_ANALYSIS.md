# Post-hoc paired comparison analysis

`analyze_paired.py` performs a separate, explicitly post-hoc comparison of the
already frozen finetuned-PAW, Qwen3-4B, and lexical predictions. It does not
change protocol 1.1.0, any original run, its sidecar, or `summary.json`.

Before doing any analysis or write, the script verifies:

- the controlled-dataset manifest and its embedded rule-source hashes;
- that the dataset, frozen runs, and sidecars are tracked and match `HEAD`;
- every run's output hash, manifest fields, exact case signatures, clean source
  Git provenance, and shared source commit;
- the finetuned PAW compiler identity; and
- the immutable Qwen model revision.

It then uses the same 5,000 `pair_id` cluster draws for both systems in each
comparison and reports percentile intervals for finetuned PAW minus comparator
macro-F1 and exact accuracy. Exact-label and binary-detection correctness also
receive two-sided exact randomization tests that swap system labels only within
complete two-case contrast-pair clusters.

A case-level McNemar test is intentionally not used because its
independent-case assumption would ignore the contrast-pair clustering. There
is no exact test for the non-additive macro-F1 statistic. The Qwen comparison
is primary and lexical is secondary. Exact-test p-values nevertheless receive
a Holm correction across the two declared comparators, separately for
exact-label and binary-detection correctness. These analyses condition on the
fixed author-constructed cases and do not address author-sampling uncertainty.

## Reproduce or create the versioned outputs

From the repository root, recompute and verify both checked-in artifacts
without modifying them:

```bash
python experiments/eacl2027/analyze_paired.py
```

The command fails if recomputed bytes differ. In a checkout where the artifacts
are absent, create them only after all provenance checks pass:

```bash
python experiments/eacl2027/analyze_paired.py --write
```

The two versioned outputs are:

- `outputs/frozen/paired-comparisons-v1.json`, containing provenance, methods,
  point differences, intervals, discordance counts, and exact tests; and
- `outputs/frozen/paired-disagreements-v1.jsonl`, containing every public
  controlled case with any prediction disagreement or exact-label error,
  including each system's prediction and correctness flags.

The summary hashes the inventory, analysis script, dataset, every input run,
and every input sidecar. It also records protocol 1.1.0 as historical metadata,
anchored by its original hash and artifact commit; the current `protocol.json`
is not a live input, so later protocols cannot invalidate this post-hoc
analysis. Existing versioned files are never overwritten with different bytes.
