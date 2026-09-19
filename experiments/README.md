# Experiments

Each file here is a complete configuration for a reproducible run. Point the CLI at one
with `--config`:

```bash
policyprobe --config experiments/legacy_estate.yaml all
```

Every configuration fixes its seeds, so two runs of the same file produce identical
findings, figures and report.

| Configuration | What it is for |
|---|---|
| `baseline.yaml` | The worked example in `reports/` — a mid-migration estate with mixed credential strength. |
| `legacy_estate.yaml` | A deliberately weak estate: legacy credentials, little monitoring. The lower bound for the posture score. |
| `modern_estate.yaml` | A well-run estate on current credentials. The upper bound, and the check that a good site is not penalised. |
| `high_noise.yaml` | The baseline estate read under poor conditions, to show how read quality propagates into the compliance conclusion. |
