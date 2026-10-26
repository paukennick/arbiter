# ARB-113: Workstream C CPU baseline (repository-family disjoint)

This is the first Workstream C step from
`docs/accuracy-gap-closure-plan.md`: freeze a split and measure a cheap CPU
baseline before any GPU spend.

## Data policy

- Inputs are development model labels only:
  - `tools/gold/labels/ai-corpus-model.jsonl`
  - `tools/gold/labels/gold-model.jsonl`
- Excluded by loader policy in `tools/triage_baseline.py`:
  - held-out labels (`held_out: true`)
  - ARB-109 labels (`source` starts `arb109-`)
  - calibration labels (`source` starts `calibration:`)
  - held-out rounds (`source` starts `heldout-`)
  - `unsure` labels
- No sealed set is opened; no ARB-109 data is used for training.

## Frozen split

Generated with:

```bash
python tools/triage_baseline.py split \
  --seed 113 --valid-ratio 0.25 --min-valid-families 6 \
  --out tools/gold/labels/triage/dev-split-v1.json
```

`dev-split-v1.json` freezes six validation families:

- `go-etcd`
- `py-aiohttp`
- `py-celery`
- `py-django`
- `ruby-rails`
- `ts-jose`

and sixteen training families (see the JSON for the full list).

Stats:

- train: 339 findings (248 tp, 91 fp), 31 repos, 16 families
- valid: 354 findings (290 tp, 64 fp), 6 repos, 6 families

## CPU baseline

Baseline: rule/language empirical precision with Laplace smoothing and simple
confidence adjustment. This is ranking-only; it does not create findings.

Single frozen-split run:

```bash
python tools/triage_baseline.py eval \
  --split tools/gold/labels/triage/dev-split-v1.json \
  --json tools/gold/labels/triage/dev-cpu-baseline-v1.json
```

- average precision: 0.980
- precision@10 / @20 / @50 / @100: 1.000
- validation base rate: 0.819

5-fold family CV (same label pool):

```bash
python tools/triage_baseline.py cv \
  --folds 5 --seed 113 \
  --json tools/gold/labels/triage/dev-cpu-baseline-cv-v1.json
```

- pooled average precision: 0.976
- fold mean AP: 0.955, min 0.860, max 0.997

Interpretation: the baseline is already strong on this development pool, so a
GPU model must beat this with clear margin on the same split before any cloud
spend is justified.

## Next gate

Before any RunPod training:

1. Add a dependency requirement for `torch` and the chosen code model package.
2. Define a fixed success bar against this CPU baseline (for example AP and
   precision@k deltas, with uncertainty).
3. Keep ARB-109 labels as one-shot evaluation only, never training data.
