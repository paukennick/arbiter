# Fact check: `supply.unpinned-action` labels (ARB-176)

Truth: `label_models.fact_truth` reads the flagged `uses:` line at the pinned commit; a full
40-character SHA means fp, a tag or branch means tp. Repositories fetched at the commits in
`tools/fetch_corpus.sh` and `tools/fetch_heldout_r5.sh`. Totals only.

| label file | held out | labels | no fact | model tp, fact tp | disagreements |
|---|---|---:|---:|---:|---:|
| gold-model | no | 169 | 0 | 169 | 0 |
| gold-model | yes | 31 | 0 | 31 | 0 |
| heldout-r5-model | yes | 500 | 0 | 500 | 0 |
| **total** | | **700** | **0** | **700** | **0** |

Labeller `tp` calls right: 700/700, Wilson 95% lower bound 0.9945. Cost: none (no model calls).
