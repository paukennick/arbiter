#!/usr/bin/env bash
#
# One training cycle. Safe to run over and over — each run adds to what came
# before rather than starting fresh, because the results live in the repo.
#
#   ./tools/train_cycle.sh              # normal run
#   ./tools/train_cycle.sh 40000        # more trials
#   PUSH=1 ./tools/train_cycle.sh       # also commit and push the results
#
# What it does, in order:
#   1. makes sure the practice repositories are downloaded
#   2. runs every rule against them and records what it found
#   3. measures whether each rule tells good code from broken code
#   4. plants known faults and checks the rules catch them
#   5. checks the tool never claims something it didn't actually check
#   6. runs the test suite, then writes training/WORKLIST.md -- what to look
#      at next, and why
#   7. optionally saves the results back to the repo
#
# It measures. It never edits a rule. Deciding what a result means is the part
# that needs judgement, and WORKLIST.md is the handoff to whoever does that.
#
set -euo pipefail

TRIALS="${1:-20000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="${CORPUS:-/tmp/corpus}"
RESULTS="$ROOT/training"
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

cd "$ROOT"
mkdir -p "$RESULTS" .arbiter

echo "==> 1/8  practice repositories"
if [ ! -d "$CORPUS" ] || [ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
  echo "    downloading (first run only, a few minutes)"
  bash "$ROOT/tools/fetch_corpus.sh" "$CORPUS"
else
  echo "    already present: $(ls -1 "$CORPUS" | wc -l) repositories"
fi

echo "==> 2/8  running every rule against them"
python tools/corpus.py --root "$CORPUS" --out "$RESULTS/corpus-$STAMP" \
  | tee "$RESULTS/corpus-$STAMP.txt" | tail -20

echo "==> 3/8  measuring whether each rule separates good code from broken code"
python tools/discriminate.py --root "$CORPUS" \
  --out "$RESULTS/discriminate-$STAMP.json" \
  | tee "$RESULTS/discriminate-$STAMP.txt" | tail -24

echo "==> 3b/8  measuring the external tools' own checks"
# Only when the tools are actually installed. A missing analyzer is a coverage
# fact the scan already records; it is not a reason to fail the cycle.
if command -v checkov >/dev/null 2>&1 || command -v bandit >/dev/null 2>&1; then
  python tools/calibrate_external.py --root "$CORPUS" \
    --out "$RESULTS/external-severity-$STAMP.json" \
    | tee "$RESULTS/external-$STAMP.txt" | tail -20
  cp "$RESULTS/external-severity-$STAMP.json" .arbiter/external-severity.json
else
  echo "    no external analyzers installed — skipped"
fi

echo "==> 4/8  planting known faults ($TRIALS trials)"
python tools/inject.py --corpus "$CORPUS" --trials "$TRIALS" \
  --knowledge .arbiter/knowledge.json \
  | tee "$RESULTS/injection-$STAMP.txt" | tail -24

echo "==> 5/8  checking the tool never overclaims"
python tools/integrity.py --probes 5 | tee "$RESULTS/integrity-$STAMP.txt" | tail -12

echo "==> 6/8  test suite"
python -m pytest tests/ -q | tail -3

echo "==> 7/8  working out what to do next"
python tools/worklist.py \
  --corpus-summary "$RESULTS/corpus-$STAMP/summary.json" \
  --discrimination "$RESULTS/discriminate-$STAMP.json" \
  --out "$RESULTS/WORKLIST.md"

echo "==> 8/8  results"
if [ "${PUSH:-0}" = "1" ]; then
  git add -A .arbiter training
  if git diff --cached --quiet; then
    echo "    nothing changed"
  else
    git commit -q -m "training run $STAMP ($TRIALS trials)"
    git push -q origin HEAD && echo "    pushed"
  fi
else
  echo "    saved under training/ — set PUSH=1 to commit and push"
fi

echo
echo "Done. Summary of what the tool now knows:"
python - <<'PY'
import json, pathlib
p = pathlib.Path(".arbiter/knowledge.json")
if not p.is_file():
    raise SystemExit("  (no knowledge file yet)")
k = json.loads(p.read_text())
rules = k.get("rules", {})
planted = sum(r.get("synthetic_detected", 0) + r.get("synthetic_missed", 0) for r in rules.values())
controls = sum(r.get("synthetic_clean_pass", 0) + r.get("synthetic_false_alarm", 0) for r in rules.values())
found = sum(r.get("synthetic_detected", 0) for r in rules.values())
quiet = sum(r.get("synthetic_clean_pass", 0) for r in rules.values())
human = sum(r.get("true_positives", 0) + r.get("false_positives", 0) for r in rules.values())
print(f"  version {k.get('version')}")
print(f"  {len(rules)} rules have results")
print(f"  faults planted: {planted:,}   caught: {found:,}"
      + (f"  ({found/planted:.4%})" if planted else ""))
print(f"  look-alikes:    {controls:,}   correctly ignored: {quiet:,}"
      + (f"  ({quiet/controls:.4%})" if controls else ""))
print(f"  real findings reviewed by a person: {human:,}")
PY
