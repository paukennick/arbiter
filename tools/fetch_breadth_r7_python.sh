#!/usr/bin/env bash
# Breadth set r7, Python (ARB-163): fetch the pinned repositories of
# tools/gold/breadth-r7-python-repos.json. Same fetch as tools/fetch_heldout_r5.sh:
# one exact commit, no history, hooks off, LFS not smudged, submodules untouched,
# line endings unconverted, nothing executed.
#   tools/fetch_breadth_r7_python.sh DEST [dev|heldout|all] [SHARD_INDEX SHARD_COUNT]
set -u
DEST="${1:-$HOME/wt/corpus-r7py-breadth}"
SLICE="${2:-all}"
SHARD="${3:-0}"
SHARDS="${4:-1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || command -v python)"
mkdir -p "$DEST"
"$PY" - "$HERE/gold/breadth-r7-python-repos.json" "$SLICE" "$SHARD" "$SHARDS" <<'PYEOF' |
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
sl, i, n = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
rows = [(k, r) for k, r in sorted(m["repos"].items()) if sl == "all" or r["slice"] == sl]
for j, (k, r) in enumerate(rows):
    if j % n == i:
        print(k, r["url"], r["sha"])
PYEOF
while read -r name url sha; do
  dir="$DEST/$name"
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$sha" ]; then
    printf '  have %s @ %s\n' "$name" "${sha:0:12}"; continue
  fi
  rm -rf "$dir"; mkdir -p "$dir"
  if git -C "$dir" -c init.defaultBranch=gold init -q \
     && git -C "$dir" config core.autocrlf false \
     && git -C "$dir" remote add origin "$url" \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          fetch --quiet --depth 1 --no-tags origin "$sha" 2>/dev/null \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          -c advice.detachedHead=false checkout --quiet FETCH_HEAD; then
    printf '  got  %s @ %s\n' "$name" "${sha:0:12}"
  else
    rm -rf "$dir"; printf '  FAILED %s @ %s (skipping)\n' "$name" "${sha:0:12}"
  fi
done
