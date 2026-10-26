#!/usr/bin/env python3
"""Freeze an r7 breadth set for one language from GitHub metadata only.

Python (ARB-163) came first; JavaScript, TypeScript, Go, Ruby, Java, C and C++
(ARB-166) use the same filters. Nothing is cloned and no source is read. Per
candidate the script reads the search result, the language byte counts and the
recursive file-name tree (to screen paths Windows cannot check out and to
confirm a .github/workflows directory). The kept repositories are pinned to
their default-branch HEAD and split with a fixed seed into a development slice
(rule fixes may look at it) and a held-out slice (measured, never used for
tuning).

    python tools/freeze_breadth.py --language go
    python tools/freeze_breadth.py --language ruby --min-stars 300
    python tools/freeze_breadth.py --language go --scripts-only   # rewrite fetch scripts

Writes tools/gold/breadth-r7-<language>-repos.json and the two fetch scripts
tools/fetch_breadth_r7_<language>.sh (slice/shard) and
tools/fetch_breadth_r7_<language>_heldout.sh (get_pinned form read by
tools/gold_benchmark.py). Needs `gh` signed in. Re-running on another day gives
a different set (stars, pushes and HEADs move); the committed manifest is the
frozen record.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import random
import re
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = 20261026
PUSHED_SINCE = "2026-08-26"
MAX_SIZE_KB = 400_000
MIN_SHARE = 0.60
OSI = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0", "GPL-3.0",
    "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0", "ISC", "EPL-2.0", "0BSD",
    "Unlicense", "Zlib", "PSF-2.0", "Artistic-2.0", "EUPL-1.2", "BSL-1.0",
}
LIBRARY_WORDS = re.compile(r"\b(library|sdk|bindings?|wrapper|package for|framework for|toolkit)\b", re.I)
# Added for ARB-166 (not applied to the frozen Python set): repositories that
# are reading material or scaffolding rather than a running application.
NOT_APP_WORDS = re.compile(
    r"\b(header-only|boilerplate|starter kit|starter template|awesome list|curated list|"
    r"tutorials?|examples? of|interview|leetcode|homework|course)\b", re.I)
# Characters Windows refuses in a path component, plus reserved device names.
BAD_CHARS = re.compile(r'[<>:"|?*\\]')
RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.I)


@dataclass(frozen=True)
class Lang:
    key: str              # file-name token: breadth-r7-<key>-repos.json
    github: str           # GitHub's language name (search qualifier and byte counts)
    prefix: str           # repository name prefix in the manifest
    pin_language: str     # fourth column of get_pinned (gold_benchmark language)
    short: str            # corpus directory token: corpus-r7<short>-breadth
    requirement: str
    topics: tuple[str, ...]
    total: int = 120
    dev: int = 30
    min_stars: int = 1000
    # Other languages that must stay under a share (JS: TypeScript < 10%).
    max_other: dict = field(default_factory=dict)
    extra_not_app: bool = True


SERVICE = ("self-hosted", "web-application", "webapp", "dashboard", "cms", "api-server",
           "rest-api", "backend", "monitoring", "automation", "bot", "discord-bot",
           "telegram-bot", "chatbot", "scraper", "crawler", "cli", "proxy")
NATIVE = ("daemon", "server", "web-server", "http-server", "networking", "proxy", "vpn",
          "cli", "command-line-tool", "terminal", "shell", "embedded", "firmware", "esp32",
          "stm32", "microcontroller", "iot", "monitoring", "router", "self-hosted",
          "cmake", "meson", "makefile", "linux")

LANGS: dict[str, Lang] = {l.key: l for l in (
    Lang("python", "Python", "py", "python", "py", "ARB-163", (
        "self-hosted", "django-application", "flask-application", "fastapi",
        "web-application", "webapp", "dashboard", "home-automation", "chatbot",
        "discord-bot", "telegram-bot", "crawler", "scraper", "automation",
        "monitoring", "cms", "erp", "saas", "api-server", "rag", "llm-app",
        "workflow", "media-server", "download-manager", "bot"),
        total=180, dev=45, extra_not_app=False),
    Lang("javascript", "JavaScript", "js", "javascript", "js", "ARB-166", SERVICE + (
        "express", "expressjs", "nodejs", "koa", "fastify", "socket-io", "whatsapp-bot",
        "electron-app", "home-automation", "game-server", "chat"),
        max_other={"TypeScript": 0.10}),
    Lang("typescript", "TypeScript", "ts", "typescript", "ts", "ARB-166", SERVICE + (
        "nestjs", "express", "nextjs", "fastify", "hono", "trpc", "saas", "workflow",
        "llm-app", "rag", "mcp-server", "electron-app", "home-automation")),
    Lang("go", "Go", "go", "go", "go", "ARB-166", SERVICE + (
        "http-server", "reverse-proxy", "gin", "echo", "fiber", "grpc", "microservice",
        "kubernetes-operator", "devops", "backup", "file-sharing", "media-server", "vpn")),
    Lang("ruby", "Ruby", "rb", "ruby", "rb", "ARB-166", SERVICE + (
        "rails", "ruby-on-rails", "rails-application", "rails-app", "sinatra", "hanami",
        "ecommerce", "mastodon", "activitypub", "jekyll", "devops", "hotwire", "graphql",
        "fediverse", "forum", "project-management", "social-network", "saas", "api",
        "e-commerce", "chat", "rails7", "rails8", "open-source"),
        min_stars=300),
    Lang("java", "Java", "java", "java", "java", "ARB-166", SERVICE + (
        "spring-boot", "springboot", "spring-cloud", "spring", "microservice", "erp",
        "admin-dashboard", "management-system", "ecommerce", "gateway", "low-code",
        "server", "im")),
    Lang("c", "C", "c", "c", "c", "ARB-166", NATIVE),
    Lang("cpp", "C++", "cpp", "cpp", "cpp", "ARB-166", NATIVE + (
        "qt", "game-server", "emulator", "database", "arduino")),
)}


# ---------------------------------------------------------------------------
# Pure screening steps -- tested with fixture metadata, no network
# ---------------------------------------------------------------------------

def search_query(lang: Lang, topic: str, min_stars: int) -> str:
    """URL-encoded search query. Encoding matters: `language:C++` sent raw
    reads as `language:C` followed by two spaces."""
    q = (f"topic:{topic} language:{lang.github} stars:>={min_stars} pushed:>={PUSHED_SINCE} "
         "archived:false fork:false")
    return urllib.parse.quote(q, safe=":>=")


def metadata_reason(item: dict, prior: set[str], lang: Lang) -> str | None:
    """Why a search result is rejected before any further API call, or None."""
    lic = (item.get("license") or {}).get("spdx_id")
    desc = item.get("description") or ""
    if item["full_name"].lower() in prior:
        return "used before in Arbiter's corpora, docs or another breadth manifest"
    if item.get("is_template"):
        return "template repository"
    if item.get("archived") or item.get("fork"):
        return "archived or fork"
    if lic not in OSI:
        return f"licence {lic} not in the OSI list"
    if item["size"] > MAX_SIZE_KB:
        return f"size {item['size']} KB > {MAX_SIZE_KB}"
    if LIBRARY_WORDS.search(desc):
        return "description names a library/SDK, not an application"
    if lang.extra_not_app and NOT_APP_WORDS.search(desc):
        return "description names a tutorial/boilerplate/list, not an application"
    return None


def share_reason(langs: dict[str, int], lang: Lang) -> tuple[str | None, float]:
    """Byte-share test on GitHub's language counts: the language must be at
    least 60%, and any `max_other` language must stay under its cap."""
    total = max(1, sum(langs.values()))
    share = langs.get(lang.github, 0) / total
    if share < MIN_SHARE:
        return f"{lang.github} {share:.0%} of bytes (< 60%)", share
    for other, cap in lang.max_other.items():
        s = langs.get(other, 0) / total
        if s >= cap:
            return f"{other} {s:.0%} of bytes (>= {cap:.0%})", share
    return None, share


def tree_reason(tree: dict) -> str | None:
    """Windows-unsafe paths, a truncated tree, or no .github/workflows."""
    bad = []
    for e in tree.get("tree", []):
        for part in e["path"].split("/"):
            if BAD_CHARS.search(part) or RESERVED.match(part) or part.endswith((" ", ".")):
                bad.append(e["path"])
                break
    if tree.get("truncated"):
        bad.append("<tree truncated: cannot confirm>")
    if bad:
        return f"paths Windows cannot check out: {bad[:2]}"
    if not any(e["path"].startswith(".github/workflows/") for e in tree.get("tree", [])):
        return "no .github/workflows directory"
    return None


def name_for(lang: Lang, full: str, taken: set[str]) -> str:
    """`<prefix>-<repo>`; owner added when two owners share a repo name."""
    owner, repo = full.lower().split("/", 1)
    name = f"{lang.prefix}-{repo}"
    return name if name not in taken else f"{lang.prefix}-{owner}-{repo}"


def split(kept: list[dict], lang: Lang, dev: int, seed: int) -> dict[str, dict]:
    """Seeded split into `dev` and `heldout`; names keyed in kept order."""
    idx = list(range(len(kept)))
    random.Random(seed + 1).shuffle(idx)
    dev_idx = set(idx[:dev])
    repos: dict[str, dict] = {}
    for i, r in enumerate(kept):
        r["slice"] = "dev" if i in dev_idx else "heldout"
        repos[name_for(lang, r["github"], set(repos))] = r
    return repos


def about(lang: Lang, min_stars: int, dev: int, seed: int) -> str:
    if lang.key == "python":
        return (
            "Breadth set r7, Python (ARB-163), frozen before any scan. Python applications drawn "
            f"from GitHub topics {list(lang.topics)}, each with >= {min_stars} stars, pushed since "
            f"{PUSHED_SINCE}, not archived/fork/template, an OSI licence, Python >= 60% of bytes, "
            f"size <= {MAX_SIZE_KB} KB, a .github/workflows directory, no path Windows cannot "
            "check out, and not named anywhere in Arbiter's tools, packs, docs or fixtures (r5 and "
            "r7 held-out, gold repos, ground-truth sources). Chosen from metadata and file names "
            f"only; candidates shuffled with seed {seed}, then split with seed {seed + 1} into "
            f"'dev' ({dev}: rule fixes may read these) and 'heldout' (measurement only, never "
            "used for tuning). Each repo is pinned to its default-branch HEAD at freeze time.")
    other = "".join(f", {o} < {c:.0%} of bytes" for o, c in lang.max_other.items())
    return (
        f"Breadth set r7, {lang.github} ({lang.requirement}), frozen before any clone or scan. "
        f"{lang.github} applications and services drawn from GitHub topics {list(lang.topics)}, "
        f"each with >= {min_stars} stars, pushed since {PUSHED_SINCE}, not archived/fork/"
        f"template, an OSI licence, {lang.github} >= 60% of bytes{other}, size <= {MAX_SIZE_KB} "
        "KB, a .github/workflows directory, no path Windows cannot check out, a description "
        "that does not name a library/SDK/tutorial/boilerplate/list, and not named anywhere in "
        "Arbiter's tools, packs, docs or fixtures (held-out sets, gold repos, ground-truth "
        "sources, every other breadth manifest). Chosen from metadata and file names only; "
        f"candidates shuffled with seed {seed}, then split with seed {seed + 1} into 'dev' "
        f"({dev}: rule fixes may read these) and 'heldout' (measurement only, never used for "
        "tuning). Each repo is pinned to its default-branch HEAD at freeze time.")


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def gh(path: str, tries: int = 6) -> object:
    """`gh api`, retrying rate limits and server errors with a growing wait."""
    for n in range(tries):
        out = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                             capture_output=True, text=True, encoding="utf-8")
        if not out.returncode:
            return json.loads(out.stdout)
        err = out.stderr.strip()
        if n + 1 < tries and re.search(r"rate limit|HTTP (403|429|5\d\d)|timeout|EOF", err, re.I):
            time.sleep(min(600, 30 * 2 ** n))
            continue
        raise RuntimeError(f"gh api {path}: {err[:200]}")
    raise RuntimeError(f"gh api {path}: retries exhausted")


def used_before() -> set[str]:
    """Every owner/repo named anywhere in tools/, packs, docs or fixtures --
    which includes every breadth manifest already written."""
    pat = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
    seen: set[str] = set()
    for base in ("tools", "src/arbiter/packs", "docs", "fixtures"):
        for p in (ROOT / base).rglob("*"):
            if p.is_file() and p.suffix in {".json", ".sh", ".md", ".py", ".yaml", ".yml", ".txt"}:
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for m in pat.finditer(text):
                    seen.add(re.sub(r"\.git$", "", m.group(1)).lower())
    return seen


def search(lang: Lang, topic: str, min_stars: int) -> list[dict]:
    items: list[dict] = []
    for page in (1, 2, 3):
        res = gh(f"search/repositories?q={search_query(lang, topic, min_stars)}"
                 f"&sort=stars&order=desc&per_page=100&page={page}")
        items += res["items"]
        time.sleep(2.2)  # search API allows 30 requests a minute
        if len(res["items"]) < 100:
            break
    return items


def freeze(lang: Lang, min_stars: int, total: int, dev: int, seed: int) -> dict:
    prior = used_before()
    cand: dict[str, dict] = {}
    for t in lang.topics:
        for it in search(lang, t, min_stars):
            cand.setdefault(it["full_name"].lower(), it)
    print(f"{len(cand)} candidates from {len(lang.topics)} topics; {len(prior)} repos used before",
          file=sys.stderr)
    order = sorted(cand)
    random.Random(seed).shuffle(order)
    kept, rejected = [], []
    for key in order:
        if len(kept) >= total:
            break
        it = cand[key]
        full = it["full_name"]
        why = metadata_reason(it, prior, lang)
        share = 0.0
        if why is None:
            why, share = share_reason(gh(f"repos/{full}/languages"), lang)
        if why is None:
            branch = it["default_branch"]
            sha = gh(f"repos/{full}/commits/{branch}")["sha"]
            why = tree_reason(gh(f"repos/{full}/git/trees/{sha}?recursive=1"))
        if why:
            rejected.append({"github": full, "stars": it["stargazers_count"], "reason": why})
            continue
        kept.append({"github": full, "url": it["clone_url"], "sha": sha, "branch": branch,
                     "stars": it["stargazers_count"],
                     "license": (it.get("license") or {}).get("spdx_id"),
                     "language_share": round(share, 3), "description": it.get("description")})
        print(f"  keep {len(kept):3d} {full}", file=sys.stderr)
    dev = min(dev, round(len(kept) * dev / total)) if len(kept) < total else dev
    return {
        "_about": about(lang, min_stars, dev, seed),
        "language": lang.key,
        "requirement": lang.requirement,
        "frozen": dt.date.today().isoformat(),
        "seed": seed,
        "split_seed": seed + 1,
        "min_stars": min_stars,
        "candidates": len(cand),
        "target": total,
        "repos": split(kept, lang, dev, seed),
        "rejected": rejected,
    }


# ---------------------------------------------------------------------------
# Fetch scripts
# ---------------------------------------------------------------------------

_FETCH = r'''#!/usr/bin/env bash
# Breadth set r7, {github} ({req}): fetch the pinned repositories of
# tools/gold/breadth-r7-{key}-repos.json. Same fetch as tools/fetch_heldout_r5.sh:
# one exact commit, no history, hooks off, LFS not smudged, submodules untouched,
# line endings unconverted, nothing executed. Generated by tools/freeze_breadth.py.
#   tools/fetch_breadth_r7_{key}.sh DEST [dev|heldout|all] [SHARD_INDEX SHARD_COUNT]
set -u
DEST="${{1:-$HOME/wt/corpus-r7{short}-breadth}}"
SLICE="${{2:-all}}"
SHARD="${{3:-0}}"
SHARDS="${{4:-1}}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || command -v python)"
mkdir -p "$DEST"
"$PY" - "$HERE/gold/breadth-r7-{key}-repos.json" "$SLICE" "$SHARD" "$SHARDS" <<'PYEOF' |
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
    printf '  have %s @ %s\n' "$name" "${{sha:0:12}}"; continue
  fi
  rm -rf "$dir"; mkdir -p "$dir"
  if git -C "$dir" -c init.defaultBranch=gold init -q \
     && git -C "$dir" config core.autocrlf false \
     && git -C "$dir" config core.longpaths true \
     && git -C "$dir" remote add origin "$url" \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          fetch --quiet --depth 1 --no-tags origin "$sha" 2>/dev/null \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          -c advice.detachedHead=false checkout --quiet FETCH_HEAD; then
    printf '  got  %s @ %s\n' "$name" "${{sha:0:12}}"
  else
    rm -rf "$dir"; printf '  FAILED %s @ %s (skipping)\n' "$name" "${{sha:0:12}}"
  fi
done
'''

_HELDOUT = r'''#!/usr/bin/env bash
# Breadth set r7, {github}, held-out slice ({req}): fetch the {n} pinned 'heldout' repositories of
# tools/gold/breadth-r7-{key}-repos.json, in the get_pinned form tools/gold_benchmark.py reads.
# Same fetch as tools/fetch_heldout_r5.sh: one exact commit, no history, hooks off, LFS not smudged,
# submodules untouched, nothing executed. Generated by tools/freeze_breadth.py.
set -u
DEST="${{1:-$HOME/wt/corpus-r7{short}-breadth}}"
mkdir -p "$DEST"
get_pinned() {{
  local name="$1" url="$2" sha="$3" dir="$DEST/$1"
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$sha" ]; then
    printf '  have %s @ %s\n' "$name" "${{sha:0:12}}"
    return
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  if git -C "$dir" -c init.defaultBranch=gold init -q \
     && git -C "$dir" config core.autocrlf false \
     && git -C "$dir" config core.longpaths true \
     && git -C "$dir" remote add origin "$url" \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          fetch --quiet --depth 1 --no-tags origin "$sha" 2>/dev/null \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          -c advice.detachedHead=false checkout --quiet FETCH_HEAD; then
    printf '  got  %s @ %s\n' "$name" "${{sha:0:12}}"
  else
    rm -rf "$dir"
    printf '  FAILED %s @ %s (skipping)\n' "$name" "${{sha:0:12}}"
  fi
}}
'''


def fetch_scripts(lang: Lang, manifest: dict) -> tuple[str, str]:
    """(slice/shard script, held-out get_pinned script) for a manifest."""
    ho = sorted((k, r) for k, r in manifest["repos"].items() if r["slice"] == "heldout")
    fmt = dict(github=lang.github, req=lang.requirement, key=lang.key, short=lang.short, n=len(ho))
    heldout = _HELDOUT.format(**fmt)
    heldout += "".join(f"get_pinned {k} {r['url']} {r['sha']} {lang.pin_language}\n" for k, r in ho)
    return _FETCH.format(**fmt), heldout


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--language", required=True, choices=sorted(LANGS))
    ap.add_argument("--out", help="manifest path (default tools/gold/breadth-r7-<language>-repos.json)")
    ap.add_argument("--min-stars", type=int)
    ap.add_argument("--total", type=int)
    ap.add_argument("--dev", type=int)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--scripts-only", action="store_true",
                    help="regenerate the fetch scripts from the existing manifest")
    a = ap.parse_args(argv)
    lang = LANGS[a.language]
    out = Path(a.out) if a.out else ROOT / "tools" / "gold" / f"breadth-r7-{lang.key}-repos.json"
    frozen_py = ROOT / "tools" / "gold" / "breadth-r7-python-repos.json"
    if lang.key == "python" and out.resolve() == frozen_py.resolve() and not a.scripts_only:
        print("the Python manifest is frozen; pass --out to write elsewhere", file=sys.stderr)
        return 2
    if a.scripts_only:
        manifest = json.loads(out.read_text(encoding="utf-8"))
    else:
        manifest = freeze(lang, a.min_stars or lang.min_stars, a.total or lang.total,
                          a.dev if a.dev is not None else lang.dev, a.seed)
        out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8", newline="\n")
        n_dev = sum(r["slice"] == "dev" for r in manifest["repos"].values())
        print(f"kept {len(manifest['repos'])} ({n_dev} dev), rejected {len(manifest['rejected'])}",
              file=sys.stderr)
    if lang.key != "python":
        slice_sh, heldout_sh = fetch_scripts(lang, manifest)
        for name, text in ((f"fetch_breadth_r7_{lang.key}.sh", slice_sh),
                           (f"fetch_breadth_r7_{lang.key}_heldout.sh", heldout_sh)):
            (ROOT / "tools" / name).write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
