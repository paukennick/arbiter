#!/usr/bin/env python3
"""Freeze the r7 Python breadth set (ARB-163) from GitHub metadata only.

Nothing is cloned and no source is read. Per candidate the script reads the
search result, the language byte counts and the recursive file-name tree (to
screen paths Windows cannot check out and to confirm a .github/workflows
directory). The kept repositories are pinned to their default-branch HEAD and
split with a fixed seed into a development slice (rule fixes may look at it)
and a held-out slice (measured, never used for tuning).

    python tools/freeze_breadth_python.py --out tools/gold/breadth-r7-python-repos.json

Needs `gh` signed in. Re-running on another day gives a different set (stars,
pushes and HEADs move); the committed manifest is the frozen record.
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = 20261026
PUSHED_SINCE = "2026-08-26"
MIN_STARS = 1000
MAX_SIZE_KB = 400_000
MIN_PY_SHARE = 0.60
OSI = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0", "GPL-3.0",
    "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0", "ISC", "EPL-2.0", "0BSD",
    "Unlicense", "Zlib", "PSF-2.0", "Artistic-2.0", "EUPL-1.2", "BSL-1.0",
}
# Applications, not libraries: the rules under test (SQL, HTTP clients,
# request bodies, workers) fire in deployed services, so the set is drawn from
# GitHub topics that name a running application.
APP_TOPICS = [
    "self-hosted", "django-application", "flask-application", "fastapi",
    "web-application", "webapp", "dashboard", "home-automation", "chatbot",
    "discord-bot", "telegram-bot", "crawler", "scraper", "automation",
    "monitoring", "cms", "erp", "saas", "api-server", "rag", "llm-app",
    "workflow", "media-server", "download-manager", "bot",
]
LIBRARY_WORDS = re.compile(r"\b(library|sdk|bindings?|wrapper|package for|framework for|toolkit)\b", re.I)
# Characters Windows refuses in a path component, plus reserved device names.
BAD_CHARS = re.compile(r'[<>:"|?*\\]')
RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.I)


def gh(path: str) -> object:
    out = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                         capture_output=True, text=True, encoding="utf-8")
    if out.returncode:
        raise RuntimeError(f"gh api {path}: {out.stderr.strip()[:200]}")
    return json.loads(out.stdout)


def used_before() -> set[str]:
    """Every owner/repo named anywhere in tools/, packs, docs or fixtures."""
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


def search(topic: str) -> list[dict]:
    q = (f"topic:{topic} language:Python stars:>={MIN_STARS} pushed:>={PUSHED_SINCE} "
         "archived:false fork:false")
    items: list[dict] = []
    for page in (1, 2, 3):
        res = gh(f"search/repositories?q={q.replace(' ', '+')}&sort=stars&order=desc&per_page=100&page={page}")
        items += res["items"]
        time.sleep(2.2)  # search API allows 30 requests a minute
        if len(res["items"]) < 100:
            break
    return items


def windows_bad_paths(full: str, sha: str) -> tuple[list[str], bool]:
    tree = gh(f"repos/{full}/git/trees/{sha}?recursive=1")
    bad = []
    for e in tree.get("tree", []):
        for part in e["path"].split("/"):
            if BAD_CHARS.search(part) or RESERVED.match(part) or part.endswith((" ", ".")):
                bad.append(e["path"])
                break
    if tree.get("truncated"):
        bad.append("<tree truncated: cannot confirm>")
    return bad, any(e["path"].startswith(".github/workflows/") for e in tree.get("tree", []))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--total", type=int, default=180)
    ap.add_argument("--dev", type=int, default=45)
    a = ap.parse_args()

    prior = used_before()
    cand: dict[str, dict] = {}
    for t in APP_TOPICS:
        for it in search(t):
            cand.setdefault(it["full_name"].lower(), it)
    print(f"{len(cand)} candidates from {len(APP_TOPICS)} topics; {len(prior)} repos used before",
          file=sys.stderr)

    rng = random.Random(SEED)
    order = sorted(cand)
    rng.shuffle(order)
    kept, rejected = [], []
    for key in order:
        if len(kept) >= a.total:
            break
        it = cand[key]
        full = it["full_name"]
        why = None
        lic = (it.get("license") or {}).get("spdx_id")
        if key in prior:
            why = "used before in Arbiter's corpora or docs"
        elif it.get("is_template"):
            why = "template repository"
        elif lic not in OSI:
            why = f"licence {lic} not in the OSI list"
        elif it["size"] > MAX_SIZE_KB:
            why = f"size {it['size']} KB > {MAX_SIZE_KB}"
        elif LIBRARY_WORDS.search(it.get("description") or ""):
            why = "description names a library/SDK, not an application"
        if why is None:
            langs = gh(f"repos/{full}/languages")
            share = langs.get("Python", 0) / max(1, sum(langs.values()))
            if share < MIN_PY_SHARE:
                why = f"Python {share:.0%} of bytes (< 60%)"
        if why is None:
            branch = it["default_branch"]
            sha = gh(f"repos/{full}/commits/{branch}")["sha"]
            bad, has_wf = windows_bad_paths(full, sha)
            if bad:
                why = f"paths Windows cannot check out: {bad[:2]}"
            elif not has_wf:
                why = "no .github/workflows directory"
        if why:
            rejected.append({"github": full, "stars": it["stargazers_count"], "reason": why})
            continue
        kept.append({"github": full, "url": it["clone_url"], "sha": sha, "branch": branch,
                     "stars": it["stargazers_count"], "license": lic,
                     "python_share": round(share, 3), "description": it.get("description")})
        print(f"  keep {len(kept):3d} {full}", file=sys.stderr)

    split = random.Random(SEED + 1)
    idx = list(range(len(kept)))
    split.shuffle(idx)
    dev = set(idx[: a.dev])
    repos = {}
    for i, r in enumerate(kept):
        name = "py-" + r["github"].split("/")[1].lower()
        r["slice"] = "dev" if i in dev else "heldout"
        repos[name] = r
    manifest = {
        "_about": (
            "Breadth set r7, Python (ARB-163), frozen before any scan. Python applications drawn "
            f"from GitHub topics {APP_TOPICS}, each with >= {MIN_STARS} stars, pushed since "
            f"{PUSHED_SINCE}, not archived/fork/template, an OSI licence, Python >= 60% of bytes, "
            f"size <= {MAX_SIZE_KB} KB, a .github/workflows directory, no path Windows cannot "
            "check out, and not named anywhere in Arbiter's tools, packs, docs or fixtures (r5 and "
            "r7 held-out, gold repos, ground-truth sources). Chosen from metadata and file names "
            f"only; candidates shuffled with seed {SEED}, then split with seed {SEED + 1} into "
            f"'dev' ({a.dev}: rule fixes may read these) and 'heldout' (measurement only, never "
            "used for tuning). Each repo is pinned to its default-branch HEAD at freeze time."
        ),
        "frozen": dt.date.today().isoformat(),
        "seed": SEED,
        "repos": repos,
        "rejected": rejected,
    }
    Path(a.out).write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8", newline="\n")
    print(f"kept {len(kept)} ({a.dev} dev), rejected {len(rejected)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
