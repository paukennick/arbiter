#!/usr/bin/env python3
"""Fetch, scan and score the frozen GHSA fix pairs (ARB-121).

    python tools/ground_truth/ghsa_pairs.py fetch --dest ~/wt/corpus-gt/cve-ghsa
    python tools/ground_truth/ghsa_pairs.py score --dest ~/wt/corpus-gt/cve-ghsa \\
        --out-dev tools/gold/results/2026-10-24-ghsa-dev.json \\
        --out-sealed tools/gold/results/2026-10-24-ghsa-sealed-aggregate.json

The pairs and every scoring rule are frozen in tools/ground_truth/
ghsa_pairs.json by `ghsa_select.py` before anything is scanned; this file
implements what its `criteria.scoring` says. `fetch` downloads only the
files each fix changed, at the fix and at its parent, from
raw.githubusercontent.com into DEST (outside the repository; the trees are
data, never built or run). `score` scans both sides with this checkout of
Arbiter (native probes, no cache) and reports, per pair:

* recall (primary): a finding whose CWE matches the advisory's, on the
  vulnerable side, within 3 lines of a hunk the fix changed (an add-only
  hunk counts at its insertion point);
* recall (secondary, looser): in the enclosing function of a changed hunk;
  anywhere in a changed file;
* fixed-side persistence: every primary match still reported after the
  fix -- a likely false-positive or partial-fix signal, not proof.

Development pairs are reported in detail. Sealed pairs are scanned in
memory and only per-language and overall aggregates are written: no
per-pair row, CWE cell, finding or excerpt of a sealed pair reaches disk.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import gt_common as g  # noqa: E402
from cve_pairs import CWE_ALIASES, PROJECT_RULES, changed_lines  # noqa: E402

REGION = 3        # lines either side of a changed old-side hunk (primary recall)
NEAR = 2          # persistence: lines either side of the mapped new-side hunk
BOOTSTRAP = 2000
SEED = 20261024
Z = 1.959963984540054
METRICS = ("hunk", "function", "file")


# ---------------------------------------------------------------------------
# Pure scoring (unit-tested on synthetic inputs)
# ---------------------------------------------------------------------------

def region_hunk(line: int, hunks: list[tuple[range, range]]) -> tuple[range, range] | None:
    """The first hunk whose widened old-side region [start-3, stop+3) holds `line`."""
    for o, n in hunks:
        if o.start - REGION <= line < o.stop + REGION:
            return o, n
    return None


def in_function(line: int, hunks: list[tuple[range, range]], span: tuple[int, int] | None) -> bool:
    """`line` lies in function `span` and a changed hunk (or insertion point) falls inside it.
    Without a span, the primary region decides."""
    if span is None:
        return region_hunk(line, hunks) is not None
    lo, hi = span
    if not lo <= line <= hi:
        return False
    for o, _ in hunks:
        a, b = o.start, max(o.stop, o.start + 1)  # an insertion point occupies its line
        if a <= hi and b - 1 >= lo:
            return True
    return False


def persists(f: dict, hunk: tuple[range, range], old: list[str], new: list[str], fix_lines: list[int]) -> bool:
    """The vulnerable-side finding `f` is still reported after the fix."""
    _, n = hunk
    lo, hi = n.start, (n.stop if len(n) else n.start)
    text = old[f["line"] - 1].strip() if 0 < f["line"] <= len(old) else ""
    return any(lo - NEAR <= ln < hi + NEAR or (text and 0 < ln <= len(new) and new[ln - 1].strip() == text)
               for ln in fix_lines)


def score_pair(pair: dict, vuln: list[dict], fix: list[dict], texts: dict[str, tuple[list[str], list[str]]],
               spans=None) -> dict:
    """Outcome of one pair. `spans(path, text, line)` gives the enclosing function span."""
    cwes = pair["in_scope_cwes"]
    fix_by: dict = defaultdict(list)
    for f in fix:
        fix_by[(f["path"], f["rule"])].append(f["line"])
    hunks = {p: changed_lines(o, n) for p, (o, n) in texts.items()}
    matched = []
    per_cwe = {c: {m: False for m in METRICS} for c in cwes}
    for f in vuln:
        if f["rule"].startswith(PROJECT_RULES) or f["path"] not in texts:
            continue
        hit = [c for c in cwes if g.cwe_match(f["cwe"], [c], CWE_ALIASES)]
        if not hit:
            continue
        old, new = texts[f["path"]]
        h = region_hunk(f["line"], hunks[f["path"]])
        span = spans(f["path"], "\n".join(old), f["line"]) if spans else None
        where = {"hunk": h is not None, "function": in_function(f["line"], hunks[f["path"]], span), "file": True}
        for c in hit:
            for m in METRICS:
                per_cwe[c][m] |= where[m]
        row = {"rule": f["rule"], "path": f["path"], "line": f["line"], "cwe": f["cwe"],
               "region": "hunk" if where["hunk"] else "function" if where["function"] else "file"}
        if h is not None:
            row["persists"] = persists(f, h, old, new, fix_by.get((f["path"], f["rule"]), []))
        matched.append(row)
    primary = [r for r in matched if r["region"] == "hunk"]
    return {"detected": {m: any(per_cwe[c][m] for c in cwes) for m in METRICS},
            "per_cwe": per_cwe,
            "persists": bool(primary) and all(r["persists"] for r in primary),
            "primary_findings": len(primary), "primary_persisting": sum(r["persists"] for r in primary),
            "matched": matched, "vuln_findings": len(vuln), "fix_findings": len(fix)}


def wilson(k: int, n: int, z: float = Z) -> tuple[float | None, float | None]:
    if n == 0:
        return None, None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def cluster_bootstrap(rows: list[tuple[str, int, int]], b: int = BOOTSTRAP, seed: str = "") -> dict:
    """rows: (cluster, successes, trials). Percentile 95% CI of sum(k)/sum(n) when
    whole clusters are resampled with replacement, and the effective sample size."""
    by: dict = defaultdict(lambda: [0, 0])
    for c, k, n in rows:
        by[c][0] += k
        by[c][1] += n
    clusters = [tuple(v) for _, v in sorted(by.items())]
    n_tot = sum(n for _, n in clusters)
    if not clusters or n_tot == 0:
        return {"lower": None, "upper": None, "clusters": len(clusters), "effective_n": None}
    p = sum(k for k, _ in clusters) / n_tot
    rng = random.Random(int(hashlib.sha256(f"{SEED}:{seed}".encode()).hexdigest()[:16], 16))
    stats = []
    m = len(clusters)
    for _ in range(b):
        k = n = 0
        for _ in range(m):
            ck, cn = clusters[rng.randrange(m)]
            k += ck
            n += cn
        stats.append(k / n if n else p)
    stats.sort()
    mean = sum(stats) / b
    var = sum((s - mean) ** 2 for s in stats) / (b - 1)
    ess = (p * (1 - p) / var) if var > 0 else float(n_tot)
    return {"lower": stats[int(0.025 * b)], "upper": stats[min(b - 1, int(0.975 * b))],
            "clusters": m, "effective_n": round(min(ess, float(n_tot)), 1)}


def rate(rows: list[tuple[str, int, int]], seed: str) -> dict:
    k, n = sum(r[1] for r in rows), sum(r[2] for r in rows)
    lo, hi = wilson(k, n)
    bs = cluster_bootstrap(rows, seed=seed)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "wilson_95": [lo, hi],
            "cluster_bootstrap_95": [bs["lower"], bs["upper"]], "clusters": bs["clusters"],
            "effective_n": bs["effective_n"]}


def summarise(pairs: list[dict], outcomes: dict[str, dict], label: str, per_cwe: bool) -> dict:
    """Per language (and overall) rates; per (language, CWE) cells when `per_cwe`."""
    out: dict = {"languages": {}, "overall": {}}
    groups = defaultdict(list)
    for p in pairs:
        if p["key"] in outcomes:
            groups[p["language"]].append(p)
    groups["all"] = [p for ps in list(groups.values()) for p in ps]

    def block(ps, tag):
        res = {"pairs": len(ps)}
        for m in METRICS:
            res[f"recall_{m}"] = rate([(q["repo"].lower(), int(outcomes[q["key"]]["detected"][m]), 1)
                                       for q in ps], f"{label}:{tag}:{m}")
        det = [q for q in ps if outcomes[q["key"]]["detected"]["hunk"]]
        res["fixed_side_persistence"] = rate([(q["repo"].lower(), int(outcomes[q["key"]]["persists"]), 1)
                                              for q in det], f"{label}:{tag}:persist")
        res["primary_findings"] = sum(outcomes[q["key"]]["primary_findings"] for q in ps)
        res["primary_findings_persisting"] = sum(outcomes[q["key"]]["primary_persisting"] for q in ps)
        return res

    for lang, ps in sorted(groups.items()):
        if lang == "all":
            out["overall"] = block(ps, "all")
            continue
        out["languages"][lang] = block(ps, lang)
        if per_cwe:
            cells = defaultdict(list)
            for q in ps:
                for c, d in outcomes[q["key"]]["per_cwe"].items():
                    cells[c].append((q["repo"].lower(), d))
            out["languages"][lang]["cwes"] = {
                c: {"pairs": len(v), **{f"recall_{m}": rate([(r, int(d[m]), 1) for r, d in v],
                                                            f"{label}:{lang}:{c}:{m}") for m in METRICS}}
                for c, v in sorted(cells.items(), key=lambda kv: int(kv[0].split("-")[1]))}
    return out


# ---------------------------------------------------------------------------
# Fetch and scan
# ---------------------------------------------------------------------------

def pair_key(p: dict) -> str:
    return f"{p['language']}-{p['ghsa']}"


def _get(job) -> str | None:
    url, target = job
    if target.exists():
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".part")
    for attempt in range(3):
        r = subprocess.run(["curl", "-sfL", "-m", "60", "-o", str(tmp), url], capture_output=True, timeout=90)
        if r.returncode == 0:
            tmp.replace(target)
            return None
        if r.returncode == 22:  # HTTP error: retrying will not help
            break
        time.sleep(2 * (attempt + 1))
    tmp.unlink(missing_ok=True)
    return f"{url}: curl {r.returncode}"


def fetch(pairs: list[dict], dest: Path, workers: int = 16) -> list[str]:
    jobs = []
    for p in pairs:
        for side, sha in (("vuln", p["vuln_sha"]), ("fix", p["fix_sha"])):
            for path in p["files"]:
                jobs.append((f"https://raw.githubusercontent.com/{p['repo']}/{sha}/{path}",
                             dest / pair_key(p) / side / path))
    with ThreadPoolExecutor(workers) as ex:
        return [e for e in ex.map(_get, jobs) if e]


def _fetched(p: dict, dest: Path) -> bool:
    root = dest / pair_key(p)
    return all((root / side / f).is_file() for side in ("vuln", "fix") for f in p["files"])


def _span(path: str, text: str, line: int):
    try:
        return g._function_span(text, path, g.language_of(path), line)
    except Exception:  # noqa: BLE001 - no span means "use the primary region"
        return None


def _scan_one(job) -> tuple[str, dict | None, str]:
    key, pair, root = job
    root = Path(root)
    try:
        vuln, fix = g.scan_tree(root / "vuln"), g.scan_tree(root / "fix")
        texts = {}
        for path in pair["files"]:
            texts[path] = ((root / "vuln" / path).read_text(encoding="utf-8", errors="replace").splitlines(),
                           (root / "fix" / path).read_text(encoding="utf-8", errors="replace").splitlines())
        return key, score_pair(pair, vuln, fix, texts, spans=_span), ""
    except Exception as exc:  # noqa: BLE001 - a failed scan is "not assessed", counted
        return key, None, f"{type(exc).__name__}: {exc}"[:300]


def run_record(doc: dict, pairs_path: Path) -> dict:
    def git(*a):
        r = subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        return r.stdout.strip()
    return {"arbiter_commit": git("rev-parse", "HEAD"),
            "arbiter_worktree_clean": git("status", "--porcelain", "--untracked-files=no") == "",
            "pairs_file_sha256": hashlib.sha256(pairs_path.read_bytes()).hexdigest(),
            "pairs_file_commit": git("log", "-1", "--format=%H", "--", str(pairs_path.relative_to(ROOT)))
            if pairs_path.is_relative_to(ROOT) else None,
            "profile": "native probes only (gt_common.scan_tree: use_adapters=False, use_cache=False)",
            "python_version": platform.python_version(), "operating_system_image": platform.platform(),
            "architecture": platform.machine(), "started_at_utc": None, "completed_at_utc": None,
            "seed": SEED, "bootstrap_resamples": BOOTSTRAP, "region_lines": REGION, "persistence_near": NEAR,
            "criteria_sha256": hashlib.sha256(json.dumps(doc["criteria"], sort_keys=True).encode()).hexdigest()}


def score(args) -> int:
    doc = json.loads(args.pairs.read_text(encoding="utf-8"))
    pairs = [{**p, "key": pair_key(p)} for p in doc["pairs"]]
    dest = args.dest.expanduser()
    rec = run_record(doc, args.pairs.resolve())
    rec["started_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    jobs = [(p["key"], p, str(dest / p["key"])) for p in pairs if _fetched(p, dest)]
    not_fetched = {p["key"] for p in pairs} - {j[0] for j in jobs}
    outcomes, failed = {}, {}
    with ProcessPoolExecutor(args.workers) as ex:
        for i, (key, out, err) in enumerate(ex.map(_scan_one, jobs, chunksize=2), 1):
            if out is None:
                failed[key] = err
            else:
                outcomes[key] = out
            if i % 50 == 0:
                print(f"  scanned {i}/{len(jobs)}", file=sys.stderr, flush=True)
    rec["completed_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    by_split = {s: [p for p in pairs if p["split"] == s] for s in ("development", "sealed")}

    def not_assessed(ps):
        return {"not_fetched": sum(p["key"] in not_fetched for p in ps),
                "scan_failed": sum(p["key"] in failed for p in ps)}

    dev = by_split["development"]
    dev_doc = {"requirement": "ARB-121", "split": "development", "run": rec,
               "not_assessed": not_assessed(dev),
               "summary": summarise(dev, outcomes, "development", per_cwe=True),
               "pairs": [{"ghsa": p["ghsa"], "language": p["language"], "repo": p["repo"],
                          "fix_sha": p["fix_sha"], "in_scope_cwes": p["in_scope_cwes"],
                          **({"status": "not fetched"} if p["key"] in not_fetched else
                             {"status": "scan failed", "error": failed[p["key"]]} if p["key"] in failed else
                             {"status": "scored", **{k: v for k, v in outcomes[p["key"]].items()}})}
                         for p in dev]}
    sealed = by_split["sealed"]
    s = summarise(sealed, outcomes, "sealed", per_cwe=False)
    sealed_doc = {"requirement": "ARB-121", "split": "sealed", "run": rec,
                  "policy": "aggregate only: no per-pair, per-CWE or finding data of the sealed split is written",
                  "not_assessed": not_assessed(sealed), "summary": s}
    args.out_dev.parent.mkdir(parents=True, exist_ok=True)
    args.out_dev.write_text(json.dumps(dev_doc, indent=1) + "\n", encoding="utf-8")
    args.out_sealed.write_text(json.dumps(sealed_doc, indent=1) + "\n", encoding="utf-8")
    for name, d in (("development", dev_doc["summary"]), ("sealed", s)):
        print(f"{name}:")
        for lang, r in list(d["languages"].items()) + [("all", d["overall"])]:
            print(f"  {lang:10} pairs {r['pairs']:3}  " + "  ".join(
                f"{m} {r[f'recall_{m}']['k']}/{r[f'recall_{m}']['n']}" for m in METRICS)
                + f"  persists {r['fixed_side_persistence']['k']}/{r['fixed_side_persistence']['n']}")
    print(f"not assessed: dev {dev_doc['not_assessed']}, sealed {sealed_doc['not_assessed']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["fetch", "score"])
    ap.add_argument("--pairs", type=Path, default=HERE / "ghsa_pairs.json")
    ap.add_argument("--dest", type=Path, default=Path("~/wt/corpus-gt/cve-ghsa"))
    ap.add_argument("--out-dev", type=Path, default=ROOT / "tools" / "gold" / "results" / "ghsa-dev.json")
    ap.add_argument("--out-sealed", type=Path,
                    default=ROOT / "tools" / "gold" / "results" / "ghsa-sealed-aggregate.json")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    args = ap.parse_args(argv)
    doc = json.loads(args.pairs.read_text(encoding="utf-8"))
    if args.cmd == "fetch":
        errors = fetch(doc["pairs"], args.dest.expanduser())
        print("\n".join(errors), file=sys.stderr)
        n = sum(_fetched(p, args.dest.expanduser()) for p in doc["pairs"])
        print(f"{n}/{len(doc['pairs'])} pairs fetched at both commits; {len(errors)} file(s) failed")
        return 0
    return score(args)


if __name__ == "__main__":
    raise SystemExit(main())
