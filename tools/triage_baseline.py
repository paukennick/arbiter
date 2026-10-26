#!/usr/bin/env python3
"""Repository-disjoint split and CPU baseline for Workstream C (ARB-113)."""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LABELS = [
    ROOT / "tools" / "gold" / "labels" / "ai-corpus-model.jsonl",
    ROOT / "tools" / "gold" / "labels" / "gold-model.jsonl",
]


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _family(repo: str) -> str:
    if repo.startswith("ai-corpus/"):
        parts = repo.split("/")
        return "ai-corpus:" + (parts[2] if len(parts) > 2 else repo)
    if "/" in repo:
        return repo.split("/")[-1].lower()
    return repo.lower()


def _label01(label: str) -> int | None:
    if label == "tp":
        return 1
    if label == "fp":
        return 0
    return None


def load_records(paths: list[Path]) -> list[dict]:
    out = []
    for path in paths:
        for row in read_jsonl(path):
            y = _label01(row.get("label", ""))
            if y is None:
                continue
            if row.get("held_out"):
                continue
            src = row.get("source", "")
            if src.startswith("arb109-") or src.startswith("calibration:") or src.startswith("heldout-"):
                continue
            repo = row.get("repo")
            rule = row.get("rule_id")
            if not repo or not rule:
                continue
            out.append({
                "repo": repo,
                "family": _family(repo),
                "rule_id": rule,
                "language": row.get("language") or "",
                "confidence": row.get("confidence") or "",
                "severity": row.get("severity") or "",
                "y": y,
            })
    return out


def _stats(rows: list[dict]) -> dict:
    return {
        "n": len(rows),
        "tp": sum(r["y"] for r in rows),
        "fp": sum(1 - r["y"] for r in rows),
        "repos": len({r["repo"] for r in rows}),
        "families": len({r["family"] for r in rows}),
    }


def build_split(rows: list[dict], seed: int = 113, valid_ratio: float = 0.25,
                min_valid_families: int = 6) -> dict:
    by_family: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_family[r["family"]].append(r)
    families = sorted(by_family)
    rng = random.Random(seed)
    rng.shuffle(families)
    families.sort(key=lambda f: len(by_family[f]), reverse=True)

    total = len(rows)
    target_valid = int(round(total * valid_ratio))
    valid_families: set[str] = set()
    valid_n = 0
    for fam in families:
        n = len(by_family[fam])
        if valid_n >= target_valid and len(valid_families) >= min_valid_families:
            continue
        if len(valid_families) < min_valid_families:
            valid_families.add(fam)
            valid_n += n
            continue
        if abs((valid_n + n) - target_valid) <= abs(valid_n - target_valid) or valid_n < max(20, target_valid // 2):
            valid_families.add(fam)
            valid_n += n

    valid = [r for r in rows if r["family"] in valid_families]
    train = [r for r in rows if r["family"] not in valid_families]
    return {
        "seed": seed,
        "valid_ratio": valid_ratio,
        "valid_families": sorted(valid_families),
        "train_families": sorted(set(by_family) - valid_families),
        "train_stats": _stats(train),
        "valid_stats": _stats(valid),
    }


def _smoothed_precision(tp: int, fp: int, alpha: float = 1.0) -> float:
    return (tp + alpha) / (tp + fp + 2 * alpha)


def _fit(train: list[dict]) -> dict:
    rl = Counter()
    rtot = Counter()
    gtp = gfp = 0
    for r in train:
        k = (r["rule_id"], r["language"])
        rl[(k, r["y"])] += 1
        rtot[(r["rule_id"], r["y"])] += 1
        if r["y"]:
            gtp += 1
        else:
            gfp += 1
    return {"rule_lang": rl, "rule": rtot, "global": (gtp, gfp)}


def _score(model: dict, row: dict) -> float:
    tp, fp = model["global"]
    base = _smoothed_precision(tp, fp)
    k = (row["rule_id"], row["language"])
    rlk = model["rule_lang"]
    rk = model["rule"]
    n_rl = rlk[(k, 1)] + rlk[(k, 0)]
    if n_rl >= 4:
        base = _smoothed_precision(rlk[(k, 1)], rlk[(k, 0)])
    else:
        n_r = rk[(row["rule_id"], 1)] + rk[(row["rule_id"], 0)]
        if n_r:
            base = _smoothed_precision(rk[(row["rule_id"], 1)], rk[(row["rule_id"], 0)])
    c = (row.get("confidence") or "").lower()
    if c == "high":
        base += 0.04
    elif c == "low":
        base -= 0.04
    return max(0.001, min(0.999, base))


def _average_precision(scored: list[tuple[float, int]]) -> float | None:
    pos = sum(y for _, y in scored)
    if pos == 0:
        return None
    scored = sorted(scored, key=lambda x: x[0], reverse=True)
    hits = 0
    total = 0.0
    for i, (_s, y) in enumerate(scored, start=1):
        if y:
            hits += 1
            total += hits / i
    return round(total / pos, 3)


def _precision_at(scored: list[tuple[float, int]], k: int) -> float | None:
    if not scored:
        return None
    rows = sorted(scored, key=lambda x: x[0], reverse=True)[: min(k, len(scored))]
    return round(sum(y for _, y in rows) / len(rows), 3)


def evaluate(rows: list[dict], split: dict) -> dict:
    vf = set(split["valid_families"])
    train = [r for r in rows if r["family"] not in vf]
    valid = [r for r in rows if r["family"] in vf]
    model = _fit(train)
    scored = [(_score(model, r), r["y"]) for r in valid]
    out = {
        "train": _stats(train),
        "valid": _stats(valid),
        "metrics": {
            "average_precision": _average_precision(scored),
            "precision_at_10": _precision_at(scored, 10),
            "precision_at_20": _precision_at(scored, 20),
            "precision_at_50": _precision_at(scored, 50),
            "precision_at_100": _precision_at(scored, 100),
            "base_rate_valid": round(sum(r["y"] for r in valid) / len(valid), 3) if valid else None,
        },
    }
    return out


def build_folds(rows: list[dict], k: int = 5, seed: int = 113) -> list[list[str]]:
    by_family: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_family[r["family"]].append(r)
    fams = sorted(by_family)
    rng = random.Random(seed)
    rng.shuffle(fams)
    fams.sort(key=lambda f: len(by_family[f]), reverse=True)
    folds: list[list[str]] = [[] for _ in range(k)]
    load = [0] * k
    for fam in fams:
        idx = min(range(k), key=lambda i: (load[i], i))
        folds[idx].append(fam)
        load[idx] += len(by_family[fam])
    return [sorted(f) for f in folds]


def evaluate_cv(rows: list[dict], folds: list[list[str]]) -> dict:
    metrics = []
    all_scored: list[tuple[float, int]] = []
    for i, vf in enumerate(folds):
        vset = set(vf)
        train = [r for r in rows if r["family"] not in vset]
        valid = [r for r in rows if r["family"] in vset]
        model = _fit(train)
        scored = [(_score(model, r), r["y"]) for r in valid]
        all_scored.extend(scored)
        metrics.append({
            "fold": i,
            "families": len(vf),
            "rows": len(valid),
            "average_precision": _average_precision(scored),
            "base_rate": round(sum(y for _, y in scored) / len(scored), 3) if scored else None,
            "precision_at_20": _precision_at(scored, 20),
            "precision_at_50": _precision_at(scored, 50),
        })
    aps = [m["average_precision"] for m in metrics if m["average_precision"] is not None]
    return {
        "folds": metrics,
        "overall": {
            "rows": len(all_scored),
            "average_precision": _average_precision(all_scored),
            "precision_at_20": _precision_at(all_scored, 20),
            "precision_at_50": _precision_at(all_scored, 50),
            "base_rate": round(sum(y for _, y in all_scored) / len(all_scored), 3) if all_scored else None,
            "average_precision_mean": round(sum(aps) / len(aps), 3) if aps else None,
            "average_precision_min": min(aps) if aps else None,
            "average_precision_max": max(aps) if aps else None,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("split", help="Build a deterministic repository-family split")
    sp.add_argument("--labels", nargs="+", type=Path, default=DEFAULT_LABELS)
    sp.add_argument("--seed", type=int, default=113)
    sp.add_argument("--valid-ratio", type=float, default=0.25)
    sp.add_argument("--min-valid-families", type=int, default=6)
    sp.add_argument("--out", type=Path, required=True)

    ep = sub.add_parser("eval", help="Evaluate the CPU baseline on a saved split")
    ep.add_argument("--labels", nargs="+", type=Path, default=DEFAULT_LABELS)
    ep.add_argument("--split", type=Path, required=True)
    ep.add_argument("--json", type=Path, required=True)

    cp = sub.add_parser("cv", help="Repository-family cross-validation")
    cp.add_argument("--labels", nargs="+", type=Path, default=DEFAULT_LABELS)
    cp.add_argument("--folds", type=int, default=5)
    cp.add_argument("--seed", type=int, default=113)
    cp.add_argument("--json", type=Path, required=True)

    a = ap.parse_args(argv)
    rows = load_records(a.labels)

    if a.cmd == "split":
        split = build_split(rows, a.seed, a.valid_ratio, a.min_valid_families)
        a.out.write_text(json.dumps(split, indent=1) + "\n", encoding="utf-8")
        print(json.dumps({"rows": len(rows), **split["train_stats"], "valid": split["valid_stats"]["n"]}, indent=1))
        return 0
    if a.cmd == "cv":
        folds = build_folds(rows, a.folds, a.seed)
        res = evaluate_cv(rows, folds)
        a.json.write_text(json.dumps({"fold_families": folds, **res}, indent=1) + "\n", encoding="utf-8")
        print(json.dumps(res["overall"], indent=1))
        return 0

    split = json.loads(a.split.read_text(encoding="utf-8"))
    res = evaluate(rows, split)
    a.json.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(res["metrics"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
