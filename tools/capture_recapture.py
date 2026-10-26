#!/usr/bin/env python3
"""Capture-recapture catch-rate estimate (ARB-172, Workstream D item D6).

    # 1. Scan with every adapter, one JSON per repository (resumable).
    python tools/capture_recapture.py scan --corpus ~/wt/corpus-gold --only owasp-benchmark-python
    # 2. Benchmarks with known truth: estimate vs the true total.
    python tools/capture_recapture.py validate --out tools/gold/results/2026-10-26-capture-recapture.md
    # 3. Development data: capture histories from labelled sites.
    python tools/capture_recapture.py sites --set gold-dev --labels ... --out sites.json

The estimators and the matching rule live in `arbiter.capture`; this file
only gathers findings and truth and writes results. Held-out sets are not
read here (see docs/catch-rate.md, "Running it on held-out data").
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCANS = ROOT / "arbiter-out" / "capture" / "scans"
# Semgrep's adapter declares 600 s. On a large repository a timeout reads as
# "semgrep ran and found nothing" to the estimator unless recorded, so the scan
# gives every tool an hour and records each tool's status per repository.
SCAN_TIMEOUT = 3600


def scan_one(args: tuple[str, str, str]) -> str:
    path, name, out_dir = args
    out = Path(out_dir) / f"{name}.json"
    if out.is_file():
        return f"have {name}"
    from arbiter.adapters import register_adapters
    from arbiter.engine import run_scan
    from arbiter.policy import load_config
    for a in register_adapters():
        a.timeout = max(a.timeout, SCAN_TIMEOUT)
    started = time.time()
    rep = run_scan([path], load_config(None), use_adapters=True, use_cache=False)
    doc = {
        "name": name,
        "seconds": round(time.time() - started, 1),
        "probes": {o.name: {"status": o.status, "reason": o.reason[:300],
                            "findings": o.finding_count, "version": o.version}
                   for o in rep.probes},
        "findings": [{"id": f.id, "rule": f.rule_id, "probe": f.probe, "path": f.location.path,
                      "line": f.location.start_line, "cwe": list(f.cwe), "tags": list(f.tags),
                      "severity": f.severity, "title": f.title[:160]}
                     for f in rep.active()],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=0, sort_keys=True), encoding="utf-8")
    return f"done {name} {len(doc['findings'])} findings {doc['seconds']}s"


def cmd_scan(a) -> int:
    corpus = Path(a.corpus).expanduser()
    names = a.only.split(",") if a.only else sorted(p.name for p in corpus.iterdir() if p.is_dir())
    jobs = [(str(corpus / n), (a.prefix + n), str(Path(a.out))) for n in names if (corpus / n).is_dir()]
    if a.jobs <= 1:
        for j in jobs:
            print(scan_one(j), flush=True)
    else:
        with ProcessPoolExecutor(max_workers=a.jobs) as pool:
            for msg in pool.map(scan_one, jobs):
                print(msg, flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan repositories with Arbiter and every adapter")
    s.add_argument("--corpus", required=True)
    s.add_argument("--only")
    s.add_argument("--prefix", default="", help="prefix for the output file name")
    s.add_argument("--out", default=str(SCANS))
    s.add_argument("--jobs", type=int, default=2)
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        return cmd_scan(a)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
