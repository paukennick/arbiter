#!/usr/bin/env python3
"""Freeze the r7 Python breadth set (ARB-163) -- now a thin wrapper.

The filters live in tools/freeze_breadth.py (ARB-166), which also freezes the
other languages. The Python configuration there (topics, >= 1000 stars, 180
repos, 45 dev, seed 20261026) is the one tools/gold/breadth-r7-python-repos.json
was frozen with on 2026-10-26; that committed manifest is the frozen record and
is never rewritten in place, so --out is required.

    python tools/freeze_breadth_python.py --out some/other/path.json
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import freeze_breadth  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--total", type=int, default=180)
    ap.add_argument("--dev", type=int, default=45)
    a = ap.parse_args()
    return freeze_breadth.main(["--language", "python", "--out", a.out,
                                "--total", str(a.total), "--dev", str(a.dev)])


if __name__ == "__main__":
    sys.exit(main())
