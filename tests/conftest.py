"""Fixtures shared across the suite.

The two fixture scans are the most expensive thing the tests do, and more
than one file needs them. Session scope means the suite pays for each once
rather than once per file -- without this, adding a second file that scans
`fixtures/legacy-platform` doubles the wall clock of the pull-request gate.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from arbiter.engine import run_scan
from arbiter.policy import load_config

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "fixtures" / "legacy-platform"
SYSTEM = ROOT / "fixtures" / "system" / "arbiter-system.yaml"

# The external analyzers are calibrated separately and are not always
# installed; a fixture scan measures Arbiter's own rules.
EXTERNAL = ["checkov", "semgrep", "bandit", "ruff", "gitleaks"]


@pytest.fixture(scope="session")
def legacy_report():
    cfg = load_config(None, str(LEGACY))
    return run_scan([str(LEGACY)], cfg, skip=EXTERNAL)


@pytest.fixture(scope="session")
def system_report():
    cfg = load_config(None)
    return run_scan([], cfg, system_path=str(SYSTEM), skip=EXTERNAL)
