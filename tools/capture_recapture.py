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
import math
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

SCANS = ROOT / "arbiter-out" / "capture" / "scans"
CORPORA = {"gold": Path("~/wt/corpus-gold").expanduser(),
           "juliet": Path("~/wt/corpus-gt").expanduser()}
# A stratum below this many confirmed defects, or with no defect found by two
# detectors, is reported "not estimable" rather than as a number (plan).
MIN_SITES = 10
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


# ---------------------------------------------------------------------------
# Detectors and what each covers
# ---------------------------------------------------------------------------

DETECTORS = ("arbiter", "semgrep", "bandit")
LANG_OF = {"owasp-benchmark-python": "python", "owasp-benchmark-java": "java",
           "juliet-java": "java"}

# Bandit's checks by family, from its plugin and blacklist catalog (bandit
# 1.9.4, `tooling.json`), folded the way `arbiter.capture.RULE_FAMILIES` folds
# them. Python only.
BANDIT_FAMILIES = frozenset({
    "sql-injection",       # B608, B610, B611
    "command-injection",   # B60x
    "code-injection",      # B102, B307
    "deserialization",     # B301, B506
    "path-traversal",      # B202
    "xss",                 # B308, B701, B703
    "xxe",                 # B313-B320, B405-B410
    "weak-crypto",         # B303, B304, B324, B505
    "weak-random",         # B311
    "tls-verification",    # B501, B323
    "hardcoded-secret",    # B105-B107
    "missing-timeout",     # B113
})


def _semgrep_families(language: str) -> set[str]:
    """Families the pinned semgrep-rules checkout covers for one language,
    from each rule's own CWE metadata, in the directory the adapter loads."""
    import yaml
    from arbiter import capture
    from arbiter.adapters import cache_dir
    from arbiter.cwe import normalise
    out: set[str] = set()
    base = cache_dir() / "semgrep-rules" / language
    for p in sorted(base.rglob("*.yaml")):
        if ".test." in p.name:
            continue
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        rules = doc.get("rules", []) if isinstance(doc, dict) else []
        for r in rules:
            if not isinstance(r, dict):
                continue
            fam = capture.family_of("semgrep", f"semgrep/{r.get('id', '')}",
                                    normalise((r.get("metadata") or {}).get("cwe")))
            if fam:
                out.add(fam)
    return out


def _arbiter_families(language: str) -> set[str]:
    from arbiter import capture
    from arbiter.lang_rules import load_packs
    out = set()
    for r in load_packs().get(language, {}).get("rules", []):
        fam = capture.family_of("arbiter", f"arbiter/{language}.{r.get('id', '')}", r.get("cwe") or [])
        if fam:
            out.add(fam)
    return out


def coverage(language: str) -> dict[str, set[str]]:
    """detector -> families it has at least one rule for in this language.
    Decided from the rules, never from what a scan happened to report."""
    return {"arbiter": _arbiter_families(language),
            "semgrep": _semgrep_families(language),
            "bandit": set(BANDIT_FAMILIES) if language == "python" else set()}


def detector_of(f: dict) -> str:
    return f["probe"] if "external-tool" in f.get("tags", []) else "arbiter"


def load_scan(path: Path) -> dict:
    """One scan file; findings get `detector`, `family`, `repo`. A finding the
    engine merged across tools (`also:<probe>` tag) counts for each tool."""
    from arbiter import capture
    doc = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for f in doc["findings"]:
        det = detector_of(f)
        fam = capture.family_of(det, f["rule"], f.get("cwe") or [])
        if not fam or not f.get("path"):
            continue
        dets = {det} | {t[5:] for t in f.get("tags", []) if t.startswith("also:")}
        for d in sorted(dets & set(DETECTORS)):
            rows.append({**f, "detector": d, "family": fam, "repo": doc["name"]})
    ran = {d for d in DETECTORS
           if d == "arbiter" or doc["probes"].get(d, {}).get("status") == "ran"}
    return {"name": doc["name"], "findings": rows, "ran": ran}


# ---------------------------------------------------------------------------
# Validation on benchmarks with known truth
# ---------------------------------------------------------------------------

def juliet_case(path: str) -> str:
    """Every file of one Juliet case maps to one id: `..._51a.java`,
    `..._51b.java` -> `..._51`; `..._81_bad.java`, `..._81_goodG2B.java` ->
    `..._81`; a single-file case is its own stem."""
    stem = Path(path).stem
    m = re.match(r"^(.*_\d+)(?:[a-z]|_bad|_good\w*|_base)$", stem)
    return m.group(1) if m else stem


def truth_owasp(name: str) -> tuple[dict[str, set[str]], Callable]:
    """family -> real case ids, and finding -> case id (or None when the
    finding is not on a real case of its own family)."""
    import gold_benchmark as gb
    from arbiter import capture
    cfg = json.loads((ROOT / "tools" / "gold" / "benchmarks.json").read_text(encoding="utf-8"))[name]
    expected = gb.read_expected(CORPORA["gold"] / name / cfg["expected_results"])
    aliases = cfg.get("cwe_aliases", {})
    fam_of_case = {case: capture.family_of("truth", "", [e["cwe"], *aliases.get(e["cwe"], [])])
                   for case, e in expected.items()}
    real: dict[str, set[str]] = {}
    for case, e in expected.items():
        if e["real"] and fam_of_case[case]:
            real.setdefault(fam_of_case[case], set()).add(case)
    prefix = cfg["test_dir"].rstrip("/") + "/"

    def case_of(f: dict) -> str | None:
        if not f["path"].startswith(prefix):
            return None
        case = Path(f["path"]).stem
        e = expected.get(case)
        return case if e and e["real"] and fam_of_case[case] == f["family"] else None
    return real, case_of


def truth_juliet() -> tuple[dict[str, set[str]], Callable]:
    """Juliet: every case has one flawed (`bad`) variant, so every case in a
    directory is one real defect; a finding is on it when it sits in a `bad`
    method (`benchmarks_gt.juliet_side`)."""
    sys.path.insert(0, str(ROOT / "tools" / "ground_truth"))
    import benchmarks_gt as bg
    from arbiter import capture
    root = CORPORA["juliet"] / "juliet-java"
    real: dict[str, set[str]] = {}
    fam_dir = {d: capture.family_of("truth", "", cwes) for d, cwes in bg.JULIET_DIRS.items()}
    for d, fam in fam_dir.items():
        if not fam:
            continue
        for p in sorted((root / "Java" / "src" / "testcases" / d).rglob("*.java")):
            real.setdefault(fam, set()).add(juliet_case(p.name))
    texts: dict[str, str] = {}

    def case_of(f: dict) -> str | None:
        d = next((x for x in Path(f["path"]).parts if x in fam_dir), None)
        if d is None or fam_dir[d] != f["family"]:
            return None
        p = root / f["path"]
        if f["path"] not in texts:
            texts[f["path"]] = p.read_text(encoding="utf-8", errors="replace")
        side = bg.juliet_side(texts[f["path"]], str(p), int(f["line"]))
        return juliet_case(f["path"]) if side == "bad" else None
    return real, case_of


def _clean(e: dict) -> dict:
    keep = ("method", "n_hat", "lo", "hi", "observed", "pairs", "aic", "df",
            "f1", "f2", "n1", "n2", "m")
    out = {}
    for k, v in e.items():
        if k not in keep:
            continue
        if isinstance(v, float):
            v = round(v, 2) if math.isfinite(v) else "inf"
        out[k] = v
    return out


def _rate(r: dict) -> dict:
    return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()}


def stratum_result(language: str, family: str, dets: list[str], caught: dict[str, set],
                   true_total: float | None = None, weights: dict[str, float] | None = None) -> dict:
    """caught: defect id -> detectors that found it. `weights` (defect id ->
    how many defects it stands for) is for sampled development sites."""
    from arbiter import capture
    w = weights or {}
    hist: dict = {}
    for k, ds in caught.items():
        h = tuple(1 if d in ds else 0 for d in dets)
        if any(h):
            hist[h] = hist.get(h, 0.0) + w.get(k, 1.0)
    found = {d: sum(w.get(k, 1.0) for k, ds in caught.items() if d in ds) for d in dets}
    union = sum(hist.values())
    multi = sum(v for h, v in hist.items() if sum(h) >= 2)
    out = {"language": language, "family": family, "detectors": dets,
           "found": {d: round(v, 2) for d, v in found.items()}, "union": round(union, 2),
           "true_total": true_total,
           "histories": {"".join(map(str, h)): round(v, 2) for h, v in sorted(hist.items())}}
    if len(dets) < 2 or union < MIN_SITES or multi == 0:
        out["estimable"] = False
        out["why"] = ("fewer than two detectors cover it" if len(dets) < 2 else
                      f"{union:g} confirmed defects (< {MIN_SITES})" if union < MIN_SITES else
                      "no defect found by two detectors")
        return out
    est = capture.estimate(hist)
    out["estimable"] = True
    out["primary"] = _clean(est)
    if len(dets) >= 3:
        out["chao"] = _clean(capture.chao_lower_bound(hist))
    out["pairs"] = {f"{dets[i]}+{dets[j]}": _clean(capture.two_way(hist, i, j))
                    for i in range(len(dets)) for j in range(i + 1, len(dets))}
    out["rates"] = {d: _rate(capture.catch_rate(found[d], est)) for d in dets}
    out["rates"]["union"] = _rate(capture.catch_rate(union, est))
    return out


def validate(scans: Path) -> list[dict]:
    out = []
    for name, truth in (("owasp-benchmark-python", lambda: truth_owasp("owasp-benchmark-python")),
                        ("owasp-benchmark-java", lambda: truth_owasp("owasp-benchmark-java")),
                        ("juliet-java", truth_juliet)):
        p = scans / f"{name}.json"
        if not p.is_file():
            continue
        lang = LANG_OF[name]
        cov = coverage(lang)
        scan = load_scan(p)
        real, case_of = truth()
        for fam in sorted(real):
            dets = [d for d in DETECTORS if fam in cov[d] and d in scan["ran"]]
            caught: dict[str, set] = {}
            for f in scan["findings"]:
                if f["family"] != fam or f["detector"] not in dets:
                    continue
                case = case_of(f)
                if case:
                    caught.setdefault(case, set()).add(f["detector"])
            r = stratum_result(lang, fam, dets, caught, true_total=len(real[fam]))
            r["benchmark"] = name
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Development data: sites, labels, estimates
# ---------------------------------------------------------------------------

# Development corpora only (plan: gold dev repositories and the breadth
# `slice: "dev"` Python repositories). Held-out sets are never listed here.
DEV_SETS = {"gold-dev": Path("~/wt/corpus-gold-dev").expanduser(),
            "r7py-dev": Path("~/wt/corpus-r7py-dev").expanduser()}

_EXT_LANG = {".py": "python", ".java": "java", ".go": "go", ".rb": "ruby", ".ts": "typescript",
             ".tsx": "typescript", ".js": "typescript", ".mjs": "typescript", ".cjs": "typescript",
             ".jsx": "typescript"}
_SEMGREP_DIRS = {"typescript": ("typescript", "javascript")}

# The family's claim is the existing claim text of one Arbiter rule pattern
# (label_models.CLAIMS), reused word for word: a site is labelled under a
# rule id that matches that pattern. Families with no claim that fits every
# detector's findings (weak-crypto: the only claim is about password hashing;
# xxe, insecure-cookie, open-redirect: none) are not labelled (plan, step 5).
CLAIM_RULE = {
    "sql-injection": "capture/{lang}.sql-injection",
    "command-injection": "capture/{lang}.command-injection",
    "code-injection": "capture/{lang}.code-injection",
    "deserialization": "capture/{lang}.unsafe-deserialization",
    "path-traversal": "capture/{lang}.path-traversal",
    "xss": "capture/{lang}.xss-unescaped-html",
    "ssrf": "capture/{lang}.ssrf-request",
    "weak-random": "capture/{lang}.insecure-random-for-secret",
    "tls-verification": "capture/{lang}.tls-verify-off",
    "hardcoded-secret": "arbiter/secrets.capture-site",
    "missing-timeout": "capture/{lang}.http-no-timeout",
    "info-exposure": "capture/{lang}.error-message-to-client",
}


def lang_of_path(path: str) -> str | None:
    return _EXT_LANG.get(Path(path).suffix.lower())


def dev_coverage() -> dict[str, dict[str, set[str]]]:
    out = {}
    for lang in ("python", "java", "go", "ruby", "typescript"):
        sem: set[str] = set()
        for d in _SEMGREP_DIRS.get(lang, (lang,)):
            sem |= _semgrep_families(d)
        out[lang] = {"arbiter": _arbiter_families(lang), "semgrep": sem,
                     "bandit": set(BANDIT_FAMILIES) if lang == "python" else set()}
    return out


def dev_sites(scans: Path) -> list[dict]:
    """Every family site in the development scans, in strata (language,
    family) that at least two detectors cover. Each site: repo, set, path,
    line, language, family, detectors that ran on that repository and caught
    it, site id, and the member finding the label is asked about."""
    from arbiter import capture
    cov = dev_coverage()
    out = []
    for set_name, corpus in DEV_SETS.items():
        names = sorted(p.name for p in corpus.iterdir() if p.is_dir()) if corpus.is_dir() else []
        for name in names:
            p = scans / f"{name}.json"
            if not p.is_file():
                continue
            scan = load_scan(p)
            rows = []
            for f in scan["findings"]:
                lang = lang_of_path(f["path"])
                if lang and f["family"] in cov[lang][f["detector"]] and f["detector"] in scan["ran"]:
                    rows.append({**f, "language": lang})
            for s in capture.cluster_sites(rows):
                repo, path, fam = s["key"]
                lang = s["members"][0]["language"]
                dets = [d for d in DETECTORS if fam in cov[lang][d]]
                if len(dets) < 2:
                    continue
                rep = next((m for m in s["members"] if m["detector"] == "arbiter"), s["members"][0])
                out.append({"set": set_name, "repo": repo, "path": path, "line": s["line"],
                            "language": lang, "family": fam, "detectors": s["detectors"],
                            "stratum_detectors": dets, "ran": sorted(scan["ran"]),
                            "site_id": f"site:{repo}|{path}|{fam}|{s['line']}",
                            "rep": {"id": rep["id"], "rule": rep["rule"], "line": rep["line"],
                                    "cwe": rep.get("cwe", []), "severity": rep.get("severity", "")},
                            "members": sorted({(m["detector"], m["rule"], int(m["line"] or 0))
                                               for m in s["members"]})})
    return out


def existing_labels(paths: list[Path]) -> dict[tuple, str]:
    """(repo, path, line, rule) -> label, development rows only."""
    out = {}
    for p in paths:
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("held_out"):
                continue
            out[(r.get("repo"), r.get("path"), int(r.get("line") or 0), r.get("rule_id"))] = r["label"]
    return out


def site_label(site: dict, known: dict[tuple, str], capture_labels: dict[str, str]) -> str | None:
    if site["site_id"] in capture_labels:
        return capture_labels[site["site_id"]]
    for det, rule, line in site["members"]:
        lab = known.get((site["repo"], site["path"], line, rule))
        if lab:
            return lab
    return None


def labelling_report(sites: list[dict], set_name: str) -> dict:
    """A gold-report-shaped document `tools/label_models.py label --report`
    reads unchanged: one raw finding per unlabelled claimable site, under a
    rule id whose pattern carries the family's existing claim text. The
    finding id is the site id hashed, so labels map back to sites."""
    import hashlib
    raw: dict[str, list] = {}
    for s in sites:
        if s["set"] != set_name or s["family"] not in CLAIM_RULE:
            continue
        rid = CLAIM_RULE[s["family"]].format(lang=s["language"])
        fid = "f:" + hashlib.sha256(s["site_id"].encode()).hexdigest()[:12]
        raw.setdefault(s["repo"], []).append(
            {"id": fid, "rule": rid, "path": s["path"], "line": s["rep"]["line"],
             "cwe": s["rep"]["cwe"], "severity": s["rep"]["severity"], "probe": "capture",
             "confidence": "", "title": ""})
    return {"raw_findings": {k: sorted(v, key=lambda f: (f["path"], f["line"])) for k, v in sorted(raw.items())},
            "repos": [{"name": k, "language": ""} for k in sorted(raw)]}


def site_fid(site: dict) -> str:
    import hashlib
    return "f:" + hashlib.sha256(site["site_id"].encode()).hexdigest()[:12]


def dev_estimates(sites: list[dict], labels: dict[str, str]) -> list[dict]:
    """Per (language, family): capture histories over tp sites only, pooled
    over repositories, with a repository bootstrap interval beside the
    primary one. `labels` maps site id -> tp/fp/unsure; unlabelled sites are
    left out and counted."""
    from arbiter import capture
    strata: dict[tuple, list[dict]] = {}
    for s in sites:
        strata.setdefault((s["language"], s["family"]), []).append(s)
    out = []
    for (lang, fam), rows in sorted(strata.items()):
        dets = rows[0]["stratum_detectors"]
        # Every detector must have run on every repository of the stratum.
        rows = [s for s in rows if set(dets) <= set(s["ran"])]
        tp = [s for s in rows if labels.get(s["site_id"]) == "tp"]
        caught = {s["site_id"]: set(s["detectors"]) for s in tp}
        r = stratum_result(lang, fam, dets, caught)
        r["sites"] = len(rows)
        r["labelled"] = sum(1 for s in rows if s["site_id"] in labels)
        r["tp"] = len(tp)
        r["repos_with_tp"] = len({s["repo"] for s in tp})
        if r["estimable"] and r["repos_with_tp"] >= 5:
            groups: dict[str, dict] = {}
            for s in tp:
                h = tuple(1 if d in s["detectors"] else 0 for d in dets)
                g = groups.setdefault(s["repo"], {})
                g[h] = g.get(h, 0) + 1
            ci = capture.bootstrap_ci([groups[k] for k in sorted(groups)],
                                      lambda hh: capture.estimate(hh)["n_hat"] if len(hh) > 0 else None,
                                      b=400, seed=f"capture|{lang}|{fam}")
            r["bootstrap"] = [round(ci[0], 2), round(ci[1], 2)] if ci else None
        out.append(r)
    return out


def _fmt(v) -> str:
    if v is None:
        return "–"
    if v == "inf" or (isinstance(v, float) and math.isinf(v)):
        return "∞"
    return f"{v:g}" if isinstance(v, (int, float)) else str(v)


def _pct(v) -> str:
    return "–" if v is None else f"{100 * v:.0f}%"


def render_rows(rows: list[dict], truth: bool) -> list[str]:
    head = ["Language", "Family"] + (["Set"] if truth else []) + \
        ["Detectors", "Found (A/S/B)", "Union", "N̂ [95% CI]"] + (["True total"] if truth else []) + \
        ["Arbiter catch rate", "Union catch rate", "Note"]
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        found = "/".join(_fmt(r["found"].get(d)) if d in r["found"] else "–" for d in DETECTORS)
        if r["estimable"]:
            p = r["primary"]
            nh = f"{_fmt(p['n_hat'])} [{_fmt(p['lo'])}, {_fmt(p['hi'])}]"
            ar = r["rates"].get("arbiter")
            arb = f"{_pct(ar['rate'])} [{_pct(ar['lo'])}, {_pct(ar['hi'])}]" if ar else "–"
            un = r["rates"]["union"]
            uni = f"{_pct(un['rate'])} [{_pct(un['lo'])}, {_pct(un['hi'])}]"
            note = p["method"] + (f", Chao {_fmt(r['chao']['n_hat'])}" if "chao" in r else "")
        else:
            nh, arb, uni, note = "not estimable", "–", "–", r["why"]
        cells = [r["language"], r["family"]] + ([r.get("benchmark", "")] if truth else []) + \
            [", ".join(r["detectors"]) or "none", found, _fmt(r["union"]), nh] + \
            ([_fmt(r["true_total"])] if truth else []) + [arb, uni, note]
        out.append("| " + " | ".join(cells) + " |")
    return out


def cmd_validate(a) -> int:
    rows = validate(Path(a.scans))
    out = Path(a.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=1, sort_keys=True), encoding="utf-8")
    print("\n".join(render_rows(rows, truth=True)))
    return 0


DEFAULT_LABELS = [ROOT / "tools" / "gold" / "labels" / "gold-model.jsonl"]
CAPTURE_LABELS = ROOT / "tools" / "gold" / "labels" / "capture-dev-model.jsonl"


def _capture_labels(path: Path, sites: list[dict]) -> dict[str, str]:
    by_fid = {site_fid(s): s["site_id"] for s in sites}
    out = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                if r["finding_id"] in by_fid:
                    out[by_fid[r["finding_id"]]] = r["label"]
    return out


def _all_labels(sites: list[dict], label_files: list[Path], capture_file: Path) -> dict[str, str]:
    known = existing_labels(label_files)
    cap = _capture_labels(capture_file, sites)
    out = {}
    for s in sites:
        lab = site_label(s, known, cap)
        if lab:
            out[s["site_id"]] = lab
    return out


def cmd_sites(a) -> int:
    """Sites, what is already labelled, and one label report per dev set for
    the sites still unlabelled (input to label_models.py --report)."""
    from collections import Counter
    sites = dev_sites(Path(a.scans))
    labels = _all_labels(sites, [Path(p) for p in a.labels], Path(a.capture_labels))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "sites.json").write_text(json.dumps(sites, indent=0, sort_keys=True), encoding="utf-8")
    todo = [s for s in sites if s["site_id"] not in labels]
    for set_name in DEV_SETS:
        rep = labelling_report(todo, set_name)
        (out / f"label-report-{set_name}.json").write_text(json.dumps(rep, indent=0), encoding="utf-8")
    by = Counter((s["language"], s["family"], "+".join(s["detectors"])) for s in sites)
    for k, n in sorted(by.items()):
        print(f"{k[0]:<11} {k[1]:<18} {k[2]:<24} {n}")
    print(f"{len(sites)} sites, {len(labels)} already labelled, {len(todo)} unlabelled, "
          f"{sum(1 for s in todo if s['family'] in CLAIM_RULE)} claimable")
    return 0


def cmd_dev(a) -> int:
    sites = json.loads((Path(a.sites)).read_text(encoding="utf-8"))
    labels = _all_labels(sites, [Path(p) for p in a.labels], Path(a.capture_labels))
    rows = dev_estimates(sites, labels)
    Path(a.json).write_text(json.dumps(rows, indent=1, sort_keys=True), encoding="utf-8")
    print("\n".join(render_rows(rows, truth=False)))
    return 0


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
    v = sub.add_parser("validate", help="estimate vs true total on OWASP Benchmark and Juliet")
    v.add_argument("--scans", default=str(SCANS))
    v.add_argument("--json", default=str(ROOT / "arbiter-out" / "capture" / "validate.json"))
    st = sub.add_parser("sites", help="development sites, existing labels, label reports")
    st.add_argument("--scans", default=str(SCANS))
    st.add_argument("--labels", nargs="*", default=[str(p) for p in DEFAULT_LABELS])
    st.add_argument("--capture-labels", default=str(CAPTURE_LABELS))
    st.add_argument("--out", default=str(ROOT / "arbiter-out" / "capture"))
    dv = sub.add_parser("dev", help="estimates on development data")
    dv.add_argument("--sites", default=str(ROOT / "arbiter-out" / "capture" / "sites.json"))
    dv.add_argument("--labels", nargs="*", default=[str(p) for p in DEFAULT_LABELS])
    dv.add_argument("--capture-labels", default=str(CAPTURE_LABELS))
    dv.add_argument("--json", default=str(ROOT / "arbiter-out" / "capture" / "dev.json"))
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        return cmd_scan(a)
    if a.cmd == "validate":
        return cmd_validate(a)
    if a.cmd == "sites":
        return cmd_sites(a)
    if a.cmd == "dev":
        return cmd_dev(a)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
