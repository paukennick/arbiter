#!/usr/bin/env python3
"""Build the per-rule precision ledger from label files.

    # JSON-lines labels (docs/precision.md, "Label format"), from the model
    # labellers, external ground truth, or both:
    python tools/precision_ledger.py build labels/*.jsonl

    # label_sample.py sheets (CSV or JSON), one per labeller; the sheet has
    # no finding id, source or split, so they are given here:
    python tools/precision_ledger.py build --sheet-batch gold-2026-10 \\
        --sheet-source gold --sheet-held-out alice.csv bob.csv

    # What the shipped ledger is built from (current-version model labels;
    # superseded ones live under labels/history/ and are dropped anyway):
    python tools/precision_ledger.py build tools/gold/labels/*.jsonl tools/gold/labels/*.jsonl.gz

    python tools/precision_ledger.py show            # the ledger as a table
    python tools/precision_ledger.py check           # written ledger == rebuilt counts
    python tools/precision_ledger.py report          # tier claim per language (JS apart from TS)

The ledger is rebuilt from the label files every time, never edited by hand:
the label files are the evidence and the ledger is arithmetic on them. Two
things carry over from the previous ledger, because a label file does not
hold them: each rule's `fp_notes` (merged with the notes on FP labels), and
`updated` / `snapshot_counts` for a rule whose counts did not change, so the
CI precision guard can tell a re-label from a rebuild.

It writes tools/gold/precision.json and the copy shipped in the package
(src/arbiter/packs/precision.json); a test holds the two equal.
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arbiter import dawid_skene as DS  # noqa: E402
from arbiter import precision as P  # noqa: E402

LEDGER = ROOT / "tools" / "gold" / "precision.json"
PACKAGED = ROOT / "src" / "arbiter" / "packs" / "precision.json"
SNAPSHOTS = ROOT / "tools" / "gold" / "snapshots"
SNAPSHOT_TARGETS = ("planted", "ai-corpus")
LABELS = {"tp": "tp", "fp": "fp", "unsure": "unsure", "true": "tp", "false": "fp",
          "y": "tp", "n": "fp", "": "unsure"}
ABOUT = ("Per-rule precision ledger (docs/precision.md). Built by tools/precision_ledger.py "
         "from label files; do not edit by hand. A rule is admitted when its Wilson 95% lower "
         "bound reaches bar.rule_lower on at least bar.rule_min_n TP+FP labels, with labeller "
         "kappa at least bar.kappa_min where two labellers looked. `tier` is the claim: verified-"
         "tier precision on held-out labels only, stratified by (rule, source, language) and "
         "weighted by each stratum's population, overall and per category.")


# ---------------------------------------------------------------------------
# Reading labels
# ---------------------------------------------------------------------------

def norm_label(v) -> str:
    out = LABELS.get(str(v if v is not None else "").strip().lower())
    if out is None:
        raise ValueError(f"label must be tp, fp or unsure, got {v!r}")
    return out


def read_jsonl(path: Path) -> list[dict]:
    out = []
    if path.name.endswith(".gz"):
        import gzip
        text = gzip.decompress(path.read_bytes()).decode("utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            raise SystemExit(f"{path}:{i}: not JSON: {exc}") from exc
        missing = [k for k in ("finding_id", "rule_id", "label", "labeller", "source", "held_out")
                   if k not in rec]
        if missing:
            raise SystemExit(f"{path}:{i}: missing {', '.join(missing)}")
        if not isinstance(rec["held_out"], bool):
            raise SystemExit(f"{path}:{i}: held_out is true or false")
        try:
            rec["label"] = norm_label(rec["label"])
        except ValueError as exc:
            raise SystemExit(f"{path}:{i}: {exc}") from exc
        rec.setdefault("role", "labeller")
        if rec["role"] not in ROLES:
            raise SystemExit(f"{path}:{i}: role is labeller, adjudicator, mechanical or ground_truth")
        out.append(rec)
    return out


def drop_calibration(records: list[dict]) -> tuple[list[dict], int]:
    """Calibration records (`source` starting `calibration:`) relabel
    ground-truth items blind, or label planted good-twin lines no rule fired
    on. Counted in the ledger they would double-count ground truth or invent
    findings, so `labels/*.jsonl` is safe to pass whole."""
    keep = [r for r in records if not str(r.get("source", "")).startswith("calibration:")]
    return keep, len(records) - len(keep)


_MODEL_LABELLER = re.compile(r":prosecutor\+defender(?:\+adjudicator)?/(v\d+)$")
# The panel (tools/panel/panel.py, ARB-122): one record per model,
# `<seat>-<model>:panel/<version>`.
_PANEL_LABELLER = re.compile(r":(panel/v\d+)$")


def current_model_prompt() -> str:
    """The model labellers' prompt version (`tools/label_models.py`)."""
    m = re.search(r'^PROMPT_VERSION = "([^"]+)"', (ROOT / "tools" / "label_models.py").read_text(encoding="utf-8"),
                  re.M)
    return m.group(1) if m else ""


def current_panel_prompt() -> str:
    """The panel's prompt version (`tools/panel/panel.py` PANEL_VERSION)."""
    p = ROOT / "tools" / "panel" / "panel.py"
    m = re.search(r'^PANEL_VERSION = "([^"]+)"', p.read_text(encoding="utf-8"), re.M) if p.is_file() else None
    return m.group(1) if m else ""


def drop_superseded_panel_labels(records: list[dict], current: str) -> tuple[list[dict], int]:
    """Panel labels made with a panel prompt other than `current` (the
    same rule as `drop_superseded_model_labels`, for the panel's own
    version line). Empty `current` keeps every version."""
    if not current:
        return records, 0
    keep = [r for r in records
            if not (m := _PANEL_LABELLER.search(str(r.get("labeller", "")))) or m.group(1) == current]
    return keep, len(records) - len(keep)


def drop_superseded_model_labels(records: list[dict], current: str) -> tuple[list[dict], int]:
    """Model labels (`tools/label_models.py`, labeller `<model>:prosecutor+
    defender[+adjudicator]/<version>`) made with an older prompt than
    `current`. Each prompt version is a different labeller with its own
    calibration, and a finding labelled by two versions would be counted
    under whichever came last, so the ledger reads one version only. The
    superseded files are kept under `tools/gold/labels/history/`. Ground
    truth, sheets and other labellers pass through."""
    if not current:
        return records, 0
    keep = []
    for r in records:
        m = _MODEL_LABELLER.search(str(r.get("labeller", "")))
        if m and m.group(1) != current:
            continue
        keep.append(r)
    return keep, len(records) - len(keep)


def read_sheet(path: Path, batch: str, source: str, held_out: bool) -> list[dict]:
    """A label_sample.py sheet as label records. The finding is the sheet's
    sample id within `batch` (every copy of one sample shares its ids)."""
    if path.suffix == ".json":
        rows = json.loads(path.read_text(encoding="utf-8"))
    else:
        with path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        try:
            label = norm_label(r.get("verdict"))
        except ValueError:
            label = "unsure"
        out.append({"finding_id": f"{batch}:{r['sample_id']}", "rule_id": r["rule"], "label": label,
                    "labeller": (r.get("labeller") or "").strip() or path.stem, "source": source,
                    "held_out": held_out, "role": "labeller", "note": r.get("notes") or "",
                    "language": P.label_language(r.get("path"), r.get("language")),
                    # A sheet is one split, so its stratum's held-out size is
                    # all of it or none of it. A blank size stays unknown.
                    **({"stratum_size": int(r["stratum_size"]),
                        "stratum_held_out_size": int(r["stratum_size"]) if held_out else 0}
                       if str(r.get("stratum_size") or "").strip() else {})})
    return out


# ---------------------------------------------------------------------------
# Arithmetic -- pure
# ---------------------------------------------------------------------------

# Who decides a finding, strongest first: published ground truth; a
# mechanical checker's observed result (the planned sandbox checkers: a fact re-derived by a
# second implementation, an exploit that ran, a mutant a test never
# caught); an adjudicator; agreeing labellers.
ROLES = ("ground_truth", "mechanical", "adjudicator", "labeller")
_ROLE_ORDER = {r: i for i, r in enumerate(ROLES)}

# The company that made a model, by model-name prefix. Independence between
# labellers is independence between vendors: two models of one company share
# training data and blind spots.
_VENDORS = (("claude", "anthropic"), ("anthropic", "anthropic"), ("gpt", "openai"), ("o1", "openai"),
            ("o3", "openai"), ("o4", "openai"), ("codex", "openai"), ("chatgpt", "openai"),
            ("gemini", "google"), ("gemma", "google"), ("mai", "microsoft"), ("phi", "microsoft"),
            ("kimi", "moonshot"), ("grok", "xai"), ("llama", "meta"), ("mistral", "mistral"),
            ("codestral", "mistral"), ("deepseek", "deepseek"), ("qwen", "alibaba"))
_SEATS = ("claude-", "codex-", "copilot-")


def model_vendor(model: str) -> str:
    """'anthropic', 'openai', 'google', ... for a model name; '' when unknown."""
    m = str(model or "").strip().lower().rsplit("/", 1)[-1]
    for prefix, vendor in _VENDORS:
        if m == prefix or m.startswith((prefix + "-", prefix + ".", prefix + "_")):
            return vendor
    return ""


def labeller_vendor(labeller: str) -> str:
    """The vendor behind a labeller name (`claude-opus-5-5:panel/v1`,
    `copilot-mai-code-1.1-flash:panel/v1`, `claude-opus-5-5:prosecutor+
    defender/v3`), or the name itself when no model vendor is recognised
    (a person, a sheet), so distinct people stay distinct."""
    stem = str(labeller).split(":", 1)[0]
    for seat in _SEATS:
        if stem.startswith(seat) and model_vendor(stem[len(seat):]):
            return model_vendor(stem[len(seat):])
    return model_vendor(stem) or f"labeller:{labeller}"


def kappa_pair(seen: dict[str, str]) -> tuple[str, str] | None:
    """The two labels kappa compares: the first labeller (by name) and the
    first after it from a different vendor. Two models of one vendor are
    not an independent pair, so they give none."""
    names = list(seen)
    if not names:
        return None
    first = labeller_vendor(names[0])
    other = next((n for n in names[1:] if labeller_vendor(n) != first), None)
    return (seen[names[0]], seen[other]) if other else None


def _size(v) -> int | None:
    return None if v is None or v == "" else int(v)


def finding_stratum(recs: list[dict]) -> dict:
    """The sampling stratum one finding was drawn from: its source and
    language (the rule is the finding's own), and the population sizes its
    label record carries (docs/precision.md, "Population weights"). Taken
    from the first record, ground truth first, that carries a size; when
    none does, the sizes are None: unknown, never the label count."""
    ordered = sorted(recs, key=lambda r: _ROLE_ORDER.get(r.get("role", "labeller"), 3))
    r = next((x for x in ordered if _size(x.get("stratum_size")) is not None), ordered[0])
    size = _size(r.get("stratum_size"))
    held = _size(r.get("stratum_held_out_size"))
    return {"source": r["source"], "language": P.label_language(r.get("path"), r.get("language")),
            "size": size,
            "held_out_size": held if size is not None else None,
            "rule_size": _size(r.get("rule_population")) if size is not None else None,
            "rule_held_out_size": _size(r.get("rule_held_out_population")) if size is not None else None}


def final_verdicts(records: list[dict]) -> dict[str, dict]:
    """finding_id -> {rule_id, label, held_out, source, labellers, pair}.

    Ground truth wins; then a mechanical checker's result (when its decided
    results agree; checkers that contradict each other make the finding
    `unsure`, and one that could not decide passes to the next role); then an
    adjudicator's label; then the labellers' labels when every tp/fp among
    them agrees -- the panel's one record per model included. A disagreement
    nobody has adjudicated is `unsure`: it counts toward neither TP nor FP.
    `pair` is two labellers' tp/fp labels for kappa: the first by name and
    the first after it from another vendor (`kappa_pair`)."""
    by: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by[r["finding_id"]].append(r)
    out = {}
    for fid, recs in by.items():
        rules = {r["rule_id"] for r in recs}
        if len(rules) > 1:
            raise SystemExit(f"finding {fid} is labelled under more than one rule: {sorted(rules)}")
        truth = [r for r in recs if r["role"] == "ground_truth"]
        mech = {r["label"] for r in recs if r["role"] == "mechanical" and r["label"] != "unsure"}
        adj = [r for r in recs if r["role"] == "adjudicator"]
        lab = sorted((r for r in recs if r["role"] == "labeller"), key=lambda r: r["labeller"])
        decided = [r["label"] for r in lab if r["label"] != "unsure"]
        if truth:
            label = truth[-1]["label"]
        elif mech:
            label = mech.pop() if len(mech) == 1 else "unsure"
        elif adj:
            label = adj[-1]["label"]
        elif decided and len(set(decided)) == 1:
            label = decided[0]
        else:
            label = "unsure"
        seen: dict[str, str] = {}
        for r in lab:
            if r["label"] != "unsure" and r["labeller"] not in seen:
                seen[r["labeller"]] = r["label"]
        pair = kappa_pair(seen)
        out[fid] = {"rule_id": rules.pop(), "label": label,
                    # A finding is held out only if every record says so.
                    "held_out": all(r["held_out"] for r in recs),
                    "source": recs[0]["source"], "cluster": finding_cluster(recs),
                    "labellers": sorted({r["labeller"] for r in recs}),
                    "sources": sorted({r["source"] for r in recs}),
                    "dates": sorted(r["date"] for r in recs if r.get("date")),
                    "notes": [r["note"] for r in recs if r.get("note") and r["label"] == "fp"],
                    "stratum": finding_stratum(recs),
                    "dimension": next((r["dimension"] for r in recs if r.get("dimension")), ""),
                    "cwe": sorted({c for r in recs for c in (r.get("cwe") or [])}),
                    "pair": pair}
    return out


def _round(x):
    return None if x is None else round(x, 4)


def _new_stratum(source: str, language: str) -> dict:
    return {"source": source, "language": language, "population": None, "held_out_population": None,
            "unknown": 0, "tp": 0, "fp": 0, "unsure": 0, "held_out": {"tp": 0, "fp": 0, "unsure": 0}}


def _agree_size(rule: str, where: str, old, new):
    if old is not None and new is not None and old != new:
        raise SystemExit(f"{rule} {where}: label records give two population sizes ({old} and {new}); "
                         "labels drawn from different runs need different `source` names")
    return new if old is None else old


def rule_strata(rule: str, verdicts: list[dict]) -> tuple[list[dict], dict]:
    """A rule's strata (source, language) with their populations and label
    counts, and the rule's population per source. A stratum any of whose
    labels lacks a recorded size is unknown as a whole (population None)."""
    strata: dict[tuple, dict] = {}
    sources: dict[str, dict] = {}
    for v in verdicts:
        st = v["stratum"]
        key = (st["source"], st["language"])
        e = strata.setdefault(key, _new_stratum(*key))
        e[v["label"]] += 1
        if v["held_out"]:
            e["held_out"][v["label"]] += 1
        if st["size"] is None:
            e["unknown"] += 1
            continue
        where = f"stratum {key[0]}/{key[1] or '-'}"
        e["population"] = _agree_size(rule, where, e["population"], st["size"])
        e["held_out_population"] = _agree_size(rule, where + " (held out)", e["held_out_population"],
                                               st["held_out_size"])
        src = sources.setdefault(st["source"], {"population": None, "held_out_population": None})
        src["population"] = _agree_size(rule, f"source {st['source']}", src["population"], st["rule_size"])
        src["held_out_population"] = _agree_size(rule, f"source {st['source']} (held out)",
                                                 src["held_out_population"], st["rule_held_out_size"])
    out = []
    for key in sorted(strata):
        e = strata[key]
        if e.pop("unknown"):
            e["population"] = e["held_out_population"] = None
        out.append(e)
    return out, sources


def _weighted(strata: list[dict], held_out: bool) -> dict | None:
    rows = [{"key": f"{s['source']}/{s['language'] or '-'}",
             "tp": s["held_out"]["tp"] if held_out else s["tp"],
             "fp": s["held_out"]["fp"] if held_out else s["fp"],
             "population": s["held_out_population"] if held_out else s["population"]} for s in strata]
    return P.weighted_precision(rows)


def rule_entries(verdicts: dict[str, dict], bar: dict) -> dict[str, dict]:
    from arbiter.rule_meta import meta
    per: dict[str, dict] = {}
    for v in verdicts.values():
        e = per.setdefault(v["rule_id"], {
            "tp": 0, "fp": 0, "unsure": 0, "held_out": {"tp": 0, "fp": 0, "unsure": 0},
            "labellers": set(), "sources": set(), "dates": [], "pairs": [], "notes": [],
            "verdicts": [], "dimension": v["dimension"], "cwe": set(v["cwe"])})
        e[v["label"]] += 1
        if v["held_out"]:
            e["held_out"][v["label"]] += 1
        e["labellers"].update(v["labellers"])
        e["sources"].update(v["sources"])
        e["dates"] += v["dates"]
        e["notes"] += v["notes"]
        e["cwe"].update(v["cwe"])
        e["verdicts"].append(v)
        if v["pair"]:
            e["pairs"].append(v["pair"])
    out = {}
    for rule, e in sorted(per.items()):
        n = e["tp"] + e["fp"]
        ci = P.wilson(e["tp"], n)
        kappa = P.cohens_kappa([a for a, _ in e["pairs"]], [b for _, b in e["pairs"]])
        agree = (sum(a == b for a, b in e["pairs"]) / len(e["pairs"])) if e["pairs"] else None
        strata, sources = rule_strata(rule, e["verdicts"])
        unknown = sum(s["tp"] + s["fp"] + s["unsure"] for s in strata if s["population"] is None)
        m = meta(rule) or {}
        entry = {
            "tp": e["tp"], "fp": e["fp"], "unsure": e["unsure"], "n": n,
            "held_out": e["held_out"],
            "precision": _round(e["tp"] / n) if n else None,
            "wilson_lower": _round(ci[0]) if ci else None,
            "wilson_upper": _round(ci[1]) if ci else None,
            "kappa": _round(kappa), "kappa_pairs": len(e["pairs"]),
            "observed_agreement": _round(agree),
            "labellers": sorted(e["labellers"]), "sources": sorted(e["sources"]),
            "dates": {"first": e["dates"][0] if e["dates"] else "",
                      "last": e["dates"][-1] if e["dates"] else ""} if e["dates"] else {},
            # Findings of the rule in the runs its labels were drawn from; None
            # when any label's population is unknown (`population_unknown`).
            "population": None if unknown else sum(s["population"] for s in strata),
            "held_out_population": None if unknown or any(s["held_out_population"] is None for s in strata)
            else sum(s["held_out_population"] for s in strata),
            "population_unknown": unknown,
            "strata": strata,
            "source_population": dict(sorted(sources.items())),
            "weighted": None if unknown else _weighted(strata, held_out=False),
            "dimension": e["dimension"] or m.get("dimension", ""),
            "cwe": sorted(e["cwe"] | set(m.get("cwe") or [])),
            "fp_notes": list(dict.fromkeys(e["notes"])),
        }
        entry["admitted"], entry["admitted_reason"] = P.admission(entry, bar)
        out[rule] = entry
    return out


def _row(rule: str, s: dict) -> dict:
    return {"key": f"{rule}|{s['source']}/{s['language'] or '-'}", "rule": rule,
            "stratum": f"{s['source']}/{s['language'] or '-'}", "tp": s["held_out"]["tp"],
            "fp": s["held_out"]["fp"], "population": s["held_out_population"]}


def tier_rows(rules: dict[str, dict], names: list[str]) -> tuple[list[dict], int]:
    """The held-out strata of `names` (empty ones included; the weighting
    skips them) and the held-out population the claim is over."""
    rows, total = [], 0
    for r in names:
        strata = rules[r].get("strata") or []
        sources = rules[r].get("source_population") or {}
        rows += [_row(r, s) for s in strata]
        for src in {s["source"] for s in strata}:
            listed = sum(s["held_out_population"] for s in strata if s["source"] == src)
            total += max(listed, (sources.get(src) or {}).get("held_out_population") or 0)
    return rows, total


def language_rows(rules: dict[str, dict], members: list[str], lang: str) -> tuple[list[dict], int]:
    """`tier_rows` restricted to one language (see `language_claims`)."""
    rows, total = [], 0
    for r in members:
        strata = rules[r].get("strata") or []
        sources = rules[r].get("source_population") or {}
        for src in sorted({s["source"] for s in strata if (s["language"] or "-") == lang}):
            mine = [s for s in strata if s["source"] == src and (s["language"] or "-") == lang]
            listed = sum(s["held_out_population"] for s in strata if s["source"] == src)
            rest = max(0, ((sources.get(src) or {}).get("held_out_population") or 0) - listed)
            total += sum(s["held_out_population"] for s in mine) + rest
            rows += [_row(r, s) for s in mine]
    return rows, total


def stratified_claim(rules: dict[str, dict], names: list[str], bar: dict) -> dict:
    """The held-out, population-weighted precision over the strata of
    `names` (docs/precision.md, "Tier claim"). Unknown populations make it
    None and say which rules; held-out findings in strata with no decided
    held-out label count against the bound, as if every one were an FP."""
    unknown = sorted(r for r in names if rules[r].get("population_unknown")
                     or rules[r].get("held_out_population") is None)
    if unknown:
        return {"estimate": None, "claim": False, "population_unknown": unknown}
    rows, total = tier_rows(rules, names)
    w = P.weighted_precision(rows)
    if w is None:
        return {"estimate": None, "claim": False, "population_unknown": []}
    labelled = w["population"]
    coverage = labelled / total if total else 1.0
    lower = round(w["wilson_lower"] * coverage, 4)
    est = {**w, "held_out_population": total, "unlabelled_population": total - labelled,
           "coverage": round(coverage, 4), "claim_lower": lower}
    return {"estimate": est, "claim": lower >= bar["tier_lower"], "population_unknown": []}


def tier_claim(rules: dict[str, dict], bar: dict, verified: set[str]) -> dict:
    """The held-out claim, over the rules that are verified (declared and
    admitted), overall and per category (dimension and each CWE). A
    category's 99% claim is made only where its own lower bound reaches it."""
    names = sorted(r for r in verified if r in rules and rules[r]["admitted"])
    whole = stratified_claim(rules, names, bar)
    cats: dict[str, list[str]] = defaultdict(list)
    for r in names:
        if rules[r]["dimension"]:
            cats[rules[r]["dimension"]].append(r)
        for c in rules[r]["cwe"]:
            cats[c].append(r)
    categories = {}
    for c, members in sorted(cats.items()):
        sc = stratified_claim(rules, members, bar)
        categories[c] = {**(sc["estimate"] or {"precision": None, "wilson_lower": None, "claim_lower": None}),
                         "rule_ids": members, "claim": sc["claim"],
                         "population_unknown": sc["population_unknown"]}
    return {"held_out_only": True, "method": "stratified", "rules": names,
            "overall": whole["estimate"], "claim": whole["claim"],
            "population_unknown": whole["population_unknown"],
            "categories": categories}


def language_claims(rules: dict[str, dict], bar: dict, verified: set[str]) -> dict[str, dict]:
    """The tier claim per language (ARB-176): for each language any rule has
    a stratum in, the held-out, population-weighted precision over the
    verified rules (declared and admitted) with strata in that language.

    Same arithmetic as `stratified_claim`, restricted to the language's
    strata, with one difference in the denominator: a rule's held-out
    findings that no stratum lists (its source population beyond its listed
    strata) cannot be put in a language, so they count against every
    language the rule has strata in under that source -- conservative,
    never in a language's favour. A language with no verified rule makes no
    claim."""
    names = sorted(r for r in verified if r in rules and rules[r].get("admitted"))
    langs: dict[str, dict] = {}
    for r, e in rules.items():
        for s in e.get("strata") or []:
            d = langs.setdefault(s["language"] or "-", {"rules": set(), "tp": 0, "fp": 0})
            d["rules"].add(r)
            d["tp"] += s["held_out"]["tp"]
            d["fp"] += s["held_out"]["fp"]
    out = {}
    for lang, d in sorted(langs.items()):
        members = [r for r in names if r in d["rules"]]
        row = {"rules_labelled": len(d["rules"]), "rules_admitted": len(members), "rule_ids": members,
               "held_out_tp": d["tp"], "held_out_fp": d["fp"], "precision": None, "wilson_lower": None,
               "claim_lower": None, "claim": False, "population_unknown": []}
        unknown = sorted(r for r in members if rules[r].get("population_unknown")
                         or rules[r].get("held_out_population") is None)
        if unknown:
            out[lang] = {**row, "population_unknown": unknown}
            continue
        rows, total = language_rows(rules, members, lang)
        w = P.weighted_precision(rows)
        if w is None:
            out[lang] = row
            continue
        coverage = w["population"] / total if total else 1.0
        lower = round(w["wilson_lower"] * coverage, 4)
        out[lang] = {**row, "precision": w["precision"], "wilson_lower": w["wilson_lower"],
                     "n_eff": w["n_eff"], "held_out_population": total, "coverage": round(coverage, 4),
                     "claim_lower": lower, "claim": lower >= bar["tier_lower"]}
    return out


# ---------------------------------------------------------------------------
# Alongside the ledger: Dawid-Skene (ARB-167) and repository clustering
# (ARB-168). Both are reported next to the unanimity, independent-finding
# numbers; neither decides admission or the tier claim (docs/precision.md,
# "Two more estimates").
# ---------------------------------------------------------------------------

# Benchmarks whose `repo` is the whole suite: their test cases are separate
# programs, so the cluster is the test case, not the suite. A Juliet test
# case's flow variants (`..._01.java` to `..._22.java`, `_81a`/`_81_bad`
# parts) share one source and sink, so they are one cluster.
_JULIET_VARIANT = re.compile(r"_\d+(?:[a-z]|_(?:bad|good\w*|base))?\.java$")
SUITE_CLUSTERS = {"owasp-java": "test file", "owasp-python": "test file",
                  "juliet-java": "Juliet functional variant (flow variants _01.._NN together)"}
BOOT_N = 2000      # cluster-bootstrap resamples per rule (ARB-112 uses 10,000 on one cohort)


def finding_cluster(recs: list[dict]) -> str:
    """The repository a finding came from (ARB-168): `repo` of its first
    record; for the benchmark suites in SUITE_CLUSTERS, the test case."""
    r = next((x for x in recs if x.get("repo")), recs[0])
    src = str(r.get("source", ""))
    path = str(r.get("path") or "")
    if src in SUITE_CLUSTERS and path:
        if src == "juliet-java":
            return f"{src}:{_JULIET_VARIANT.sub('', path.rsplit('/', 1)[-1])}"
        return f"{src}:{path}"
    return str(r.get("repo") or f"source:{src}")


def _ds_votes(rec: dict) -> list[tuple[str, str]]:
    """A record's votes, one per rater. A model labeller record carries
    the prosecutor's, defender's and (on disputes) adjudicator's votes; each
    is its own rater, keyed by model, role and prompt version, because each
    makes its own mistakes. Anything else is one rater, its labeller."""
    lab = str(rec.get("labeller", ""))
    m = _MODEL_LABELLER.search(lab)
    votes = rec.get("votes")
    if m and isinstance(votes, dict) and votes:
        model = lab.split(":", 1)[0]
        out = []
        for role, v in sorted(votes.items()):
            label = v.get("label") if isinstance(v, dict) else v
            try:
                out.append((f"{model}:{role}/{m.group(1)}", norm_label(label)))
            except ValueError:
                continue
        return out
    return [(lab, rec["label"])]


def _is_truth(r: dict) -> bool:
    """Published truth: the ground-truth role, or the benchmark importers'
    records (labeller `ground-truth`, role left at labeller), which the
    unanimity verdict also takes as decided on their own."""
    return r["role"] == "ground_truth" or r.get("labeller") == "ground-truth"


def ds_items(records: list[dict]) -> list[dict]:
    """Ledger findings as Dawid-Skene items: votes from labellers and
    adjudicators; known truth from ground truth (or an agreeing mechanical
    checker), as the unanimity verdict takes it."""
    by: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by[r["finding_id"]].append(r)
    out = []
    for fid, recs in sorted(by.items()):
        truth = [r["label"] for r in recs if _is_truth(r)]
        mech = {r["label"] for r in recs if r["role"] == "mechanical" and r["label"] != "unsure"}
        t = truth[-1] if truth else (next(iter(mech)) if len(mech) == 1 else None)
        votes = [v for r in sorted(recs, key=lambda x: str(x.get("labeller", "")))
                 if r["role"] in ("labeller", "adjudicator") and not _is_truth(r) for v in _ds_votes(r)]
        out.append({"id": fid, "group": recs[0]["rule_id"], "truth": t if t in ("tp", "fp") else None,
                    "category": next((r["category"] for r in recs if r.get("category")), "other"),
                    "votes": votes})
    return out


def ds_anchors(calibration: list[dict]) -> list[dict]:
    """Calibration records (blind labels on benchmark items with known
    truth) as Dawid-Skene anchors."""
    out = []
    for i, r in enumerate(calibration):
        if r.get("truth") not in ("tp", "fp"):
            continue
        out.append({"id": f"{r.get('source', '')}|{r.get('finding_id', '')}|{i}", "group": r.get("rule_id", ""),
                    "category": r.get("category") or "other", "truth": r["truth"], "votes": _ds_votes(r)})
    return out


def _sums(ps: list) -> list:
    ps = [p for p in ps if p is not None]
    return [len(ps), round(math.fsum(ps), 6), round(math.fsum(p * (1 - p) for p in ps), 6)]


def dawid_skene_block(records: list[dict], anchors: list[dict], verdicts: dict[str, dict],
                      rules: dict[str, dict], bar: dict, names: list[str]) -> dict:
    """Dawid-Skene over the ledger's findings, anchored on `anchors`
    (calibration records): per-rule posterior summaries next to the
    unanimity counts, the labellers' estimated error rates, and the tier
    claim under it."""
    fit = DS.fit(ds_items(records), ds_anchors(anchors))
    post = fit["posteriors"]
    per: dict[str, dict] = {}
    for fid, v in sorted(verdicts.items()):
        e = per.setdefault(v["rule_id"], {"all": [], "held_out": [], "strata": defaultdict(list), "changed": 0})
        p = post.get(fid)
        e["all"].append(p)
        hard = None if p is None else ("tp" if p >= 0.5 else "fp")
        if (hard or "unsure") != v["label"]:
            e["changed"] += 1
        if v["held_out"]:
            e["held_out"].append(p)
            st = v["stratum"]
            e["strata"][f"{st['source']}/{st['language'] or '-'}"].append(p)
    out_rules = {}
    for rule, e in sorted(per.items()):
        out_rules[rule] = {"all": DS.summarise(e["all"]), "held_out": DS.summarise(e["held_out"]),
                           "verdicts_changed": e["changed"],
                           "held_out_strata": {k: _sums(v) for k, v in sorted(e["strata"].items())}}
    block = {"_about": "Dawid-Skene labeller-weighted precision (ARB-167, docs/precision.md). Reported "
                       "alongside the unanimity numbers; admission and the tier claim do not use it.",
             "method": {"rater_prior": list(DS.RATER_PRIOR), "category_shrink": DS.SHRINK,
                        "prevalence_prior": list(DS.PREVALENCE_PRIOR), "max_iter": DS.MAX_ITER, "tol": DS.TOL,
                        "iterations": fit["iterations"], "converged": fit["converged"],
                        "anchors": len(ds_anchors(anchors)),
                        "interval": "Wilson on (sum of posteriors, n), widened by the posteriors' label "
                                    "variance; excludes uncertainty in the estimated labeller error rates"},
             "raters": fit["raters"], "independence": _independence(anchors), "rules": out_rules}
    block["tier"] = alt_claim(rules, names, bar, "dawid_skene", block)
    return block


def _independence(anchors: list[dict]) -> list[dict]:
    items = ds_anchors(anchors)
    raters = sorted({r for it in items for r, _ in it["votes"]})
    out = []
    for a in raters:
        if ":prosecutor/" not in a:
            continue
        b = a.replace(":prosecutor/", ":defender/")
        if b in raters:
            out.append(DS.independence_check(items, a, b))
    return out


_PREREG = None


def _prereg():
    """tools/prereg_b_analysis.py (ARB-112), loaded by path: its cluster
    bootstrap is preregistered, so it is reused, never copied or edited."""
    global _PREREG
    if _PREREG is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("prereg_b_analysis", ROOT / "tools" / "prereg_b_analysis.py")
        _PREREG = importlib.util.module_from_spec(spec)
        sys.modules["prereg_b_analysis"] = _PREREG
        spec.loader.exec_module(_PREREG)
    return _PREREG


def _bootstrap(clusters: dict[str, list[int]]) -> dict:
    """ARB-112's repository-cluster bootstrap (seed 109), BOOT_N resamples,
    clusters in sorted order. Degenerate cases say so instead of giving a
    number that looks like evidence."""
    tp = sum(t for t, _ in clusters.values())
    n = sum(t + f for t, f in clusters.values())
    if len(clusters) < 2:
        return {"lower": None, "note": "degenerate: one repository"}
    if tp in (0, n):
        return {"lower": None, "note": f"degenerate: every finding {'tp' if tp else 'fp'}, so every resample is too"}
    recs = [{"repo": c, "label": lab} for c, (t, f) in sorted(clusters.items())
            for lab in ["tp"] * t + ["fp"] * f]
    iv = _prereg().cluster_bootstrap(recs, n_boot=BOOT_N).get("interval95")
    return {"lower": iv[0], "upper": iv[1], "note": None} if iv else {"lower": None, "note": "degenerate"}


def clustered_block(verdicts: dict[str, dict], rules: dict[str, dict], bar: dict, names: list[str]) -> dict:
    """Repository-clustered bounds: per rule over all decided labels (as
    `wilson_lower`), and held-out per-stratum cluster counts for the claims."""
    per: dict[str, dict] = {}
    for _, v in sorted(verdicts.items()):
        if v["label"] not in ("tp", "fp"):
            continue
        e = per.setdefault(v["rule_id"], {"all": defaultdict(lambda: [0, 0]),
                                          "strata": defaultdict(lambda: defaultdict(lambda: [0, 0]))})
        i = 0 if v["label"] == "tp" else 1
        e["all"][v["cluster"]][i] += 1
        if v["held_out"]:
            st = v["stratum"]
            e["strata"][f"{st['source']}/{st['language'] or '-'}"][v["cluster"]][i] += 1
    designs = {}
    for rule, e in sorted(per.items()):
        cl = {c: list(x) for c, x in sorted(e["all"].items())}
        designs[rule] = (cl, P.cluster_design_effect([(t, t + f) for t, f in cl.values()]))
    icc = pooled_icc([d for _, d in designs.values()])
    out_rules = {}
    for rule, e in sorted(per.items()):
        cl, d = designs[rule]
        tp = sum(t for t, _ in cl.values())
        n = sum(t + f for t, f in cl.values())
        ci = P.clustered_wilson(tp / n, n, d["deff"])
        borrowed = {}
        if d["deff_source"] != "estimated" and icc is not None:
            b = P.cluster_design_effect([(t, t + f) for t, f in cl.values()], icc)
            bci = P.clustered_wilson(tp / n, n, b["deff"])
            borrowed = {"borrowed_icc": {"deff": b["deff"], "n_eff": b["n_eff"], "wilson_lower": _round(bci[0])}}
        out_rules[rule] = {"design": d, "n_eff": d["n_eff"], "wilson_lower": _round(ci[0]),
                           "wilson_upper": _round(ci[1]), **borrowed, "bootstrap": _bootstrap(cl),
                           "held_out_clusters": {k: {c: list(x) for c, x in sorted(v.items())}
                                                 for k, v in sorted(e["strata"].items())}}
    block = {"_about": "Repository-clustered precision bounds (ARB-168, docs/precision.md). Reported alongside "
                       "the independent-finding bounds; admission and the tier claim do not use them.",
             "cluster_keys": {"default": "the finding's repository (`repo`)", **SUITE_CLUSTERS},
             "bootstrap": {"resamples": BOOT_N, "seed": 109, "source": "tools/prereg_b_analysis.py"},
             "pooled_icc": icc, "rules": out_rules}
    block["tier"] = alt_claim(rules, names, bar, "clustered", block)
    if icc is not None:
        block["tier_borrowed_icc"] = alt_claim(rules, names, bar, "clustered", block, icc=icc)
    return block


def pooled_icc(designs: list) -> float | None:
    """The intra-repository correlation pooled over the rules where it can
    be estimated (two or more repositories, both labels present), weighted
    by their finding counts and clipped to [0, 1]. Used, beside the worst
    case, for the rules where it cannot be estimated."""
    ok = [d for d in designs if d and d["deff_source"] == "estimated" and d["icc"] is not None]
    n = sum(d["n"] for d in ok)
    if not n:
        return None
    return round(sum(min(1.0, max(0.0, d["icc"])) * d["n"] for d in ok) / n, 4)


def _alt_rows(rows: list[dict], mode: str, block: dict) -> list[dict]:
    out = []
    for r in rows:
        alt = (block.get("rules") or {}).get(r["rule"]) or {}
        if mode == "dawid_skene":
            n, sp, spq = (alt.get("held_out_strata") or {}).get(r["stratum"], [0, 0.0, 0.0])
            out.append({**r, "tp": sp, "fp": n - sp, "label_var": spq})
        else:
            out.append({**r, "clusters": (alt.get("held_out_clusters") or {}).get(r["stratum"]) or {}})
    return out


def alt_estimate(rows: list[dict], total: int, bar: dict, mode: str, block: dict,
                 icc: float | None = None) -> dict | None:
    """The tier arithmetic (`stratified_claim`) under one of the two
    alternative methods. Dawid-Skene: each stratum's tp/fp are the
    posterior pseudo-counts. Clustered: the unanimity estimate, with its
    effective size divided by the design effect over the strata's
    repositories."""
    alt = _alt_rows(rows, mode, block)
    w = P.weighted_precision(alt)
    if w is None:
        return None
    coverage = w["population"] / total if total else 1.0
    if mode == "dawid_skene":
        # Label variance of the weighted estimate: sum W_h^2 sum p(1-p) / n_h^2.
        live = [r for r in alt if r["tp"] + r["fp"] > 0]
        tot = sum(r["population"] for r in live)
        v_label = sum((r["population"] / tot) ** 2 * r["label_var"] / (r["tp"] + r["fp"]) ** 2 for r in live)
        v_sampling = w["precision"] * (1 - w["precision"]) / w["n_eff"]
        lower = round(DS.widen(w["wilson_lower"], w["wilson_upper"], v_sampling, v_label)[0], 4)
        extra = {"n_eff": w["n_eff"], "expected_tp": round(w["tp"], 2), "n": round(w["tp"] + w["fp"]),
                 "label_variance": v_label}
    else:
        d = P.cluster_design([{"weight": r["population"], "tp": r["tp"], "fp": r["fp"], "clusters": r["clusters"]}
                              for r in alt if r["tp"] + r["fp"]], icc)
        ci = P.clustered_wilson(w["precision"], w["n_eff"], d["deff"])
        lower = round(ci[0], 4)
        extra = {"n_eff_independent": w["n_eff"], "n_eff": round(w["n_eff"] / d["deff"], 1), "design": d}
    return {"precision": round(w["precision"], 4), "wilson_lower": lower, **extra,
            "coverage": round(coverage, 4), "claim_lower": round(lower * coverage, 4),
            "would_claim": round(lower * coverage, 4) >= bar["tier_lower"]}


def alt_claim(rules: dict[str, dict], names: list[str], bar: dict, mode: str, block: dict,
              icc: float | None = None) -> dict:
    unknown = sorted(r for r in names if rules[r].get("population_unknown")
                     or rules[r].get("held_out_population") is None)
    if unknown or not names:
        return {"rules": names, "overall": None, "population_unknown": unknown}
    rows, total = tier_rows(rules, names)
    return {"rules": names, "overall": alt_estimate(rows, total, bar, mode, block, icc), "population_unknown": []}


def alt_language_claims(ledger: dict, bar: dict, verified: set[str]) -> dict[str, dict]:
    """Per language, the claim under unanimity (as `language_claims`),
    Dawid-Skene and clustering, side by side."""
    rules = ledger.get("rules") or {}
    out = {}
    for lang, row in language_claims(rules, bar, verified).items():
        members = row["rule_ids"]
        res = {"unanimity": row}
        for mode in ("dawid_skene", "clustered"):
            block = ledger.get(mode) or {}
            est = None
            if members and not row["population_unknown"] and block:
                rows, total = language_rows(rules, members, lang)
                est = alt_estimate(rows, total, bar, mode, block)
            res[mode] = est
        out[lang] = res
    return out


def language_pooled(ledger: dict) -> dict[str, dict]:
    """Per language, every labelled rule's held-out findings pooled
    (unweighted, admitted or not): the unanimity count and Wilson bound, the
    Dawid-Skene mean posterior and bound, and the repository-clustered
    bound. A description of the labels, not a claim: the claim is over
    verified rules only and weighted by population."""
    rules = ledger.get("rules") or {}
    ds = (ledger.get("dawid_skene") or {}).get("rules") or {}
    cl = (ledger.get("clustered") or {}).get("rules") or {}
    acc: dict[str, dict] = {}
    for rule, e in rules.items():
        for s in e.get("strata") or []:
            lang = s["language"] or "-"
            key = f"{s['source']}/{lang}"
            a = acc.setdefault(lang, {"tp": 0, "fp": 0, "ds": [0, 0.0, 0.0], "rows": []})
            tp, fp = s["held_out"]["tp"], s["held_out"]["fp"]
            a["tp"] += tp
            a["fp"] += fp
            for i, x in enumerate((ds.get(rule) or {}).get("held_out_strata", {}).get(key, [0, 0.0, 0.0])):
                a["ds"][i] += x
            if tp + fp:
                # One stratum per rule, weighted by its labels, so the pooled
                # estimate is the plain pooled share and each finding is
                # compared with its own rule's rate: rules that differ are
                # not mistaken for repositories that differ.
                a["rows"].append({"weight": tp + fp, "tp": tp, "fp": fp,
                                  "clusters": (cl.get(rule) or {}).get("held_out_clusters", {}).get(key) or {}})
    out = {}
    for lang, a in sorted(acc.items()):
        n = a["tp"] + a["fp"]
        if not n:
            continue
        w = P.wilson(a["tp"], n)
        d = DS.summarise_sums(*a["ds"])
        des = P.cluster_design(a["rows"])
        ci = P.clustered_wilson(a["tp"] / n, n, des["deff"]) if des else None
        out[lang] = {"tp": a["tp"], "fp": a["fp"], "precision": round(a["tp"] / n, 4), "lower": _round(w[0]),
                     "ds_n": d["n"], "ds_precision": d["precision"], "ds_lower": d["lower"],
                     "repos": des["clusters"] if des else None, "deff": des["deff"] if des else None,
                     "deff_source": des["deff_source"] if des else None,
                     "clustered_lower": _round(ci[0]) if ci else None}
    return out


def near_bar(ledger: dict, margin: float = 0.05) -> list[dict]:
    """Rules whose unanimity lower bound is within `margin` of the
    admission bar (or above it), with all three bounds side by side."""
    bar = {**P.DEFAULT_BAR, **(ledger.get("bar") or {})}
    out = []
    for rule, e in (ledger.get("rules") or {}).items():
        lo = e.get("wilson_lower")
        if lo is None or lo < bar["rule_lower"] - margin:
            continue
        ds = (((ledger.get("dawid_skene") or {}).get("rules") or {}).get(rule) or {}).get("all") or {}
        cl = ((ledger.get("clustered") or {}).get("rules") or {}).get(rule) or {}
        d = cl.get("design") or {}
        b = cl.get("bootstrap") or {}
        out.append({"rule": rule, "tp": e["tp"], "fp": e["fp"], "n": e["n"], "lower": lo,
                    "admitted": e.get("admitted", False), "ds_n": ds.get("n"), "ds_lower": ds.get("lower"),
                    "repos": d.get("clusters"), "deff": d.get("deff"), "deff_source": d.get("deff_source"),
                    "n_eff_clustered": cl.get("n_eff"), "clustered_lower": cl.get("wilson_lower"),
                    "bootstrap_lower": b.get("lower"), "bootstrap_note": b.get("note")})
    return out


def render_alternatives(ledger: dict, bar: dict, verified: set[str]) -> str:
    def f(x):
        return "-" if x is None else f"{x:.4f}"
    lines = ["", "alongside, not used for admission or the claim: Dawid-Skene (ds) and repository-clustered (clus)",
             f"{'language':<12} {'claim_lo':>8} {'ds_lo':>8} {'clus_lo':>8} {'deff':>7} {'repos':>5}"]
    for lang, c in alt_language_claims(ledger, bar, verified).items():
        u, d, k = c["unanimity"], c["dawid_skene"] or {}, c["clustered"] or {}
        if not u["rules_admitted"]:
            continue
        des = k.get("design") or {}
        lines.append(f"{lang:<12} {f(u['claim_lower']):>8} {f(d.get('claim_lower')):>8} "
                     f"{f(k.get('claim_lower')):>8} {des.get('deff', '-'):>7} {des.get('clusters', '-'):>5}")
    for mode, key, name in (("dawid_skene", "tier", "Dawid-Skene"), ("clustered", "tier", "clustered, worst case"),
                            ("clustered", "tier_borrowed_icc", "clustered, pooled ICC")):
        o = ((ledger.get(mode) or {}).get(key) or {}).get("overall")
        if o:
            lines.append(f"verified tier, {name}: precision {o['precision']} (95% lower {o['wilson_lower']}, "
                         f"n_eff {o['n_eff']}; claim lower {o['claim_lower']}; would claim: "
                         f"{'yes' if o['would_claim'] else 'no'})")
    lines += ["", "every labelled rule's held-out findings pooled per language (unweighted; a description, not a claim)",
              f"{'language':<12} {'TP':>5} {'FP':>5} {'prec':>7} {'lower':>7} {'ds_n':>5} {'ds_prec':>7} "
              f"{'ds_lo':>7} {'repos':>5} {'deff':>7} {'clus_lo':>7}"]
    for lang, r in language_pooled(ledger).items():
        lines.append(f"{lang:<12} {r['tp']:>5} {r['fp']:>5} {f(r['precision']):>7} {f(r['lower']):>7} "
                     f"{r['ds_n']:>5} {f(r['ds_precision']):>7} {f(r['ds_lower']):>7} {r['repos'] or '-':>5} "
                     f"{r['deff'] or '-':>7} {f(r['clustered_lower']):>7}"
                     f"{'  (deff worst case, ICC = 1)' if r['deff_source'] and r['deff_source'] != 'estimated' else ''}")
    lines += ["", "test-file clusters (OWASP) give a design effect of 1.0 by construction, not by measurement",
              f"rules within 0.05 of the admission bar ({bar['rule_lower']}) by the current lower bound",
              f"{'rule':<46} {'TP':>5} {'FP':>4} {'lower':>7} {'ds_lo':>7} {'repos':>5} {'deff':>7} "
              f"{'clus_lo':>7} {'boot_lo':>7}"]
    rules_cl = (ledger.get("clustered") or {}).get("rules") or {}
    for r in near_bar(ledger):
        notes = []
        if r["deff_source"] and r["deff_source"] != "estimated":
            b = (rules_cl.get(r["rule"]) or {}).get("borrowed_icc") or {}
            notes.append("deff worst case, ICC = 1" + (f"; pooled ICC: deff {b['deff']}, lower {f(b['wilson_lower'])}"
                                                       if b else ""))
        if r["bootstrap_note"]:
            notes.append(r["bootstrap_note"])
        note = f"  ({'; '.join(notes)})" if notes else ""
        lines.append(f"{r['rule']:<46} {r['tp']:>5} {r['fp']:>4} {f(r['lower']):>7} {f(r['ds_lower']):>7} "
                     f"{r['repos'] or '-':>5} {r['deff'] or '-':>7} {f(r['clustered_lower']):>7} "
                     f"{f(r['bootstrap_lower']):>7}{note}")
    return "\n".join(lines)


def render_languages(claims: dict[str, dict], bar: dict) -> str:
    def f(x):
        return "-" if x is None else f"{x:.4f}"
    lines = [f"per-language verified-tier claim (held-out, population-weighted; bar {bar['tier_lower']})",
             f"{'language':<12} {'labelled':>8} {'admitted':>8} {'hoTP':>5} {'hoFP':>5} {'prec':>7} "
             f"{'lower':>7} {'claim_lo':>8}  claim"]
    for lang, c in claims.items():
        note = f" (population unknown: {', '.join(c['population_unknown'])})" if c["population_unknown"] else ""
        lines.append(f"{lang:<12} {c['rules_labelled']:>8} {c['rules_admitted']:>8} {c['held_out_tp']:>5} "
                     f"{c['held_out_fp']:>5} {f(c['precision']):>7} {f(c['wilson_lower']):>7} "
                     f"{f(c['claim_lower']):>8}  {'yes' if c['claim'] else 'no'}{note}")
    return "\n".join(lines)


def snapshot_counts() -> dict[str, dict[str, int]]:
    out = {}
    for t in SNAPSHOT_TARGETS:
        p = SNAPSHOTS / f"{t}.json"
        if p.is_file():
            out[t] = json.loads(p.read_text(encoding="utf-8")).get("by_rule", {})
    return out


def _counts(e: dict) -> tuple:
    """What makes a rebuild a re-label: the counts, and who labelled (a new
    labeller prompt version is a re-label even when the counts come out the
    same)."""
    return (e["tp"], e["fp"], e["unsure"], tuple(sorted(e["held_out"].items())),
            tuple(sorted(e.get("labellers") or [])))


def build(records: list[dict], previous: dict | None, today: str, verified: set[str],
          snapshots: dict[str, dict[str, int]] | None = None, anchors: list[dict] | None = None) -> dict:
    """The ledger from label records. `anchors` are the calibration records
    (known truth, labelled blind) Dawid-Skene learns the labellers' error
    rates from; they never count toward a rule."""
    prev = (previous or {}).get("rules") or {}
    bar = {**P.DEFAULT_BAR, **((previous or {}).get("bar") or {})}
    verdicts = final_verdicts(records)
    rules = rule_entries(verdicts, bar)
    snapshots = snapshots or {}
    for rule, e in rules.items():
        old = prev.get(rule) or {}
        e["fp_notes"] = list(dict.fromkeys([*(old.get("fp_notes") or []), *e["fp_notes"]]))
        if "tp" in old and isinstance(old.get("held_out"), dict) and _counts(old) == _counts(e):
            e["updated"] = old.get("updated", today)
            e["snapshot_counts"] = old.get("snapshot_counts", {})
        else:
            e["updated"] = today
            e["snapshot_counts"] = {t: int(c.get(rule, 0)) for t, c in snapshots.items()}
    # A rule with notes but no labels keeps its notes: the verify pass reads them.
    for rule, old in prev.items():
        if rule not in rules and old.get("fp_notes"):
            rules[rule] = {"tp": 0, "fp": 0, "unsure": 0, "n": 0,
                           "held_out": {"tp": 0, "fp": 0, "unsure": 0},
                           "fp_notes": old["fp_notes"], "admitted": False,
                           "admitted_reason": "0 label(s)", "updated": old.get("updated", today),
                           "snapshot_counts": {}}
    tier = tier_claim(rules, bar, verified)
    return {"_about": ABOUT, "version": 1, "bar": bar, "generated": today,
            "rules": dict(sorted(rules.items())), "tier": tier,
            "dawid_skene": dawid_skene_block(records, anchors or [], verdicts, rules, bar, tier["rules"]),
            "clustered": clustered_block(verdicts, rules, bar, tier["rules"])}


def declared_verified(config: dict | None = None) -> set[str]:
    from arbiter.rule_meta import shipped_rules
    return {r for r in shipped_rules() if P.declared_verified(r, config)}


def write(ledger: dict, paths=(LEDGER, PACKAGED)) -> None:
    text = json.dumps(ledger, indent=1, sort_keys=False) + "\n"
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def render(ledger: dict) -> str:
    lines = [f"{'rule':<56} {'TP':>4} {'FP':>4} {'?':>3} {'lower':>6} {'kappa':>6} {'pop':>5} "
             f"{'wtd':>6}  admitted"]
    for rule, e in ledger["rules"].items():
        lo = f"{e['wilson_lower']:.3f}" if e.get("wilson_lower") is not None else "-"
        k = f"{e['kappa']:.2f}" if e.get("kappa") is not None else "-"
        pop = "?" if e.get("population_unknown") else str(e.get("population") or "-")
        w = (e.get("weighted") or {}).get("precision")
        wtd = f"{w:.3f}" if w is not None else "-"
        lines.append(f"{rule:<56} {e['tp']:>4} {e['fp']:>4} {e['unsure']:>3} {lo:>6} {k:>6} {pop:>5} "
                     f"{wtd:>6}  {'yes' if e['admitted'] else 'no'}: {e.get('admitted_reason', '')}")
    unknown = sorted(r for r, e in ledger["rules"].items() if e.get("population_unknown"))
    if unknown:
        lines.append(f"population unknown for {len(unknown)} rule(s) (labels with no stratum_size; "
                     f"tools/label_populations.py): {', '.join(unknown)}")
    t = ledger.get("tier") or {}
    o = t.get("overall")
    if o:
        lines.append(f"verified tier, held-out, population-weighted: precision {o['precision']} "
                     f"(95% lower {o['wilson_lower']}, n_eff {o['n_eff']}; coverage {o['coverage']}, "
                     f"claim lower {o['claim_lower']}) over {len(t['rules'])} rule(s)"
                     f"; 99% claim: {'yes' if t.get('claim') else 'no'}")
    elif t.get("population_unknown"):
        lines.append(f"verified tier: population unknown for {', '.join(t['population_unknown'])}; no claim")
    else:
        lines.append("verified tier: no held-out labels on any verified rule; no claim")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="rebuild the ledger from label files")
    b.add_argument("labels", type=Path, nargs="*", help=".jsonl label files, or sheets (.csv/.json)")
    b.add_argument("--sheet-batch", default="sheet", help="sheets: the sample these sheets label")
    b.add_argument("--sheet-source", default="sheet", help="sheets: corpus name")
    b.add_argument("--sheet-held-out", action="store_true", help="sheets: the sample is held out")
    b.add_argument("--date", default=_dt.date.today().isoformat())
    b.add_argument("--out", type=Path, help="write here only (default: the ledger and its packaged copy)")
    b.add_argument("--model-prompt", default=None,
                   help="model labels to keep, by labeller prompt version (default: the current "
                        "tools/label_models.py PROMPT_VERSION; 'any' keeps every version)")
    sub.add_parser("show")
    r = sub.add_parser("report", help="the tier claim per language (JavaScript apart from TypeScript)")
    r.add_argument("--ledger", type=Path, default=LEDGER)
    sub.add_parser("check", help="fail when the written ledger differs from its packaged copy")
    args = ap.parse_args(argv)
    if args.cmd == "show":
        print(render(P.load_ledger(LEDGER)))
        return 0
    if args.cmd == "report":
        ledger = P.load_ledger(args.ledger)
        bar = {**P.DEFAULT_BAR, **(ledger.get("bar") or {})}
        verified = declared_verified()
        print(render_languages(language_claims(ledger.get("rules") or {}, bar, verified), bar))
        print(render_alternatives(ledger, bar, verified))
        return 0
    if args.cmd == "check":
        same = LEDGER.read_bytes() == PACKAGED.read_bytes()
        print("ok: ledger and packaged copy match" if same else
              "FAIL: tools/gold/precision.json and src/arbiter/packs/precision.json differ")
        return 0 if same else 1
    records: list[dict] = []
    for p in args.labels:
        records += (read_jsonl(p) if p.name.endswith((".jsonl", ".jsonl.gz"))
                    else read_sheet(p, args.sheet_batch, args.sheet_source, args.sheet_held_out))
    calibration = [r for r in records if str(r.get("source", "")).startswith("calibration:")]
    records, skipped = drop_calibration(records)
    if skipped:
        print(f"left out {skipped} labeller-calibration records (they measure the labellers, not the rules)",
              file=sys.stderr)
    version = current_model_prompt() if args.model_prompt is None else \
        ("" if args.model_prompt == "any" else args.model_prompt)
    records, stale = drop_superseded_model_labels(records, version)
    calibration, _ = drop_superseded_model_labels(calibration, version)
    if stale:
        print(f"left out {stale} model labels made with a labeller prompt other than {version}",
              file=sys.stderr)
    panel = current_panel_prompt() if args.model_prompt is None else \
        ("" if args.model_prompt == "any" else current_panel_prompt())
    records, stale = drop_superseded_panel_labels(records, panel)
    if stale:
        print(f"left out {stale} panel labels made with a panel prompt other than {panel}",
              file=sys.stderr)
    previous = P.load_ledger(LEDGER) if LEDGER.is_file() else None
    ledger = build(records, previous, args.date, declared_verified(), snapshot_counts(), anchors=calibration)
    write(ledger, (args.out,) if args.out else (LEDGER, PACKAGED))
    print(render(ledger))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
