#!/usr/bin/env python3
"""An independent labelling panel of models from different companies (ARB-122).

    # Label findings: one record per model, distinct labeller names.
    python tools/panel/panel.py label --report gold-report.json --corpus ~/wt/corpus-gold \\
        --per-rule per-rule.json --source heldout-r6-model --max-calls 300 --budget-usd 15

    # Measure the panel on ground truth it never saw (OWASP, Juliet, CVE
    # pairs, planted twins): per model, per family and the panel's verdict.
    python tools/panel/panel.py calibrate --n 60 --markdown out.md

    # Which rules to label next: labels still needed to reach Wilson 0.99.
    python tools/panel/panel.py prioritise --top 30 --per-rule-out per-rule.json

How it works. Each seat is one command-line model on the user's own
subscription (tools/panel/providers.py): Claude (`claude -p`, Anthropic),
Codex (`codex exec`, OpenAI) and Gemini (`gemini -p`, Google); Copilot
(`copilot -p`) is an optional fourth seat, seated only when its model
routing lands on a vendor no other seat holds. Every seat
gets the same blind packet `tools/label_models.py` builds -- the code
excerpt, the file path and a neutral claim, never Arbiter's rule text,
confidence or the verify pass's verdict -- and answers alone. Each answer is
written as its own label record, labeller `<seat>-<model>:panel/v1`
(`claude-opus-5-5:panel/v1` for Claude), so the ledger's unanimity rule
sees independent labellers and kappa can pair two vendors.

Independence is enforced, not assumed: two seats that resolve to one vendor
are refused (the later seat is dropped and the run says so), Copilot never
seats an Anthropic model, and an answer from a model other than the one its
seat resolved to is discarded. The panel's prompt (`panel/v1`) is not the
verify pass's (`verify-v3`), so a panel label never comes from the verifier
(docs/precision.md, "Label format").

A seat that is not installed or not logged in is skipped, not a failure;
a usage limit stops that seat only; `--max-calls` and `--budget-usd` cap
each seat. Cached answers cost nothing and a rerun resumes.

Labels from this panel are model labels: precision built on them is
"model-labelled conformance", never a certified number.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import sys
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import providers as pv  # noqa: E402

ROOT = pv.ROOT
lm, PL, g = pv.lm, pv.PL, pv.lm.g
from arbiter import precision as P  # noqa: E402

PANEL_VERSION = "panel/v1"
SEATS = ("claude", "codex", "gemini", "copilot")
LABELS_DIR = ROOT / "tools" / "gold" / "labels"
DEFAULT_GT = [LABELS_DIR / n for n in ("owasp-java.jsonl", "owasp-python.jsonl", "cve-fix.jsonl",
                                        "juliet-java.jsonl.gz")]
TARGET = P.DEFAULT_BAR["offline_lower"]   # 0.99: a rule verified on its own bound

# Item sources whose code is public: the open-source gold and held-out
# corpora, CVE fix pairs and suspects, and the published benchmarks. A seat
# marked `public_only` (Gemini on a free-tier API key, whose prompts may be
# used for training) gets nothing else -- not the planted or AI-written
# fixtures, not a report of someone's own repository. A report item also
# needs its corpus under a public corpus root.
PUBLIC_SOURCES = ("gold-model", "heldout-*-model", "cve-suspects-model", "calibration:owasp-java",
                  "calibration:owasp-python", "calibration:juliet-java", "calibration:cve-fix")
PUBLIC_ROOTS = (Path("~/wt/corpus-gold").expanduser(), Path("~/wt/corpus-gt").expanduser())


def public_item(it: dict) -> bool:
    import fnmatch
    if not any(fnmatch.fnmatchcase(str(it.get("source", "")), pat) for pat in PUBLIC_SOURCES):
        return False
    root = it.get("corpus_root")
    if root is None:
        return not str(it.get("source", "")).endswith("-model") or it.get("source") == "cve-suspects-model"
    r = Path(root).expanduser().resolve()
    return any(r == pr.resolve() or pr.resolve() in r.parents for pr in PUBLIC_ROOTS)


# ---------------------------------------------------------------------------
# Seats
# ---------------------------------------------------------------------------

class Seat:
    """One provider with its own budget, counters and stop flag."""

    def __init__(self, provider: pv.Provider, max_calls: int, budget_usd: float | None, jobs: int):
        self.p, self.max_calls, self.usd_cap = provider, max_calls, budget_usd
        self.name = provider.seat
        self.vendor = provider.vendor   # fixed when seated; every answer must match it
        self.lock = threading.Lock()
        self.sem = threading.Semaphore(max(1, jobs))
        self.calls = self.in_flight = self.cached = 0
        self.failed = self.unparseable = self.withheld = 0
        self.cost: Counter = Counter()
        self.max_usd = 0.0
        self.stopped = ""      # why the seat stopped, when it did

    def reserve(self) -> bool:
        with self.lock:
            if self.stopped:
                return False
            if self.calls + self.in_flight >= self.max_calls:
                self.stopped = f"call cap {self.max_calls} reached"
                return False
            if self.usd_cap is not None and \
                    self.cost["usd"] + max(self.max_usd * 1.5, 0.05) * (self.in_flight + 1) > self.usd_cap:
                self.stopped = f"budget ${self.usd_cap} reached"
                return False
            self.in_flight += 1
            return True

    def settle(self, cost: dict | None) -> None:
        with self.lock:
            self.in_flight -= 1
            self.calls += 1
            for k, v in (cost or {}).items():
                if isinstance(v, (int, float)):
                    self.cost[k] += v
            self.max_usd = max(self.max_usd, float((cost or {}).get("usd") or 0))

    def stop(self, why: str) -> None:
        with self.lock:
            self.stopped = self.stopped or why

    def summary(self) -> dict:
        return {"seat": self.name, "model": self.p.model or self.p.requested, "vendor": self.vendor,
                "labeller": f"{self.p.labeller()}:{PANEL_VERSION}", "new_calls": self.calls,
                "cached": self.cached, "failed": self.failed, "unparseable": self.unparseable,
                "withheld_private": self.withheld,
                "cost": {k: round(v, 6) for k, v in sorted(self.cost.items())},
                "stopped": self.stopped}


class Panel:
    def __init__(self, providers: list[pv.Provider], cache: "lm.Cache | None" = None,
                 max_calls: dict[str, int] | None = None, budget_usd: dict[str, float] | None = None,
                 jobs_per_seat: int = 2, today: str | None = None):
        self.providers, self.cache = providers, cache
        self.max_calls, self.budget_usd = max_calls or {}, budget_usd or {}
        self.jobs_per_seat = jobs_per_seat
        self.today = today or time.strftime("%Y-%m-%d", time.gmtime())
        self.seats: list[Seat] = []
        self.skipped: dict[str, str] = {}
        self.refused: dict[str, str] = {}
        self.vendors: dict[str, str] = {}     # vendor -> seat holding it
        self.lock = threading.Lock()

    def resolve(self) -> list[Seat]:
        """Seat each available provider whose vendor no earlier seat holds."""
        for p in self.providers:
            if hasattr(p, "forbid"):     # Copilot picks a model of a vendor not yet seated
                p.forbid |= set(self.vendors)
            ok, why = p.available()
            if not ok:
                self.skipped[p.seat] = why
                continue
            v = p.vendor
            if not v:
                self.refused[p.seat] = f"vendor of {p.model or p.requested} unknown"
                continue
            if v in self.vendors:
                self.refused[p.seat] = f"same vendor ({v}) as the {self.vendors[v]} seat"
                continue
            self.vendors[v] = p.seat
            self.seats.append(Seat(p, self.max_calls.get(p.seat, 10 ** 9), self.budget_usd.get(p.seat),
                                   self.jobs_per_seat))
        return self.seats

    # -- one answer --------------------------------------------------------

    def ask(self, it: dict, seat: Seat) -> dict | None:
        p = seat.p
        if getattr(p, "public_only", False) and not public_item(it):
            with seat.lock:
                seat.withheld += 1         # never sent: the seat may see public code only
            return None
        key = lm.Cache.key(it, PANEL_VERSION, f"{p.seat}:{p.requested}", PANEL_VERSION)
        hit = self.cache.get(key) if self.cache else None
        if hit and pv.model_vendor(hit["model"]) == seat.vendor:
            with seat.lock:
                seat.cached += 1
            p.model = p.model or hit["model"]
            return self.record(it, seat, hit, cached=True)
        with seat.sem:          # at most jobs-per-seat calls in flight on one subscription
            return self._ask(it, seat, key)

    def _ask(self, it: dict, seat: Seat, key: str) -> dict | None:
        p = seat.p
        if not seat.reserve():
            return None
        cost = None
        try:
            ans = p.label(lm.SYSTEM, lm.item_prompt(it))
            cost = ans.get("cost")
        except pv.UsageLimit as exc:
            seat.stop(f"usage limit: {str(exc)[:160]}")
        except pv.Unavailable as exc:
            seat.stop(f"unavailable: {str(exc)[:160]}")
        except pv.VendorConflict as exc:
            seat.stop(f"refused: {str(exc)[:160]}")
            cost = exc.cost
        except pv.ParseError as exc:
            with seat.lock:
                seat.unparseable += 1
            print(f"  {p.seat}: unparseable reply on {it['finding_id']}: {exc}", file=sys.stderr)
        except (pv.ProviderError, OSError) as exc:
            with seat.lock:
                seat.failed += 1
            print(f"  {p.seat}: call failed on {it['finding_id']}: {str(exc)[:200]}", file=sys.stderr)
        else:
            v = pv.model_vendor(ans["model"])
            holder = self.vendors.get(v)
            if v != seat.vendor or (holder and holder != p.seat):
                seat.stop(f"refused: answered by {ans['model']} ({v or 'unknown vendor'})")
                seat.settle(cost)
                return None
            seat.settle(cost)
            if self.cache:
                self.cache.put({"key": key, "finding_id": it["finding_id"], "seat": p.seat,
                                "label": ans["label"], "reason": ans["reason"], "model": ans["model"],
                                "cost": cost or {}, "prompt_version": PANEL_VERSION,
                                "excerpt_sha256": it["excerpt_sha256"],
                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            return self.record(it, seat, ans)
        seat.settle(cost)
        return None

    def record(self, it: dict, seat: Seat, ans: dict, cached: bool = False) -> dict:
        p = seat.p
        own = {"claude": "claude", "gemini": "gemini"}.get(p.seat)   # model names that carry the seat
        stem = ans["model"] if own and ans["model"].startswith(own) else f"{p.seat}-{ans['model']}"
        rec = g.label(it["finding"], ans["label"], labeller=f"{stem}:{PANEL_VERSION}",
                      source=it["source"], held_out=it["held_out"], reason=ans["reason"],
                      excerpt_sha256=it["excerpt_sha256"], category=it["category"],
                      panel_seat=p.seat, model=ans["model"], vendor=seat.vendor, date=self.today,
                      cost={} if cached else (ans.get("cost") or {}),
                      **{k: it[k] for k in lm.ls.POPULATION_KEYS if k in it})
        if "truth" in it:
            rec["truth"] = it["truth"]
        return rec

    # -- a run -------------------------------------------------------------

    def run(self, items: list[dict], out: Path) -> list[dict]:
        if not self.seats:
            self.resolve()
        old = g.read_jsonl(out)
        done = {(r["finding_id"], r.get("excerpt_sha256", ""), r.get("panel_seat")) for r in old}
        todo = [(it, s) for it in items for s in self.seats
                if (it["finding_id"], it["excerpt_sha256"], s.name) not in done]
        print(f"{len(items)} items x {len(self.seats)} seats: {len(todo)} answers to get "
              f"({len(items) * len(self.seats) - len(todo)} already in {out})", file=sys.stderr)
        new: list[dict] = []
        out.parent.mkdir(parents=True, exist_ok=True)
        workers = max(1, self.jobs_per_seat) * max(1, len(self.seats))
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(self.ask, it, s) for it, s in todo]
            for i, fut in enumerate(cf.as_completed(futs), 1):
                rec = fut.result()
                if rec is not None:
                    with self.lock:
                        new.append(rec)
                        with out.open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec, sort_keys=True) + "\n")
                if i % 25 == 0:
                    print(f"  {i}/{len(todo)}", file=sys.stderr, flush=True)
        return old + new

    def report(self) -> dict:
        return {"panel_version": PANEL_VERSION, "seats": [s.summary() for s in self.seats],
                "skipped": self.skipped, "refused": self.refused}


# ---------------------------------------------------------------------------
# Calibration: the panel against truth it never saw
# ---------------------------------------------------------------------------

def _wilson(k: int, n: int) -> list | None:
    ci = P.wilson(k, n)
    return [round(ci[0], 3), round(ci[1], 3)] if ci else None


def score(pairs: list[tuple[str, str]]) -> dict:
    """(label, truth) pairs -> agreement with truth. `accuracy` is over
    decided labels; `tp_precision` is how often a tp call was right (the
    number a precision claim rests on); unsure counts in neither."""
    c = Counter(pairs)
    n = len(pairs)
    decided = sum(v for (m, _t), v in c.items() if m != "unsure")
    right = c[("tp", "tp")] + c[("fp", "fp")]
    tp_calls = c[("tp", "tp")] + c[("tp", "fp")]
    return {"n": n, "decided": decided, "unsure": n - decided, "correct": right,
            "accuracy": round(right / decided, 3) if decided else None,
            "accuracy_wilson": _wilson(right, decided),
            "tp_calls": tp_calls, "tp_precision": round(c[("tp", "tp")] / tp_calls, 3) if tp_calls else None,
            "tp_precision_wilson": _wilson(c[("tp", "tp")], tp_calls),
            "false_tp": c[("tp", "fp")], "missed_tp": c[("fp", "tp")]}


def panel_verdict(labels: list[str]) -> str:
    """The ledger's rule (precision_ledger.final_verdicts): every decided
    label agrees, else unsure."""
    decided = {x for x in labels if x != "unsure"}
    return decided.pop() if len(decided) == 1 else "unsure"


def calibration(records: list[dict]) -> dict:
    recs = [r for r in records if r.get("truth") in ("tp", "fp") and str(r.get("labeller", "")).endswith(
        ":" + PANEL_VERSION)]
    by_model: dict[str, list[dict]] = defaultdict(list)
    by_item: dict[str, list[dict]] = defaultdict(list)
    for r in recs:
        by_model[r["labeller"]].append(r)
        by_item[r["finding_id"]].append(r)
    fam = lambda r: r.get("category") or lm.category(r["rule_id"])  # noqa: E731
    models = {}
    for name, rs in sorted(by_model.items()):
        fams = defaultdict(list)
        for r in rs:
            fams[fam(r)].append((r["label"], r["truth"]))
        cost: Counter = Counter()
        for r in rs:
            for k, v in (r.get("cost") or {}).items():
                if isinstance(v, (int, float)):
                    cost[k] += v
        models[name] = {**score([(r["label"], r["truth"]) for r in rs]),
                        "seat": rs[0].get("panel_seat"), "vendor": rs[0].get("vendor"),
                        "by_family": {f: score(v) for f, v in sorted(fams.items())},
                        "cost": {k: round(v, 6) for k, v in sorted(cost.items())}}
    seats_per_item = Counter(len({r["labeller"] for r in rs}) for rs in by_item.values())
    full = max(seats_per_item) if seats_per_item else 0
    panel_pairs, panel_fams = [], defaultdict(list)
    for rs in by_item.values():
        if len({r["labeller"] for r in rs}) < full:
            continue            # the panel verdict is over items every seat answered
        pair = (panel_verdict([r["label"] for r in rs]), rs[0]["truth"])
        panel_pairs.append(pair)
        panel_fams[fam(rs[0])].append(pair)
    names = sorted(by_model)
    kappas = {}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            la, lb = [], []
            for rs in by_item.values():
                d = {r["labeller"]: r["label"] for r in rs}
                if d.get(a, "unsure") != "unsure" and d.get(b, "unsure") != "unsure":
                    la.append(d[a])
                    lb.append(d[b])
            k = P.cohens_kappa(la, lb)
            kappas[f"{a} | {b}"] = {"n": len(la), "kappa": None if k is None else round(k, 3),
                                    "agreement": round(sum(x == y for x, y in zip(la, lb)) / len(la), 3)
                                    if la else None}
    return {"items": len(by_item), "seats_per_item": dict(seats_per_item), "models": models,
            "panel": {**score(panel_pairs), "seats": full,
                      "by_family": {f: score(v) for f, v in sorted(panel_fams.items())}},
            "pairwise": kappas}


def _fmt(x) -> str:
    return "-" if x is None else (f"{x:.3f}" if isinstance(x, float) else str(x))


def _ci(x) -> str:
    return "-" if not x else f"{x[0]:.3f}–{x[1]:.3f}"


def render_calibration(cal: dict, run: dict | None = None) -> str:
    head = ("| {} | n | decided | unsure | accuracy (decided) | Wilson 95% | tp calls | tp precision "
            "| Wilson 95% | false tp | missed tp |")
    rule = "|---|---:|---:|---:|---:|---|---:|---:|---|---:|---:|"

    def row(name, s):
        return (f"| {name} | {s['n']} | {s['decided']} | {s['unsure']} | {_fmt(s['accuracy'])} | "
                f"{_ci(s['accuracy_wilson'])} | {s['tp_calls']} | {_fmt(s['tp_precision'])} | "
                f"{_ci(s['tp_precision_wilson'])} | {s['false_tp']} | {s['missed_tp']} |")
    out = [f"Panel calibration ({PANEL_VERSION}): {cal['items']} ground-truth items, "
           f"seats per item {cal['seats_per_item']}.", "", head.format("model"), rule]
    for name, s in cal["models"].items():
        out.append(row(name, s))
    out.append(row(f"**panel (unanimous of {cal['panel']['seats']})**", cal["panel"]))
    out += ["", head.format("family / model"), rule]
    fams = sorted({f for s in cal["models"].values() for f in s["by_family"]} | set(cal["panel"]["by_family"]))
    for f in fams:
        for name, s in cal["models"].items():
            if f in s["by_family"]:
                out.append(row(f"{f} / {name}", s["by_family"][f]))
        if f in cal["panel"]["by_family"]:
            out.append(row(f"{f} / **panel**", cal["panel"]["by_family"][f]))
    out += ["", "| pair | both decided | agreement | kappa |", "|---|---:|---:|---:|"]
    for k, v in cal["pairwise"].items():
        out.append(f"| {k} | {v['n']} | {_fmt(v['agreement'])} | {_fmt(v['kappa'])} |")
    out += ["", "| model | cost (this file's new calls) |", "|---|---|"]
    for name, s in cal["models"].items():
        out.append(f"| {name} | {', '.join(f'{k}={v}' for k, v in s['cost'].items()) or '-'} |")
    if run:
        out += ["", "Run: " + json.dumps(run, sort_keys=True)]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Prioritising: labels still needed to reach the bar
# ---------------------------------------------------------------------------

def labels_needed(tp: int, fp: int, target: float = TARGET, cap: int = 20000) -> int | None:
    """The fewest further labels, all of them tp (the best case), that lift
    the Wilson 95% lower bound of tp/(tp+fp) to `target`; None when even
    `cap` would not."""
    def ok(k: int) -> bool:
        ci = P.wilson(tp + k, tp + fp + k)
        return bool(ci) and ci[0] >= target
    if ok(0):
        return 0
    if not ok(cap):
        return None
    lo, hi = 0, cap
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (lo, mid) if ok(mid) else (mid, hi)
    return hi


def prioritise(ledger: dict, target: float = TARGET, include_unlabelled: bool = False,
               cap: int = 20000) -> list[dict]:
    rules = dict(ledger.get("rules") or {})
    if include_unlabelled:
        from arbiter.rule_meta import shipped_rules
        for r in shipped_rules():
            rules.setdefault(r, {"tp": 0, "fp": 0, "unsure": 0})
    rows = []
    for rule, e in rules.items():
        tp, fp = int(e.get("tp", 0)), int(e.get("fp", 0))
        lower = P.wilson(tp, tp + fp)
        rows.append({"rule": rule, "tp": tp, "fp": fp, "unsure": int(e.get("unsure", 0)),
                     "wilson_lower": round(lower[0], 4) if lower else None,
                     "needed": labels_needed(tp, fp, target, cap),
                     "has_claim": lm.claim_for(rule) is not None,
                     "admitted": bool(e.get("admitted"))})
    rows.sort(key=lambda r: (r["needed"] is None, r["needed"] or 0, -r["tp"], r["rule"]))
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _seat_map(pairs: list[str], cast) -> dict:
    out = {}
    for p in pairs or []:
        k, _, v = p.partition("=")
        if k not in SEATS or not v:
            raise SystemExit(f"want seat=value with seat in {SEATS}, got {p!r}")
        out[k] = cast(v)
    return out


def build_panel(args) -> Panel:
    seats = [s.strip() for s in args.seats.split(",") if s.strip()]
    models = {"claude": args.claude_model, "codex": args.codex_model, "gemini": args.gemini_model}
    provs = [pv.make(s, models.get(s), tuple(args.copilot_models.split(","))) for s in seats]
    caps = {s: args.max_calls for s in SEATS} | _seat_map(args.cap, int)
    usd = {"claude": args.budget_usd} | _seat_map(args.seat_budget_usd, float)
    cache = lm.Cache(args.cache) if args.cache else None
    return Panel(provs, cache, caps, usd, args.jobs_per_seat)


def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--seats", default=",".join(SEATS), help="comma list, in priority order")
    ap.add_argument("--claude-model", default="opus")
    ap.add_argument("--codex-model", default="gpt-6-astra")
    ap.add_argument("--gemini-model", default="", help="default: the Gemini CLI's own model choice")
    ap.add_argument("--copilot-models", default=",".join(pv.COPILOT_MODELS),
                    help="tried in order; the first this account can use is pinned")
    ap.add_argument("--max-calls", type=int, default=200, help="new calls per seat")
    ap.add_argument("--cap", action="append", metavar="SEAT=N", help="per-seat call cap override")
    ap.add_argument("--budget-usd", type=float, default=10.0, help="Claude's spend cap (the CLI reports USD)")
    ap.add_argument("--seat-budget-usd", action="append", metavar="SEAT=USD")
    ap.add_argument("--jobs-per-seat", type=int, default=2)
    ap.add_argument("--cache", type=Path, default=ROOT / "arbiter-out" / "panel-cache.jsonl")
    ap.add_argument("--seed", type=int, default=20261024)
    ap.add_argument("--max", type=int, help="at most this many items")
    ap.add_argument("--dry-run", action="store_true", help="build items, resolve nothing, print one prompt")
    ap.add_argument("--run-json", type=Path, help="write the run summary (seats, costs) here")


def _finish(panel: Panel, args) -> int:
    rep = panel.report()
    print(json.dumps(rep, indent=1), file=sys.stderr)
    if args.run_json:
        args.run_json.write_text(json.dumps(rep, indent=1) + "\n", encoding="utf-8")
    return 0 if panel.seats else 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    lab = sub.add_parser("label", help="label findings, one record per model")
    _common(lab)
    lab.add_argument("--report", type=Path, help="gold-report.json from --raw")
    lab.add_argument("--source", default="gold-model")
    lab.add_argument("--corpus", type=Path, default=Path("~/wt/corpus-gold"))
    lab.add_argument("--n", type=int, default=600)
    lab.add_argument("--per-rule", type=Path, help="JSON {rule: n} (e.g. from prioritise --per-rule-out)")
    lab.add_argument("--ai-corpus", action="store_true")
    lab.add_argument("--suspects", type=Path)
    lab.add_argument("--out", type=Path, help="default tools/gold/labels/panel-<source>.jsonl")
    cal = sub.add_parser("calibrate", help="measure the panel on ground truth")
    _common(cal)
    cal.add_argument("--ground-truth", type=Path, nargs="+", default=DEFAULT_GT)
    cal.add_argument("--n", type=int, default=60)
    cal.add_argument("--exclude-labels", type=Path, nargs="*", default=[])
    cal.add_argument("--planted", nargs="*", metavar="CATEGORY", default=[])
    cal.add_argument("--planted-cap", type=int)
    cal.add_argument("--out", type=Path, default=LABELS_DIR / "panel-calibration.jsonl")
    cal.add_argument("--labels", type=Path, nargs="+", help="score these files only; no model calls")
    cal.add_argument("--json", type=Path)
    cal.add_argument("--markdown", type=Path)
    pr = sub.add_parser("prioritise", help="rank rules by labels needed for Wilson 0.99")
    pr.add_argument("--ledger", type=Path, default=PL.LEDGER)
    pr.add_argument("--target", type=float, default=TARGET)
    pr.add_argument("--include-unlabelled", action="store_true", help="also shipped rules with no labels")
    pr.add_argument("--claims-only", action="store_true", help="only rules the panel has a claim for")
    pr.add_argument("--top", type=int, default=40)
    pr.add_argument("--per-rule-out", type=Path, help="write {rule: n} for `label --per-rule`")
    pr.add_argument("--max-per-rule", type=int, default=400, help="cap on each rule's n in --per-rule-out")
    pr.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    if args.cmd == "prioritise":
        rows = prioritise(P.load_ledger(args.ledger), args.target, args.include_unlabelled)
        if args.claims_only:
            rows = [r for r in rows if r["has_claim"]]
        if args.json:
            args.json.write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
        if args.per_rule_out:
            want = {r["rule"]: min(r["needed"], args.max_per_rule) for r in rows[: args.top]
                    if r["needed"] and r["has_claim"]}
            args.per_rule_out.write_text(json.dumps(want, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{'rule':<58} {'TP':>5} {'FP':>4} {'lower':>6} {'needed':>7}  claim")
        for r in rows[: args.top]:
            print(f"{r['rule']:<58} {r['tp']:>5} {r['fp']:>4} {_fmt(r['wilson_lower']):>6} "
                  f"{_fmt(r['needed']) if r['needed'] is not None else 'never':>7}  "
                  f"{'yes' if r['has_claim'] else 'no'}")
        return 0

    if args.cmd == "calibrate" and args.labels:
        recs = [r for p in args.labels for r in g.read_jsonl(p)]
        return _write_calibration(calibration(recs), args, None)

    if args.cmd == "label":
        items: list[dict] = []
        if args.report:
            per_rule = json.loads(args.per_rule.read_text(encoding="utf-8")) if args.per_rule else None
            its, _meta = lm.items_from_report(args.report, args.corpus.expanduser(), args.n, args.seed,
                                              per_rule, source=args.source)
            items += [{**it, "corpus_root": str(args.corpus.expanduser())} for it in its]
        if args.ai_corpus:
            items += lm.items_from_ai_corpus()
        if args.suspects:
            items += lm.items_from_suspects(args.suspects)
        src = args.source if args.report else ("ai-corpus-model" if args.ai_corpus else "cve-suspects-model")
        out = args.out or LABELS_DIR / f"panel-{src}.jsonl"
    else:
        used = {r["finding_id"] for p in args.exclude_labels for r in g.read_jsonl(p)}
        items = lm.items_from_ground_truth(args.ground_truth, args.n, args.seed, used)
        if args.planted:
            items += lm.items_from_planted(set(args.planted), args.planted_cap)
        out = args.out
    if args.max:
        items = items[: args.max]
    print(f"{len(items)} items {dict(Counter(it['source'] for it in items))}", file=sys.stderr)
    if args.dry_run:
        if items:
            print(lm.SYSTEM + "\n----\n" + lm.item_prompt(items[0]))
        return 0
    panel = build_panel(args)
    panel.resolve()
    if not panel.seats:
        print("no seat available", file=sys.stderr)
        return _finish(panel, args)
    recs = panel.run(items, out)
    print(f"{len(recs)} records in {out}", file=sys.stderr)
    if args.cmd == "calibrate":
        ids = {it["finding_id"] for it in items}
        _write_calibration(calibration([r for r in recs if r["finding_id"] in ids]), args, panel.report())
    return _finish(panel, args)


def _write_calibration(cal: dict, args, run: dict | None) -> int:
    text = render_calibration(cal, run)
    print(text)
    if args.json:
        args.json.write_text(json.dumps({"calibration": cal, "run": run}, indent=1) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
