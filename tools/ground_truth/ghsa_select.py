#!/usr/bin/env python3
"""Select and freeze real-CVE fix pairs from the GitHub Advisory Database (ARB-121).

    python tools/ground_truth/ghsa_select.py select \\
        --out tools/ground_truth/ghsa_pairs.json \\
        --audit tools/ground_truth/ghsa_selection_audit.json
    python tools/ground_truth/ghsa_select.py check --pairs tools/ground_truth/ghsa_pairs.json

An external benchmark for the five supported languages: reviewed GitHub
Security Advisories (advisory data CC-BY-4.0) whose fix is a GitHub commit
touching source in that language, restricted to the CWEs a native security
rule of that language's pack is tagged with, so that recall is measured on
weaknesses Arbiter claims to look for. Every criterion below is fixed in
code and written into the output BEFORE any pair is scanned (docs/
external-cve-benchmark.md); the scorer is `ghsa_pairs.py`.

Population, per language (ecosystem pip / npm / go / maven / rubygems):

1. reviewed, not withdrawn, published before CUTOFF;
2. in scope: `cve_pairs.CWE_ALIASES`-expanded advisory CWEs meet the
   language pack's security-dimension CWE tags (`scope_cwes`);
3. a reference to a GitHub commit (`/commit/<sha>`, or `/pull/<n>/commits/
   <sha>`), tried in the advisory's order, the first that qualifies wins;
4. that commit qualifies by the ARB-067 rules (`cve_select`): exactly one
   parent, 1..MAX_FILES modified non-test source files of the language,
   at most MAX_LINES changed lines in them;
5. its repository is not in an already-sealed set (`sealed_repos`), and
   at most REPO_CAP pairs come from one repository per language.

Advisories are visited in the order of sha256("SEED:ghsa_id"), not the
API's, until TARGET pairs qualify or the frame is exhausted. Repositories
are then split, across all languages at once, into `sealed` and
`development` by sha256("SEED:split:repo") (half each); repositories of
the gold development corpus are kept in development. Only pointers are
stored (advisory, repository, commits, file paths, CWEs, licence): no code.

Read-only GitHub API calls through `gh api`; responses are cached under
--cache so an interrupted run resumes without repeating calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import cve_select as cs  # noqa: E402
from cve_pairs import CWE_ALIASES  # noqa: E402
from gt_common import cwe_match  # noqa: E402

SEED = 20261024
CUTOFF = "2026-10-24T00:00:00Z"
TARGET = 100
REPO_CAP = 3
SEALED_FRACTION = 0.5
LANGUAGES = ("python", "typescript", "go", "java", "ruby")
ECOSYSTEMS = cs.ECOSYSTEMS
MAX_FILES, MAX_LINES = cs.MAX_FILES, cs.MAX_LINES
PACKS = ROOT / "src" / "arbiter" / "packs" / "rules" / "ast"
DEFAULT_CACHE = Path("~/wt/corpus-gt/cve-ghsa/.select-cache")
_REF = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s#?]+)/(?:commit|pull/\d+/commits)/([0-9a-f]{40})"
                  r"(?:\.patch|\.diff)?(?:[#?].*)?/?$")
_PIN = re.compile(r"^get_pinned(?:_app)?\s+(\S+)\s+(\S+)\s+([0-9a-f]{40})\s+(\S+)\s*$")
_GH_URL = re.compile(r"github\.com/([^/\s]+)/([^/\s.]+(?:\.[^/\s.]+)*?)(?:\.git)?/?$")


class RateLimited(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Pure pieces (unit-tested without network)
# ---------------------------------------------------------------------------

def scope_cwes(pack_text_by_lang: dict[str, str]) -> dict[str, list[str]]:
    """Per language, the CWE ids that the pack's security-dimension rules carry."""
    import yaml
    out = {}
    for lang, text in pack_text_by_lang.items():
        rules = (yaml.safe_load(text) or {}).get("rules") or []
        cwes = {c for r in rules if r.get("dimension") == "security" for c in (r.get("cwe") or [])}
        out[lang] = sorted(cwes, key=lambda c: int(c.split("-")[1]))
    return out


def in_scope(advisory_cwes: list[str], scope: list[str]) -> list[str]:
    """The advisory CWEs a rule tagged with one of `scope` would match (the
    same `cwe_match` the scorer uses)."""
    return [c for c in advisory_cwes if cwe_match(list(scope), [c], CWE_ALIASES)]


def query_cwes(scope: list[str]) -> list[str]:
    """Every CWE id `in_scope` accepts: the scope itself and alias keys pointing into it."""
    cand = set(scope) | set(CWE_ALIASES)
    return sorted((c for c in cand if in_scope([c], scope)), key=lambda c: int(c.split("-")[1]))


def order_key(ghsa_id: str, seed: int = SEED) -> str:
    return hashlib.sha256(f"{seed}:{ghsa_id}".encode()).hexdigest()


def split_value(repo: str, seed: int = SEED) -> float:
    return int(hashlib.sha256(f"{seed}:split:{repo.lower()}".encode()).hexdigest(), 16) / 2 ** 256


def commit_refs(references: list[str]) -> list[tuple[str, str, str]]:
    out = []
    for ref in references or []:
        m = _REF.match((ref or "").strip())
        if m:
            owner, repo, sha = m.groups()
            key = (owner, repo.removesuffix(".git"), sha)
            if key not in out:
                out.append(key)
    return out


def qualify(commit: dict, language: str) -> tuple[list[dict] | None, str]:
    """(source files, "") when the commit qualifies, else (None, reason)."""
    if len(commit.get("parents") or []) != 1:
        return None, "not-one-parent"
    files = cs.source_files(commit.get("files") or [], language)
    if not files:
        return None, "no-source-file"
    if len(files) > MAX_FILES:
        return None, "too-many-files"
    if sum(f["additions"] + f["deletions"] for f in files) > MAX_LINES:
        return None, "too-many-lines"
    return files, ""


def eligible(adv: dict) -> str:
    """'' when the advisory is in the frame by date and status, else the reason."""
    if adv.get("withdrawn_at"):
        return "withdrawn"
    if (adv.get("published_at") or "") >= CUTOFF:
        return "after-cutoff"
    return ""


def repo_of_url(url: str) -> str | None:
    m = _GH_URL.search(url.strip())
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def sealed_and_dev_repos(root: Path = ROOT) -> tuple[dict[str, str], set[str]]:
    """({repo: why} for every repository already in a sealed set, gold development repos)."""
    sealed: dict[str, str] = {}
    held = json.loads((root / "tools" / "gold" / "heldout.json").read_text(encoding="utf-8"))
    pins = {}
    for script in ("fetch_corpus.sh", "fetch_heldout_r5.sh"):
        p = root / "tools" / script
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                m = _PIN.match(line.strip())
                if m and repo_of_url(m.group(2)):
                    pins[m.group(1)] = repo_of_url(m.group(2))
    for name in held.get("held_out", {}).get("gold_repos", []):
        if name in pins:
            sealed[pins[name]] = "heldout.json held_out (gold)"
    r5 = json.loads((root / "tools" / "gold" / "heldout-r5-repos.json").read_text(encoding="utf-8"))
    for meta in r5["repos"].values():
        sealed[meta["github"].lower()] = "heldout.json held_out_r5"
    for name in held.get("held_out_r5", {}).get("gold_repos", []):
        if name in pins:
            sealed.setdefault(pins[name], "heldout.json held_out_r5")
    cve = json.loads((root / "tools" / "ground_truth" / "cve_pairs.json").read_text(encoding="utf-8"))
    for p in cve["pairs"]:
        sealed[p["repo"].lower()] = "cve_pairs.json (cve-fix, sealed ground truth)"
    bench = json.loads((root / "tools" / "gold" / "benchmarks.json").read_text(encoding="utf-8"))
    for meta in bench.values():
        if isinstance(meta, dict) and repo_of_url(meta.get("url", "")):
            sealed[repo_of_url(meta["url"])] = "benchmarks.json (OWASP, sealed)"
    dev = {r for r in pins.values() if r not in sealed}
    return sealed, dev


def walk(language: str, advisories: list[dict], fetch_commit, fetch_repo, sealed: dict[str, str],
         scope: list[str], target: int = TARGET, cap: int = REPO_CAP) -> tuple[list[dict], list[list]]:
    """Visit `advisories` in seeded order; return (pairs, audit rows [ghsa, reason])."""
    pairs, audit = [], []
    per_repo: Counter = Counter()
    for adv in sorted(advisories, key=lambda a: order_key(a["ghsa_id"])):
        if len(pairs) >= target:
            break
        gid = adv["ghsa_id"]
        why = eligible(adv)
        cwes = sorted({c["cwe_id"] for c in adv.get("cwes") or []})
        scoped = in_scope(cwes, scope)
        if not why and not scoped:
            why = "out-of-scope-cwe"
        refs = commit_refs(adv.get("references") or []) if not why else []
        if not why and not refs:
            why = "no-commit-reference"
        reasons = []
        pick = None
        for owner, name, sha in refs:
            repo_meta = fetch_repo(f"{owner}/{name}")
            if repo_meta is None:
                reasons.append("repo-unavailable")
                continue
            repo = repo_meta["full_name"].lower()
            if repo in sealed:
                reasons.append("repo-already-sealed")
                continue
            if per_repo[repo] >= cap:
                reasons.append("repo-cap")
                continue
            commit = fetch_commit(repo_meta["full_name"], sha)
            if commit is None:
                reasons.append("commit-unavailable")
                continue
            files, r = qualify(commit, language)
            if files is None:
                reasons.append(r)
                continue
            pick = (repo_meta, sha, commit, files)
            break
        if not why and pick is None:
            why = reasons[0] if len(set(reasons)) == 1 else "+".join(sorted(set(reasons))) or "no-commit-reference"
        if pick is None:
            audit.append([gid, why])
            continue
        repo_meta, sha, commit, files = pick
        per_repo[repo_meta["full_name"].lower()] += 1
        pkg = ((adv.get("vulnerabilities") or [{}])[0].get("package") or {}).get("name")
        pairs.append({"ghsa": gid, "cve": adv.get("cve_id"), "language": language,
                      "ecosystem": ECOSYSTEMS[language], "package": pkg, "cwes": cwes,
                      "in_scope_cwes": scoped, "published": adv.get("published_at"),
                      "summary": (adv.get("summary") or "")[:160],
                      "repo": repo_meta["full_name"], "repo_license": repo_meta.get("license"),
                      "fix_sha": sha, "vuln_sha": commit["parents"][0]["sha"],
                      "files": sorted(f["filename"] for f in files),
                      "changed_lines": sum(f["additions"] + f["deletions"] for f in files),
                      "order_key": order_key(gid)})
        audit.append([gid, "selected"])
    return pairs, audit


def split(pairs: list[dict], dev_repos: set[str], seed: int = SEED,
          fraction: float = SEALED_FRACTION) -> dict[str, str]:
    """repo (lower case) -> 'sealed' | 'development', one decision per repository."""
    out = {}
    for repo in sorted({p["repo"].lower() for p in pairs}):
        if repo in dev_repos:
            out[repo] = "development"
        else:
            out[repo] = "sealed" if split_value(repo, seed) < fraction else "development"
    return out


# ---------------------------------------------------------------------------
# GitHub I/O (cached)
# ---------------------------------------------------------------------------

def _gh(args: list[str], timeout: int = 180) -> str:
    for attempt in range(4):
        r = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout
        err = r.stderr.strip()
        if "rate limit" in err.lower() or "HTTP 429" in err:
            raise RateLimited(err[:300])
        if "HTTP 404" in err or "HTTP 422" in err or "HTTP 409" in err or "HTTP 451" in err:
            raise LookupError(err[:300])
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(err[:300])


class Cache:
    def __init__(self, root: Path):
        self.root = root.expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.data = {}
        for name in ("commits", "repos"):
            p = self.root / f"{name}.json"
            self.data[name] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        self.calls = 0

    def save(self) -> None:
        for name, d in self.data.items():
            tmp = self.root / f"{name}.json.tmp"
            tmp.write_text(json.dumps(d), encoding="utf-8")
            tmp.replace(self.root / f"{name}.json")

    def repo(self, full: str) -> dict | None:
        key = full.lower()
        if key not in self.data["repos"]:
            self.calls += 1
            try:
                r = json.loads(_gh([f"repos/{full}"]))
                lic = (r.get("license") or {}).get("spdx_id")
                self.data["repos"][key] = {"full_name": r["full_name"], "license": lic,
                                           "archived": r.get("archived"), "fork": r.get("fork")}
            except LookupError:
                self.data["repos"][key] = None
            if self.calls % 25 == 0:
                self.save()
        return self.data["repos"][key]

    def commit(self, full: str, sha: str) -> dict | None:
        key = f"{full.lower()}@{sha}"
        if key not in self.data["commits"]:
            self.calls += 1
            try:
                c = json.loads(_gh([f"repos/{full}/commits/{sha}"]))
                self.data["commits"][key] = {
                    "parents": [{"sha": p["sha"]} for p in c.get("parents") or []],
                    "files": [{k: f.get(k) for k in ("filename", "status", "additions", "deletions")}
                              for f in c.get("files") or []]}
            except LookupError:
                self.data["commits"][key] = None
            if self.calls % 25 == 0:
                self.save()
        return self.data["commits"][key]


def frame(language: str, scope: list[str], cache_root: Path) -> list[dict]:
    """Every reviewed advisory of the ecosystem carrying a CWE `in_scope` accepts."""
    p = cache_root.expanduser() / f"frame-{language}.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    cwes = ",".join(c.split("-")[1] for c in query_cwes(scope))
    jq = ('.[] | {ghsa_id, cve_id, published_at, withdrawn_at, summary, references, '
          'cwes: [.cwes[]? | {cwe_id}], vulnerabilities: [.vulnerabilities[]? | {package}]}')
    out = _gh(["-X", "GET", "/advisories", "-f", f"ecosystem={ECOSYSTEMS[language]}", "-f", "type=reviewed",
               "-f", f"cwes={cwes}", "-f", "per_page=100", "--paginate", "--jq", jq], timeout=900)
    advs = {}
    for line in out.splitlines():
        if line.strip():
            a = json.loads(line)
            advs[a["ghsa_id"]] = a
    rows = sorted(advs.values(), key=lambda a: a["ghsa_id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rows), encoding="utf-8")
    return rows


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def criteria(scope: dict[str, list[str]]) -> dict:
    return {
        "seed": SEED, "cutoff_published_before": CUTOFF, "target_per_language": TARGET,
        "repo_cap_per_language": REPO_CAP, "sealed_fraction": SEALED_FRACTION,
        "advisory_type": "reviewed", "withdrawn": "excluded",
        "scope": "advisory CWEs, expanded with tools/ground_truth/cve_pairs.py CWE_ALIASES, meet the CWE tags "
                 "of the language pack's security-dimension rules (src/arbiter/packs/rules/ast/<lang>.yaml)",
        "scope_cwes": scope,
        "fix_reference": "first GitHub /commit/<sha> or /pull/<n>/commits/<sha> reference that qualifies",
        "commit": {"one_parent": True, "modified_non_test_source_files": f"1..{MAX_FILES}",
                   "max_changed_lines": MAX_LINES,
                   "source_extensions": {k: list(v) for k, v in cs.EXTENSIONS.items()},
                   "test_path_regex": cs._TEST.pattern},
        "order": "sha256('<seed>:<ghsa_id>') ascending, independent of API order",
        "split": "per repository, all languages at once: sealed when sha256('<seed>:split:<repo lower>') / 2^256 "
                 "< sealed_fraction; gold development repositories (tools/fetch_corpus.sh pins not held out) are "
                 "kept in development",
        "excluded_repositories": "every repository of an already-sealed set: tools/gold/heldout.json held_out "
                                 "and held_out_r5, tools/gold/heldout-r5-repos.json, tools/ground_truth/"
                                 "cve_pairs.json, tools/gold/benchmarks.json",
        "not_assessed": "a pair whose files cannot be fetched at both commits, or whose scan fails, is counted as "
                        "not assessed and left out of the denominator; the count is reported",
        "scoring": {
            "matching_cwe": "gt_common.cwe_match(finding.cwe, pair.in_scope_cwes, CWE_ALIASES); project-level "
                            "rules (cve_pairs.PROJECT_RULES) ignored",
            "recall_primary_hunk": "a matching finding on the vulnerable side within 3 lines of a hunk the fix "
                                   "changed (old-side lines [start-3, stop+3); an add-only hunk is the insertion "
                                   "point between old lines i and i+1, widened the same way)",
            "recall_secondary_function": "a matching finding in the vulnerable side's enclosing function of a "
                                         "changed hunk (arbiter.context.function_span); outside any function, "
                                         "the primary region",
            "recall_secondary_file": "a matching finding anywhere in a file the fix changed",
            "fixed_side_persistence": "of primary-detected pairs, those where every matching primary finding is "
                                      "still reported on the fixed side (same rule, within 2 lines of the mapped "
                                      "new-side hunk, or on a line with the same stripped text): a likely false-"
                                      "positive or partial-fix signal, not proof",
            "intervals": "Wilson 95% and a repository-cluster percentile bootstrap (2000 resamples, seeded); "
                         "effective sample size p(1-p)/var_bootstrap",
            "reporting": "development: per pair, per language, per (language, CWE); sealed: per language and "
                         "overall aggregates only",
        },
    }


HELDOUT = ROOT / "tools" / "gold" / "heldout.json"


def write_heldout(doc: dict, path: Path = HELDOUT) -> None:
    """Record the sealed repositories as their own held-out set, `held_out_ghsa_r1`."""
    held = json.loads(path.read_text(encoding="utf-8"))
    held["held_out_ghsa_r1"] = {
        "frozen": doc["selected_on"], "repos": doc["repositories"]["sealed"],
        "pairs_file": "tools/ground_truth/ghsa_pairs.json", "split_key": "split == sealed",
        "fetch": "GHSA=only tools/ground_truth/fetch_gt.sh", "requirement": "ARB-121",
        "policy": "Same as `policy`: rule authors must not open findings, outcomes, labels or code of these "
                  "repositories' pairs while changing a rule; only aggregate scores are reported."}
    path.write_text(json.dumps(held, indent=2) + "\n", encoding="utf-8")


def select(args) -> int:
    packs = {l: (PACKS / f"{l}.yaml").read_text(encoding="utf-8") for l in LANGUAGES}
    scope = scope_cwes(packs)
    sealed, dev_repos = sealed_and_dev_repos()
    cache = Cache(args.cache)
    pairs, audit, frames = [], {}, {}
    try:
        for lang in args.language or LANGUAGES:
            advs = frame(lang, scope[lang], args.cache)
            frames[lang] = len(advs)
            got, rows = walk(lang, advs, cache.commit, cache.repo, sealed, scope[lang], args.target)
            cache.save()
            pairs += got
            audit[lang] = rows
            print(f"  {lang}: frame {len(advs)}, examined {len(rows)}, selected {len(got)}, "
                  f"{dict(Counter(r[1] for r in rows))}", file=sys.stderr, flush=True)
    except RateLimited as exc:
        cache.save()
        print(f"rate limited, cache saved under {args.cache}: {exc}", file=sys.stderr)
        return 2
    cache.save()
    assignment = split(pairs, dev_repos)
    for p in pairs:
        p["split"] = assignment[p["repo"].lower()]
    counts = defaultdict(Counter)
    for p in pairs:
        counts[p["language"]][p["split"]] += 1
    doc = {"schema_version": 1, "requirement": "ARB-121",
           "source": "GitHub Advisory Database, reviewed advisories (CC-BY-4.0), via the REST /advisories API",
           "selected_on": time.strftime("%Y-%m-%d"),
           "criteria": criteria(scope),
           "frame_sizes": frames,
           "counts": {l: dict(counts[l]) for l in sorted(counts)},
           "repositories": {"sealed": sorted(r for r, s in assignment.items() if s == "sealed"),
                            "development": sorted(r for r, s in assignment.items() if s == "development")},
           "pairs": sorted(pairs, key=lambda p: (p["language"], p["order_key"]))}
    args.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    write_heldout(doc)
    args.audit.write_text(json.dumps({"requirement": "ARB-121", "examined": audit,
                                      "excluded_sealed_repositories": dict(sorted(sealed.items()))},
                                     indent=0) + "\n", encoding="utf-8")
    print(f"{len(pairs)} pairs -> {args.out}: {doc['counts']}")
    return 0


def check(args) -> int:
    """The committed split and exclusions hold: recomputed from the pairs file."""
    doc = json.loads(args.pairs.read_text(encoding="utf-8"))
    sealed, dev_repos = sealed_and_dev_repos()
    pairs = doc["pairs"]
    problems = []
    assignment = split(pairs, dev_repos, doc["criteria"]["seed"], doc["criteria"]["sealed_fraction"])
    for p in pairs:
        if p["split"] != assignment[p["repo"].lower()]:
            problems.append(f"{p['ghsa']}: split {p['split']} != {assignment[p['repo'].lower()]}")
        if p["repo"].lower() in sealed:
            problems.append(f"{p['ghsa']}: repository {p['repo']} is already sealed ({sealed[p['repo'].lower()]})")
    both = set(doc["repositories"]["sealed"]) & set(doc["repositories"]["development"])
    problems += [f"{r} in both splits" for r in sorted(both)]
    held = json.loads(HELDOUT.read_text(encoding="utf-8")).get("held_out_ghsa_r1", {})
    if held.get("repos") != doc["repositories"]["sealed"]:
        problems.append("tools/gold/heldout.json held_out_ghsa_r1 differs from the sealed repositories")
    per = Counter((p["language"], p["repo"].lower()) for p in pairs)
    problems += [f"{k} exceeds the repository cap" for k, n in per.items() if n > doc["criteria"]["repo_cap_per_language"]]
    print("\n".join(problems) or f"{len(pairs)} pairs: split, exclusions and cap hold")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["select", "check"])
    ap.add_argument("--out", type=Path, default=HERE / "ghsa_pairs.json")
    ap.add_argument("--audit", type=Path, default=HERE / "ghsa_selection_audit.json")
    ap.add_argument("--pairs", type=Path, default=HERE / "ghsa_pairs.json")
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--language", action="append", default=[])
    ap.add_argument("--target", type=int, default=TARGET)
    args = ap.parse_args(argv)
    return select(args) if args.cmd == "select" else check(args)


if __name__ == "__main__":
    raise SystemExit(main())
