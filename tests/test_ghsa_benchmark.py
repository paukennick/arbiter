"""GHSA fix-pair benchmark (ARB-121): selection, split and scoring on synthetic
inputs. No network, no scan."""
from __future__ import annotations

import importlib.util
import json
import sys

import pytest
from helpers import ROOT

GT = ROOT / "tools" / "ground_truth"
sys.path.insert(0, str(GT))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, GT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sel = _load("ghsa_select")
gp = _load("ghsa_pairs")

PY_SCOPE = ["CWE-78", "CWE-89", "CWE-95", "CWE-200", "CWE-918"]
SHA = "a" * 40


def _adv(gid, cwes=("CWE-89",), refs=None, published="2025-01-01T00:00:00Z", withdrawn=None, repo="o/r"):
    return {"ghsa_id": gid, "cve_id": None, "published_at": published, "withdrawn_at": withdrawn,
            "summary": "s", "cwes": [{"cwe_id": c} for c in cwes],
            "references": refs if refs is not None else [f"https://github.com/{repo}/commit/{SHA}"],
            "vulnerabilities": [{"package": {"name": "pkg"}}]}


def _commit(files=(("app/db.py", "modified", 3, 1),), parents=1):
    return {"parents": [{"sha": "b" * 40}] * parents,
            "files": [{"filename": f, "status": s, "additions": a, "deletions": d} for f, s, a, d in files]}


# --- selection --------------------------------------------------------------

def test_scope_comes_from_security_rules_only():
    pack = ("rules:\n  - {id: a, dimension: security, cwe: [CWE-89, CWE-200]}\n"
            "  - {id: b, dimension: quality, cwe: [CWE-400]}\n")
    assert sel.scope_cwes({"python": pack}) == {"python": ["CWE-89", "CWE-200"]}


def test_in_scope_uses_the_scorers_aliases():
    assert sel.in_scope(["CWE-94"], PY_SCOPE) == ["CWE-94"]          # CWE-94 -> CWE-95
    assert sel.in_scope(["CWE-22", "CWE-79"], PY_SCOPE) == []
    assert sel.in_scope(["CWE-77", "CWE-400"], PY_SCOPE) == ["CWE-77"]
    q = sel.query_cwes(PY_SCOPE)
    assert "CWE-94" in q and "CWE-77" in q and "CWE-22" not in q


def test_commit_refs_accept_commit_and_pull_commit_urls_only():
    refs = sel.commit_refs([f"https://github.com/o/r/commit/{SHA}.patch",
                            f"https://github.com/o/r/pull/7/commits/{SHA}#diff-1",
                            "https://github.com/o/r/pull/7", f"https://gitlab.com/o/r/commit/{SHA}"])
    assert refs == [("o", "r", SHA)]


@pytest.mark.parametrize("commit,reason", [
    (_commit(parents=2), "not-one-parent"),
    (_commit(files=(("tests/test_db.py", "modified", 3, 1), ("README.md", "modified", 1, 1))), "no-source-file"),
    (_commit(files=(("app/new.py", "added", 30, 0),)), "no-source-file"),
    (_commit(files=tuple((f"app/m{i}.py", "modified", 1, 1) for i in range(9))), "too-many-files"),
    (_commit(files=(("app/db.py", "modified", 300, 101),)), "too-many-lines"),
])
def test_qualify_rejects(commit, reason):
    assert sel.qualify(commit, "python") == (None, reason)


def test_qualify_keeps_source_files():
    files, why = sel.qualify(_commit(files=(("app/db.py", "modified", 3, 1), ("app/db_test.go", "modified", 1, 1))),
                             "python")
    assert why == "" and [f["filename"] for f in files] == ["app/db.py"]


def _walk(advs, sealed=None, target=100, commit=None):
    repo = lambda full: {"full_name": full, "license": "MIT"}  # noqa: E731
    return sel.walk("python", advs, lambda full, sha: commit or _commit(), repo, sealed or {}, PY_SCOPE,
                    target=target)


def test_walk_order_is_seeded_not_api_order():
    advs = [_adv(f"GHSA-{i:04d}", repo=f"o/r{i}") for i in range(20)]
    a, _ = _walk(advs, target=5)
    b, _ = _walk(list(reversed(advs)), target=5)
    assert [p["ghsa"] for p in a] == [p["ghsa"] for p in b]
    assert [p["ghsa"] for p in a] == sorted((x["ghsa_id"] for x in advs), key=sel.order_key)[:5]


def test_walk_exclusions_cap_and_reasons():
    advs = ([_adv(f"GHSA-cap{i}") for i in range(5)]
            + [_adv("GHSA-sealed", repo="s/sealed"), _adv("GHSA-scope", cwes=("CWE-79",)),
               _adv("GHSA-wd", withdrawn="2025-02-01"), _adv("GHSA-late", published="2026-11-01T00:00:00Z"),
               _adv("GHSA-noref", refs=["https://example.com/x"])])
    pairs, audit = _walk(advs, sealed={"s/sealed": "test"})
    assert len(pairs) == 3 and {p["repo"] for p in pairs} == {"o/r"}
    reasons = dict(audit)
    assert reasons["GHSA-sealed"] == "repo-already-sealed"
    assert reasons["GHSA-scope"] == "out-of-scope-cwe"
    assert reasons["GHSA-wd"] == "withdrawn" and reasons["GHSA-late"] == "after-cutoff"
    assert reasons["GHSA-noref"] == "no-commit-reference"
    assert sorted(r for g, r in audit if g.startswith("GHSA-cap")).count("repo-cap") == 2
    p = pairs[0]
    assert p["vuln_sha"] == "b" * 40 and p["fix_sha"] == SHA and p["files"] == ["app/db.py"]
    assert set(p) >= {"ghsa", "repo", "fix_sha", "vuln_sha", "files", "cwes", "in_scope_cwes", "repo_license"}


def test_split_is_by_repository_deterministic_and_keeps_dev_repos():
    pairs = [{"repo": f"Owner/R{i}"} for i in range(200)] + [{"repo": "owner/r1"}]
    a = sel.split(pairs, {"owner/r0"})
    assert a == sel.split(list(reversed(pairs)), {"owner/r0"})
    assert a["owner/r0"] == "development" and len(a) == 200     # one decision per repository
    sealed = sum(v == "sealed" for v in a.values())
    assert 70 < sealed < 130


def test_committed_exclusions_cover_every_sealed_set():
    sealed, dev = sel.sealed_and_dev_repos()
    cve = json.loads((GT / "cve_pairs.json").read_text(encoding="utf-8"))
    assert {p["repo"].lower() for p in cve["pairs"]} <= set(sealed)
    r5 = json.loads((ROOT / "tools" / "gold" / "heldout-r5-repos.json").read_text(encoding="utf-8"))
    assert {m["github"].lower() for m in r5["repos"].values()} <= set(sealed)
    assert not dev & set(sealed)


def test_frozen_selection_holds():
    path = GT / "ghsa_pairs.json"
    if not path.exists():
        pytest.skip("no frozen selection yet")
    assert sel.main(["check", "--pairs", str(path)]) == 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    for p in doc["pairs"]:
        assert set(p) <= {"ghsa", "cve", "language", "ecosystem", "package", "cwes", "in_scope_cwes", "published",
                          "summary", "repo", "repo_license", "fix_sha", "vuln_sha", "files", "changed_lines",
                          "order_key", "split"}
    held = json.loads((ROOT / "tools" / "gold" / "heldout.json").read_text(encoding="utf-8"))
    assert held["held_out_ghsa_r1"]["repos"] == doc["repositories"]["sealed"]


# --- scoring ----------------------------------------------------------------

OLD = [f"line{i}" for i in range(1, 31)]


def _texts(new):
    return {"a.py": (OLD, new)}


def _f(line, cwe=("CWE-89",), rule="arbiter/python.sql", path="a.py"):
    return {"rule": rule, "path": path, "line": line, "cwe": list(cwe)}


PAIR = {"in_scope_cwes": ["CWE-89"]}


def test_primary_region_is_three_lines_around_a_changed_hunk():
    new = OLD[:9] + ["fixed10"] + OLD[10:]               # old line 10 changed
    for line, hit in ((7, True), (13, True), (14, False), (6, False)):
        r = gp.score_pair(PAIR, [_f(line)], [], _texts(new))
        assert r["detected"]["hunk"] is hit, line
        assert r["detected"]["file"] is True


def test_add_only_fix_counts_at_its_insertion_point():
    new = OLD[:20] + ["if bad: raise"] + OLD[20:]        # inserted between old 20 and 21
    assert gp.score_pair(PAIR, [_f(23)], [], _texts(new))["detected"]["hunk"]
    assert gp.score_pair(PAIR, [_f(18)], [], _texts(new))["detected"]["hunk"]
    assert not gp.score_pair(PAIR, [_f(24)], [], _texts(new))["detected"]["hunk"]


def test_function_level_and_cwe_and_project_rule_filters():
    new = OLD[:9] + ["fixed10"] + OLD[10:]
    spans = lambda path, text, line: (5, 25) if 5 <= line <= 25 else None  # noqa: E731
    r = gp.score_pair(PAIR, [_f(20)], [], _texts(new), spans=spans)
    assert r["detected"] == {"hunk": False, "function": True, "file": True}
    r = gp.score_pair(PAIR, [_f(28)], [], _texts(new), spans=spans)
    assert r["detected"] == {"hunk": False, "function": False, "file": True}
    assert not any(gp.score_pair(PAIR, [_f(10, cwe=("CWE-79",))], [], _texts(new))["detected"].values())
    assert not any(gp.score_pair(PAIR, [_f(10, rule="arbiter/ast.high-complexity")], [], _texts(new))
                   ["detected"].values())
    assert gp.score_pair(PAIR, [_f(10, cwe=("CWE-564",))], [], _texts(new))["detected"]["hunk"]  # alias


def test_fixed_side_persistence():
    new = OLD[:9] + ["fixed10"] + OLD[10:]
    gone = gp.score_pair(PAIR, [_f(10)], [], _texts(new))
    assert gone["persists"] is False and gone["primary_findings"] == 1
    still = gp.score_pair(PAIR, [_f(10)], [_f(11)], _texts(new))
    assert still["persists"] is True and still["primary_persisting"] == 1
    moved_new = OLD[:8] + ["fixed9", "fixed10"] + OLD[10:24] + ["line9"] + OLD[24:]
    moved = gp.score_pair(PAIR, [_f(9)], [_f(25)], _texts(moved_new))
    assert moved["persists"] is True       # far from the hunk, but the same line text
    assert gp.score_pair(PAIR, [_f(9)], [_f(26)], _texts(moved_new))["persists"] is False
    other_rule = gp.score_pair(PAIR, [_f(10)], [_f(10, rule="arbiter/python.other")], _texts(new))
    assert other_rule["persists"] is False


def test_wilson_known_values():
    lo, hi = gp.wilson(0, 10)
    assert lo == 0 and abs(hi - 0.2775) < 1e-3
    lo, _ = gp.wilson(381, 381)
    assert abs(lo - 0.9900) < 5e-4
    assert gp.wilson(0, 0) == (None, None)


def test_cluster_bootstrap_counts_clusters_not_pairs():
    iid = [(f"r{i}", i % 2, 1) for i in range(100)]
    clustered = [(f"r{i // 10}", (i // 10) % 2, 1) for i in range(100)]
    a, b = gp.cluster_bootstrap(iid, seed="t"), gp.cluster_bootstrap(clustered, seed="t")
    assert a == gp.cluster_bootstrap(iid, seed="t")
    assert a["clusters"] == 100 and b["clusters"] == 10
    assert (b["upper"] - b["lower"]) > (a["upper"] - a["lower"])
    assert b["effective_n"] < 25 < a["effective_n"]
    zero = gp.cluster_bootstrap([("r", 0, 1)] * 3, seed="z")
    assert zero["lower"] == zero["upper"] == 0.0
    assert gp.cluster_bootstrap([], seed="e")["lower"] is None


def test_sealed_summary_is_aggregate_only():
    pairs = [{"key": f"k{i}", "language": "python", "repo": f"r{i % 3}"} for i in range(6)]
    out = {f"k{i}": {"detected": {"hunk": i < 2, "function": i < 3, "file": i < 4},
                     "per_cwe": {"CWE-89": {"hunk": i < 2, "function": i < 3, "file": i < 4}},
                     "persists": i == 0, "primary_findings": int(i < 2), "primary_persisting": int(i == 0)}
           for i in range(6)}
    s = gp.summarise(pairs, out, "sealed", per_cwe=False)
    assert "cwes" not in s["languages"]["python"]
    assert s["overall"]["recall_hunk"]["k"] == 2 and s["overall"]["recall_hunk"]["n"] == 6
    assert s["overall"]["fixed_side_persistence"]["k"] == 1 and s["overall"]["fixed_side_persistence"]["n"] == 2
    assert "k0" not in json.dumps(s)
    d = gp.summarise(pairs, out, "development", per_cwe=True)
    assert d["languages"]["python"]["cwes"]["CWE-89"]["recall_file"]["k"] == 4


def test_benchmark_manifest_matches_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    doc = json.loads((ROOT / "docs" / "accuracy-benchmark-manifest.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "docs" / "accuracy-benchmark-manifest.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(doc, schema)
    ids = [b["id"] for b in doc["benchmark_inventory"]]
    assert len(ids) == len(set(ids))
