"""Golden-fixture and unit tests.

The golden-fixture tests are the ones that matter: adapter upgrades and rule
edits change results, and a synthetic repo with known planted defects is the
only way to notice.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arbiter.ab import Arm, compare, load_ground_truth, run_ab, score_ground_truth
from arbiter.core import Finding, Location, Report
from arbiter.engine import run_scan
from arbiter.graph import build_graph, parse_terraform
from arbiter.inventory import build_inventory, detect_stacks
from arbiter.policy import apply_suppressions, load_config
from arbiter.probes import _entropy, _mask
from arbiter.report import render_html, render_markdown, write_sarif

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "fixtures" / "legacy-platform"
SYSTEM = ROOT / "fixtures" / "system" / "arbiter-system.yaml"


@pytest.fixture(scope="module")
def legacy_report():
    cfg = load_config(None, str(LEGACY))
    return run_scan([str(LEGACY)], cfg, skip=["checkov", "semgrep", "bandit", "ruff", "gitleaks"])


@pytest.fixture(scope="module")
def system_report():
    cfg = load_config(None)
    return run_scan([], cfg, system_path=str(SYSTEM),
                    skip=["checkov", "semgrep", "bandit", "ruff", "gitleaks"])


# --------------------------------------------------------------------------
# fingerprints
# --------------------------------------------------------------------------

def test_fingerprint_ignores_line_number():
    a = Finding(rule_id="r", title="t", evidence="x=1", location=Location(path="a.py", start_line=10))
    b = Finding(rule_id="r", title="t", evidence="x=1", location=Location(path="a.py", start_line=400))
    assert a.id == b.id, "a reformat must not invalidate the baseline"


def test_fingerprint_tracks_evidence():
    a = Finding(rule_id="r", title="t", evidence="port=8080", location=Location(path="a.tf"))
    b = Finding(rule_id="r", title="t", evidence="port=8443", location=Location(path="a.tf"))
    assert a.id != b.id, "a changed value is a different finding"


def test_fingerprint_is_repo_scoped():
    a = Finding(rule_id="r", title="t", repo_id="infra", location=Location(path="x.py"))
    b = Finding(rule_id="r", title="t", repo_id="app", location=Location(path="x.py"))
    assert a.id != b.id


def test_secret_values_are_masked():
    assert _mask("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"
    assert "hunter2" not in _mask("hunter2-secret-value")


def test_entropy_ranks_random_above_words():
    assert _entropy("Zx91qKp4vWmTn83LcRd7") > _entropy("passwordpassword")


# --------------------------------------------------------------------------
# inventory & graph
# --------------------------------------------------------------------------

def test_dot_github_is_not_skipped(legacy_report):
    paths = [f.location.path for f in legacy_report.findings]
    assert any(p.startswith(".github/") for p in paths), "CI config must be inventoried"


def test_terraform_parses_nested_blocks():
    resources = parse_terraform(LEGACY / "infra" / "main.tf", "infra/main.tf", "root")
    by_addr = {r.address: r for r in resources}
    assert "aws_s3_bucket.artifacts" in by_addr
    assert by_addr["aws_s3_bucket.artifacts"].kind == "object_store"
    audit = by_addr["aws_s3_bucket.audit_archive"]
    assert audit.get("server_side_encryption_configuration") is not None
    sg = by_addr["aws_security_group.web"]
    assert sg.get("ingress.cidr_blocks") == ["0.0.0.0/0"]


def test_egress_to_anywhere_is_not_flagged(legacy_report):
    """The fixture has an open egress rule. Flagging it would be a false positive."""
    ingress = [f for f in legacy_report.findings if f.rule_id.endswith("unrestricted-ingress")]
    assert len(ingress) == 1


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------

def test_known_defects_are_all_found(legacy_report):
    truth = load_ground_truth(str(LEGACY))
    assert truth is not None
    result = score_ground_truth(truth, legacy_report.active())
    assert result.missed == [], f"regressed on planted defects: {result.missed}"
    assert result.recall == 1.0


def test_underscored_credential_names_are_caught(legacy_report):
    hits = [f for f in legacy_report.findings if "DB_PASSWORD" in f.evidence]
    assert hits, "DB_PASSWORD must match even though it is not a bare `password`"


def test_encrypted_bucket_is_not_flagged(legacy_report):
    bad = [
        f for f in legacy_report.findings
        if f.location.logical == "aws_s3_bucket.audit_archive"
        and "encryption" in f.rule_id
    ]
    assert not bad, "the correctly configured bucket must stay clean"


def test_interface_findings_need_two_repos(legacy_report, system_report):
    assert not [f for f in legacy_report.findings if f.dimension == "interface"]
    seams = [f for f in system_report.findings if f.dimension == "interface"]
    assert len(seams) >= 2


def test_all_six_seam_checks_fire(system_report):
    rules = {f.rule_id.split(".")[-1] for f in system_report.findings if f.dimension == "interface"}
    assert {
        "constant-disagreement",
        "env-var-never-provided",
        "env-var-provided-but-unused",
        "permission-not-granted",
        "permission-unused",
        "port-not-exposed",
    } <= rules


def test_seam_findings_are_severity_ordered(system_report):
    """A missing grant breaks the app; an unused grant is hygiene."""
    by_rule = {f.rule_id.split(".")[-1]: f for f in system_report.findings}
    assert by_rule["permission-not-granted"].severity == "high"
    assert by_rule["permission-unused"].severity == "low"


def test_constant_disagreement_cites_both_repos(system_report):
    f = next(f for f in system_report.findings if "constant-disagreement" in f.rule_id)
    repos = {f.location.repo_id} | {r.repo_id for r in f.related}
    assert repos == {"infra", "app"}
    assert "512" in f.description and "1024" in f.description


# --------------------------------------------------------------------------
# coverage honesty
# --------------------------------------------------------------------------

def test_skipped_probes_are_recorded_with_a_reason(legacy_report):
    skipped = [p for p in legacy_report.probes if p.status == "skipped"]
    assert skipped
    assert all(p.reason for p in skipped), "every skip must say why"


def test_grade_is_withheld_when_coverage_is_thin(legacy_report):
    assert legacy_report.scorecard.coverage < 0.6
    assert legacy_report.scorecard.withheld
    assert legacy_report.scorecard.overall is None


def test_coverage_counts_only_probes_that_ran(legacy_report):
    for dim in legacy_report.scorecard.dimensions.values():
        assert dim.checks_run <= dim.checks_applicable


# --------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------

def test_expired_suppressions_stop_suppressing():
    f = Finding(rule_id="arbiter/x", title="t", location=Location(path="a.py"))
    cfg = {"suppress": [{"rule": "arbiter/x", "reason": "r", "expires": "2000-01-01"}]}
    apply_suppressions([f], cfg)
    assert not f.suppressed


def test_live_suppressions_apply():
    f = Finding(rule_id="arbiter/x", title="t", location=Location(path="a.py"))
    cfg = {"suppress": [{"rule": "arbiter/*", "reason": "accepted", "expires": "2099-01-01"}]}
    apply_suppressions([f], cfg)
    assert f.suppressed and f.suppression_reason == "accepted"


def test_gate_fails_on_critical(legacy_report):
    assert legacy_report.gate["passed"] is False
    assert any("critical" in r for r in legacy_report.gate["reasons"])


def test_inferred_findings_do_not_gate_by_default():
    from arbiter.policy import evaluate_gate
    rep = Report()
    rep.findings = [Finding(rule_id="m/x", title="t", severity="critical", provenance="inferred")]
    gate = evaluate_gate(rep, {"gate": {"fail_on": {"severity": "critical"}}})
    assert gate["passed"] is True


# --------------------------------------------------------------------------
# reporters
# --------------------------------------------------------------------------

def test_sarif_is_wellformed(legacy_report, tmp_path):
    p = tmp_path / "r.sarif"
    write_sarif(legacy_report, str(p))
    doc = json.loads(p.read_text())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note", "none")
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert res["fingerprints"]["arbiter/v1"].startswith("f:")


def test_round_trip_through_json(legacy_report):
    again = Report.from_dict(json.loads(json.dumps(legacy_report.to_dict())))
    assert len(again.findings) == len(legacy_report.findings)
    assert {f.id for f in again.findings} == {f.id for f in legacy_report.findings}
    assert again.scorecard.coverage == legacy_report.scorecard.coverage


def test_html_and_markdown_render(legacy_report):
    html = render_html(legacy_report)
    assert "Arbiter" in html and "not a pass" in html
    md = render_markdown(legacy_report)
    assert md.startswith("# Arbiter report")


# --------------------------------------------------------------------------
# A/B harness
# --------------------------------------------------------------------------

def test_compare_matches_identical_runs(legacy_report):
    matches, only_a, only_b = compare(legacy_report.active(), legacy_report.active())
    assert not only_a and not only_b
    assert all(m.how == "fingerprint" for m in matches)


def test_compare_reports_how_it_matched():
    a = [Finding(rule_id="x/a", title="Bucket is public", location=Location(path="m.tf", start_line=10))]
    b = [Finding(rule_id="y/b", title="Public bucket detected", location=Location(path="m.tf", start_line=11))]
    matches, only_a, only_b = compare(a, b)
    assert len(matches) == 1 and matches[0].how == "location"
    assert not only_a and not only_b


def test_compare_does_not_match_across_files():
    a = [Finding(rule_id="x/a", title="Same title", location=Location(path="one.tf", start_line=3))]
    b = [Finding(rule_id="y/b", title="Same title", location=Location(path="two.tf", start_line=3))]
    matches, only_a, only_b = compare(a, b)
    assert not matches and len(only_a) == 1 and len(only_b) == 1


def test_ab_two_configs_of_arbiter():
    cfg = load_config(None, str(LEGACY))
    res = run_ab(
        "unit", [str(LEGACY)],
        Arm(name="a", only=["secrets"]),
        Arm(name="b", only=["secrets", "quality"]),
        cfg,
    )
    assert not res.a.error and not res.b.error
    assert len(res.b.findings) > len(res.a.findings)
    assert not res.only_a, "the narrower arm must be a subset of the wider one"
    assert res.only_b


def test_precision_is_withheld_unless_fixture_is_exhaustive():
    truth = load_ground_truth(str(LEGACY))
    res = score_ground_truth(truth, [])
    assert res.exhaustive is False
    assert res.precision is None, "precision is meaningless against a partial ground truth"


# --------------------------------------------------------------------------
# P1/P2 additions
# --------------------------------------------------------------------------

def test_sibling_resources_fold_into_the_parent(tmp_path):
    """The loudest known false positive: modern Terraform configures a bucket
    through separate resources, and a naive scan calls it unencrypted."""
    (tmp_path / "main.tf").write_text("""
resource "aws_s3_bucket" "data" { bucket = "d" }
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket            = aws_s3_bucket.data.id
  block_public_acls = true
}
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
""")
    rep = run_scan([str(tmp_path)], load_config(None), only=["resource_policy"])
    ids = {f.rule_id for f in rep.active()}
    assert "arbiter/resource.unencrypted-object-store" not in ids, "encryption sibling not folded in"
    assert "arbiter/resource.public-object-store" not in ids, "public access block should compensate"


def test_bucket_without_siblings_is_still_flagged(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "x" { bucket = "x"\n  acl = "public-read"\n}\n'
    )
    rep = run_scan([str(tmp_path)], load_config(None), only=["resource_policy"])
    ids = {f.rule_id for f in rep.active()}
    assert "arbiter/resource.public-object-store" in ids


def test_ast_metrics_measure_real_boundaries(tmp_path):
    from arbiter import ast as ts
    if not ts.available():
        pytest.skip("tree-sitter not installed")
    src = tmp_path / "deep.py"
    body = "\n".join("    " * (i + 1) + f"if x{i}:" for i in range(8))
    src.write_text(f"def deep(x0,x1,x2,x3,x4,x5,x6,x7):\n{body}\n" + "    " * 9 + "return 1\n")
    fns = ts.functions(str(src), "python")
    assert len(fns) == 1
    assert fns[0].name == "deep"
    assert fns[0].max_depth == 8
    assert fns[0].complexity == 9


def test_ast_query_house_rule(tmp_path):
    from arbiter import ast as ts
    if not ts.available():
        pytest.skip("tree-sitter not installed")
    (tmp_path / "a.py").write_text("try:\n    f()\nexcept Exception:\n    pass\n")
    cfg = dict(load_config(None))
    cfg["rules"] = [{
        "id": "no-bare-except", "type": "ast_query", "languages": ["python"],
        "query": "(except_clause) @hit", "severity": "low",
    }]
    rep = run_scan([str(tmp_path)], cfg, only=["house_rules_ast"])
    assert [f for f in rep.active() if f.rule_id == "house/no-bare-except"]


def test_diff_survives_a_line_shift(tmp_path):
    from arbiter.diff import diff_reports
    before_dir = tmp_path / "before"
    before_dir.mkdir()
    (before_dir / "c.py").write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    cfg = load_config(None)
    before = run_scan([str(before_dir)], cfg, only=["secrets"])

    after_dir = tmp_path / "after"
    after_dir.mkdir()
    (after_dir / "c.py").write_text('\n\n\nAWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    after = run_scan([str(after_dir)], cfg, only=["secrets"])

    d = diff_reports(before, after)
    assert not d.new and not d.fixed, "a pure line shift must not churn the baseline"
    assert d.persisting


def test_diff_detects_real_change(tmp_path):
    from arbiter.diff import diff_reports
    a = tmp_path / "a"; a.mkdir(); (a / "c.py").write_text("X = 1\n")
    b = tmp_path / "b"; b.mkdir()
    (b / "c.py").write_text('X = 1\nGH_TOKEN = "ghp_' + "a" * 36 + '"\n')
    cfg = load_config(None)
    d = diff_reports(run_scan([str(a)], cfg, only=["secrets"]),
                     run_scan([str(b)], cfg, only=["secrets"]))
    assert len(d.new) >= 1
    assert d.worst_new() in ("critical", "high")


def test_pr_comment_names_what_was_not_assessed(legacy_report):
    from arbiter.diff import render_pr_comment
    text = render_pr_comment(legacy_report)
    assert "Arbiter" in text
    assert "Not assessed" in text


# --------------------------------------------------------------------------
# Tuning regressions.
#
# Every test below encodes a false positive that a public repository actually
# produced. They exist so a future rule edit cannot quietly reintroduce it.
# --------------------------------------------------------------------------

def _scan_text(tmp_path, name: str, content: str, only: list[str], cfg_extra: dict | None = None):
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(content)
    cfg = dict(load_config(None))
    cfg.update(cfg_extra or {})
    return run_scan([str(tmp_path)], cfg, only=only).active()


def test_test_fixture_keys_are_downgraded_not_hidden(tmp_path):
    """psf/requests ships four private keys under tests/certs. They are real
    keys and deliberate; reporting them as critical was wrong."""
    key = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n"
    found = _scan_text(tmp_path, "tests/certs/server.key", key, ["secrets"])
    assert len(found) == 1
    assert found[0].severity == "medium" and found[0].confidence == "low"
    assert "test fixture" in found[0].title


def test_production_key_stays_critical(tmp_path):
    key = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n"
    found = _scan_text(tmp_path, "deploy/server.key", key, ["secrets"])
    assert found and found[0].severity == "critical"


def test_passphrase_examples_are_not_credentials(tmp_path):
    """expressjs/express: `secret: 'keyboard cat'` in its own examples."""
    found = _scan_text(tmp_path, "app.js", "app.use(session({ secret: 'keyboard cat' }))\n", ["secrets"])
    assert not found, "a value containing spaces is a passphrase example, not a secret"


def test_github_expressions_are_not_credentials(tmp_path):
    """hashicorp/terraform-provider-random: `token: ${{ secrets.GITHUB_TOKEN }}`."""
    found = _scan_text(tmp_path, ".github/workflows/x.yml",
                       "jobs:\n  a:\n    steps:\n      - with:\n          token: ${{ secrets.GITHUB_TOKEN }}\n",
                       ["secrets"])
    assert not found


def test_real_high_entropy_credential_still_found(tmp_path):
    found = _scan_text(tmp_path, "cfg.py", 'API_KEY = "Zx91qKp4vWmTn83LcRd7Qa2B"\n', ["secrets"])
    assert found and found[0].severity == "high"


def test_relative_parent_links_resolve(tmp_path):
    """terraform-aws-modules: `[examples](../examples)` from .github/ was
    reported broken because '../' was being mangled into '.'."""
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "main.tf").write_text("# x\n")
    found = _scan_text(tmp_path, ".github/contributing.md",
                       "See [the examples](../examples) for usage.\n", ["doc_drift"])
    assert not [f for f in found if "broken-doc-link" in f.rule_id]


def test_rendered_site_links_are_not_checked(tmp_path):
    """terraform-provider-random docs link to ../index.html, which only exists
    on the published website. 36 findings came from this one pattern."""
    found = _scan_text(tmp_path, "docs/resources/id.md",
                       "Back to [the index](../index.html).\n", ["doc_drift"])
    assert not [f for f in found if "broken-doc-link" in f.rule_id]


def test_genuinely_broken_link_still_found(tmp_path):
    found = _scan_text(tmp_path, "README.md", "See [design](design.md).\n", ["doc_drift"])
    assert [f for f in found if "broken-doc-link" in f.rule_id]


def test_env_vars_only_checked_inside_a_config_section(tmp_path):
    """`BEGIN_TF_DOCS` in a template marker and `DEBUG_FD` in a changelog were
    both reported as undocumented environment variables."""
    (tmp_path / "app.py").write_text("import os\n")
    found = _scan_text(tmp_path, "README.md",
                       "# Usage\n\nRun it with BEGIN_TF_DOCS markers in place.\n", ["doc_drift"])
    assert not [f for f in found if "documented-env-var" in f.rule_id]


def test_env_var_in_a_config_section_is_checked(tmp_path):
    (tmp_path / "app.py").write_text("import os\nx = os.environ['KNOWN_VAR']\n")
    found = _scan_text(tmp_path, "README.md",
                       "## Environment variables\n\n- `KNOWN_VAR` — used\n- `GHOST_VAR` — not used\n",
                       ["doc_drift"])
    hits = [f for f in found if "documented-env-var" in f.rule_id]
    assert len(hits) == 1 and "GHOST_VAR" in hits[0].evidence


def test_safe_pull_request_target_is_informational(tmp_path):
    """All three terraform-aws-modules repos use this trigger safely for
    PR-title linting. Flagging it high was a false positive; flagging it "low"
    still deducted score for something that appears twelve times on
    well-maintained repositories and once on the deliberately vulnerable ones.
    It reports, at zero weight."""
    found = _scan_text(tmp_path, ".github/workflows/pr-title.yml",
                       "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  a:\n"
                       "    steps:\n      - uses: amannn/action-semantic-pull-request@v5\n",
                       ["supply_chain"])
    prt = [f for f in found if "pull-request-target" in f.rule_id]
    assert prt, "the safe form is still reported"
    assert prt[0].severity == "info"
    from arbiter.core import SEV_WEIGHT
    assert SEV_WEIGHT[prt[0].severity] == 0.0


def test_dangerous_pull_request_target_is_high(tmp_path):
    found = _scan_text(tmp_path, ".github/workflows/bad.yml",
                       "on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n"
                       "      - uses: actions/checkout@v4\n"
                       "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                       "      - run: npm install && npm test\n",
                       ["supply_chain"])
    prt = [f for f in found if "pull-request-target" in f.rule_id]
    assert prt and prt[0].severity == "high" and prt[0].confidence == "high"


def test_example_infrastructure_is_downgraded(tmp_path):
    found = _scan_text(tmp_path, "examples/basic/main.tf",
                       'resource "aws_db_instance" "x" { engine = "postgres" }\n',
                       ["resource_policy"])
    enc = [f for f in found if "unencrypted-database" in f.rule_id]
    assert enc and enc[0].severity == "medium" and "example code" in enc[0].title


def test_production_infrastructure_is_not_downgraded(tmp_path):
    found = _scan_text(tmp_path, "infra/main.tf",
                       'resource "aws_db_instance" "x" { engine = "postgres" }\n',
                       ["resource_policy"])
    enc = [f for f in found if "unencrypted-database" in f.rule_id]
    assert enc and enc[0].severity == "high"


def test_status_fields_are_not_credentials(tmp_path):
    """terraform-aws-modules: `access_key_status = "Inactive"` matched the
    keyword `access_key` but holds a status, not a key."""
    found = _scan_text(tmp_path, "examples/main.tf",
                       'resource "x" "y" { access_key_status = "Inactive" }\n', ["secrets"])
    assert not found


def test_self_referential_fixture_values_are_not_credentials(tmp_path):
    """pallets/flask: `secret_key = "secret_key"` in a test."""
    found = _scan_text(tmp_path, "tests/test_x.py", 'app.secret_key = "secret_key"\n', ["secrets"])
    assert not found


def test_weak_hardcoded_password_is_still_found(tmp_path):
    """Terragoat's Azure SQL password has low entropy precisely because it is
    weak. An entropy floor high enough to silence example passphrases also
    silenced this, which was the wrong trade."""
    found = _scan_text(tmp_path, "infra/sql.tf",
                       'resource "a" "b" { administrator_login_password = "Aa12issue5678" }\n',
                       ["secrets"])
    assert found, "a weak credential is still a credential"


# --------------------------------------------------------------------------
# Terraform plan JSON
# --------------------------------------------------------------------------

TFPLAN = ROOT / "fixtures" / "tfplan"


@pytest.fixture(scope="module")
def plan_report():
    return run_scan([str(TFPLAN)], load_config(None), only=["resource_policy"])


@pytest.fixture(scope="module")
def source_only_report(tmp_path_factory):
    """The same repository with the plan removed — the old behaviour."""
    import shutil
    dst = tmp_path_factory.mktemp("srconly") / "repo"
    shutil.copytree(TFPLAN, dst)
    (dst / "tfplan.json").unlink()
    return run_scan([str(dst)], load_config(None), only=["resource_policy"])


def test_plan_expands_for_each_into_instances(plan_report):
    from arbiter.graph import build_graph
    from arbiter.inventory import acquire_one, build_inventory
    info, _ = acquire_one(str(TFPLAN))
    graph = build_graph(build_inventory([info]))
    buckets = [r for r in graph if r.native == "aws_s3_bucket"]
    assert len(buckets) == 2, "for_each must yield one resource per instance"
    assert {b.index for b in buckets} == {"eu", "us"}
    assert all(b.source == "plan" for b in buckets)


def test_plan_finds_what_source_cannot(plan_report, source_only_report):
    """The ACL is a conditional expression, so a literal read cannot see that
    one of the two buckets is public. This is a false negative, not noise."""
    plan_ids = {f.rule_id for f in plan_report.active()}
    src_ids = {f.rule_id for f in source_only_report.active()}
    assert "arbiter/resource.public-object-store" in plan_ids
    assert "arbiter/resource.public-object-store" not in src_ids


def test_plan_avoids_a_false_positive_source_produces(plan_report, source_only_report):
    """`encrypted = var.encrypt_volumes` reads literally as a truthy string;
    the plan marks it unknown until apply."""
    src = [f for f in source_only_report.active()
           if f.rule_id == "arbiter/resource.unencrypted-volume"]
    planned = [f for f in plan_report.active()
               if f.rule_id == "arbiter/resource.unencrypted-volume"]
    assert src, "the literal reader asserts something it cannot know"
    assert not planned, "the plan must not assert an undetermined value"


def test_unknown_is_reported_as_not_assessed(plan_report):
    notes = [f for f in plan_report.active() if f.rule_id.endswith(".not-assessed")]
    assert notes, "an unevaluatable high-severity check must be surfaced"
    assert all(f.severity == "info" for f in notes)
    assert any("unknown" in f.evidence for f in notes)


def test_unknown_never_becomes_a_pass_or_a_finding():
    from arbiter.graph import Resource
    from arbiter.probes import SATISFIED, UNKNOWN, VIOLATED, _eval_assert
    rule = {"id": "x", "assert": "property_truthy", "any_of": ["encrypted"], "severity": "high"}
    assert _eval_assert(Resource("a", "block_store", "aws", "aws_ebs_volume",
                                 {"encrypted": True}), rule) == SATISFIED
    assert _eval_assert(Resource("a", "block_store", "aws", "aws_ebs_volume",
                                 {"encrypted": False}), rule) == VIOLATED
    assert _eval_assert(Resource("a", "block_store", "aws", "aws_ebs_volume",
                                 {}, unknown=["encrypted"]), rule) == UNKNOWN


def test_siblings_link_through_plan_configuration(plan_report):
    """In a real plan `bucket = aws_s3_bucket.data.id` has been resolved away,
    so the parent link comes from the configuration section's references."""
    enc = [f for f in plan_report.active()
           if f.rule_id == "arbiter/resource.unencrypted-object-store"]
    assert len(enc) == 1, "only the bucket without an encryption sibling should fire"
    assert "data[\"us\"]" in enc[0].location.logical


def test_destroyed_resources_are_ignored(plan_report):
    ingress = [f for f in plan_report.active() if "unrestricted-ingress" in f.rule_id]
    assert not ingress, "a security group the plan destroys is not a finding"


def test_plan_findings_cite_source_lines(plan_report):
    findings = [f for f in plan_report.active() if f.severity in ("critical", "high")]
    assert findings
    for f in findings:
        assert f.location.path.endswith(".tf"), "a plan finding must point at code"
        assert f.location.start_line > 0


def test_source_only_declares_its_own_weakness(source_only_report):
    note = [f for f in source_only_report.active()
            if f.rule_id == "arbiter/resource.source-is-literal-hcl"]
    assert note and note[0].severity == "info"


def test_base_address_strips_modules_and_indexes():
    from arbiter.graph import base_address, module_of
    assert base_address('module.storage.aws_s3_bucket.data["eu"]') == "aws_s3_bucket.data"
    assert base_address("aws_db_instance.primary") == "aws_db_instance.primary"
    assert base_address("module.a.module.b.aws_s3_bucket.x[0]") == "aws_s3_bucket.x"
    assert module_of('module.storage.aws_s3_bucket.data["eu"]') == "module.storage"
    assert module_of("aws_db_instance.primary") == ""


def test_explicit_plan_path_is_used(tmp_path):
    import shutil
    dst = tmp_path / "repo"
    shutil.copytree(TFPLAN, dst)
    plan = dst / "tfplan.json"
    moved = tmp_path / "elsewhere.json"
    shutil.move(str(plan), str(moved))
    rep = run_scan([str(dst)], load_config(None), only=["resource_policy"],
                   plan_paths=[str(moved)])
    assert "arbiter/resource.public-object-store" in {f.rule_id for f in rep.active()}


def test_a_bad_plan_path_fails_loudly(tmp_path):
    (tmp_path / "notaplan.json").write_text('{"hello": "world"}')
    with pytest.raises(Exception):
        run_scan([str(TFPLAN)], load_config(None), only=["resource_policy"],
                 plan_paths=[str(tmp_path / "notaplan.json")])


# --------------------------------------------------------------------------
# Claim integrity
#
# Verdict correctness on arbitrary code is undecidable. Claim integrity is a
# property of Arbiter's own execution, so it can be enumerated rather than
# sampled — these tests are a proof over a bounded space, not an estimate.
# --------------------------------------------------------------------------

def test_real_reports_pass_their_own_integrity_check(legacy_report, system_report, plan_report):
    for rep in (legacy_report, system_report, plan_report):
        assert rep.integrity["ok"], rep.integrity["violations"]


def test_every_invariant_is_enforced():
    """A declared invariant nobody can trip is decoration."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("integ", ROOT / "tools" / "integrity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tested, unenforced = mod.check_enforcement()
    assert tested >= 8
    assert unenforced == [], f"invariants declared but not enforced: {unenforced}"


def test_bounded_state_space_is_exhaustively_clean():
    import importlib.util
    spec = importlib.util.spec_from_file_location("integ", ROOT / "tools" / "integrity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    checked, failures = mod.enumerate_space(3, 2, (0.0, 0.6, 1.0))
    assert checked >= 2000
    assert failures == [], f"{len(failures)} reports asserted more than they verified"


def test_a_dimension_with_no_basis_cannot_claim_complete(legacy_report):
    """interface scores 100 because nothing ran. That must read as partial."""
    claims = {c["id"]: c for c in legacy_report.claims}
    interface = claims.get("dimension:interface")
    assert interface and interface["scope"] == "partial"
    assert interface["basis"] == []


def test_wilson_bound_refuses_to_flatter_small_samples():
    from arbiter.claims import wilson_lower_bound
    assert wilson_lower_bound(10, 10) < 0.80, "ten for ten is not six nines"
    assert wilson_lower_bound(0, 0) == 0.0
    assert wilson_lower_bound(999_999, 1_000_000) > 0.99999


def test_sample_size_maths_is_stated_not_assumed():
    from arbiter.claims import observations_needed
    assert observations_needed(1e-6) > 2_900_000
    assert observations_needed(1e-2) < 400


# --------------------------------------------------------------------------
# Learning
# --------------------------------------------------------------------------

def _knowledge_with(rule: str, tp: int, fp: int):
    from arbiter.learn import Knowledge, RuleStats
    k = Knowledge()
    k.rules[rule] = RuleStats(rule_id=rule, true_positives=tp, false_positives=fp)
    return k


def test_feedback_is_recorded_once_per_finding():
    from arbiter.learn import Knowledge, record
    k = Knowledge()
    f = Finding(rule_id="arbiter/x", title="t", location=Location(path="a.py"), evidence="e")
    assert record(k, f, "false_positive") is True
    assert record(k, f, "false_positive") is False, "one finding must not move the stats twice"
    assert k.rules["arbiter/x"].observations == 1


def test_calibration_waits_for_enough_observations():
    from arbiter.learn import MIN_OBSERVATIONS, calibrated_confidence
    thin = _knowledge_with("r", 5, 0).rules["r"]
    assert thin.proven is False
    assert calibrated_confidence(thin) is None, "five samples is not evidence"
    # Twenty for twenty clears the observation floor but only supports a lower
    # bound near 0.84 — "medium" is the honest label, not "high".
    thick = _knowledge_with("r", MIN_OBSERVATIONS, 0).rules["r"]
    assert thick.proven is True
    assert 0.80 < thick.precision_lower_bound < 0.90
    assert calibrated_confidence(thick) == "medium"

    # High confidence has to be earned with enough samples to support it.
    many = _knowledge_with("r", 60, 0).rules["r"]
    assert many.precision_lower_bound > 0.90
    assert calibrated_confidence(many) == "high"


def test_learning_adjusts_confidence_but_never_severity():
    from arbiter.learn import apply
    k = _knowledge_with("arbiter/x", 4, 36)          # measured precision 0.10
    f = Finding(rule_id="arbiter/x", title="t", severity="critical", confidence="high",
                location=Location(path="a.py"), evidence="e")
    apply([f], k)
    assert f.confidence == "low", "a rule wrong 90% of the time must not stay high confidence"
    assert f.severity == "critical", "how much it matters is policy, not statistics"
    assert any(t.startswith("precision:") for t in f.tags)


def test_knowledge_version_changes_when_learning_does():
    from arbiter.learn import Knowledge, record
    k = Knowledge()
    before = k.version_hash()
    record(k, Finding(rule_id="arbiter/x", title="t", location=Location(path="a.py")), "true_positive")
    assert k.version_hash() != before


def test_pinned_knowledge_refuses_a_changed_version(tmp_path):
    from arbiter.learn import Knowledge
    kp = tmp_path / "knowledge.json"
    Knowledge().save(str(kp))
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.py").write_text("x = 1\n")
    with pytest.raises(RuntimeError, match="pinned"):
        run_scan([str(repo)], load_config(None), only=["quality"],
                 knowledge_path=str(kp), pin_knowledge="k:deadbeefdead")


def test_scan_records_the_knowledge_version_it_used(tmp_path):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.py").write_text("x = 1\n")
    rep = run_scan([str(repo)], load_config(None), only=["quality"],
                   knowledge_path=str(tmp_path / "k.json"))
    assert rep.learning["knowledge_version"].startswith("k:")


def test_same_inputs_produce_identical_findings(tmp_path):
    """Adaptation happens between runs, never within one."""
    repo = tmp_path / "r"; repo.mkdir()
    (repo / "c.py").write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nTODO = 1\n')
    kp = str(tmp_path / "k.json")
    runs = [run_scan([str(repo)], load_config(None), only=["secrets", "quality"],
                     knowledge_path=kp) for _ in range(3)]
    signatures = [tuple(sorted((f.id, f.severity, f.confidence) for f in r.active())) for r in runs]
    assert len(set(signatures)) == 1
    assert len({r.learning["knowledge_version"] for r in runs}) == 1


def test_adaptive_thresholds_respect_a_floor():
    from arbiter.learn import adaptive_threshold, build_profile
    tiny = build_profile([2.0] * 200)        # a codebase of two-line functions
    assert adaptive_threshold(tiny, 120, "p95", 40) == 40, "cannot tighten below the floor"
    huge = build_profile([400.0] * 200)      # uniformly enormous functions
    assert adaptive_threshold(huge, 120, "p95", 40) == 400


def test_adaptive_thresholds_ignore_thin_distributions():
    from arbiter.learn import adaptive_threshold, build_profile
    thin = build_profile([10.0] * 5)
    assert adaptive_threshold(thin, 120, "p95", 40) == 120, "5 samples cannot retune a threshold"


def test_adaptive_is_off_unless_asked(tmp_path):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.py").write_text("def f():\n    return 1\n")
    rep = run_scan([str(repo)], load_config(None), only=["ast_metrics"],
                   knowledge_path=str(tmp_path / "k.json"))
    assert rep.learning["adaptive_thresholds"] == ""


# --------------------------------------------------------------------------
# Defects found by breadth and injection testing.
#
# Each of these was a real gap: the evaluator claimed to cover a language or a
# platform and did not. They are regressions waiting to happen.
# --------------------------------------------------------------------------

def test_go_short_declaration_is_seen(tmp_path):
    """`apiKey := "..."` was invisible: the regex matched the colon of `:=`
    and then failed on the equals. Recall on the rule was 0.48."""
    found = _scan_text(tmp_path, "main.go",
                       'package main\n\nfunc init() {\n\tapiKey := "Zx91qKp4vWmTn83LcRd7Qa"\n}\n',
                       ["secrets"])
    assert found, "Go short variable declarations must be scanned"


def test_template_literal_is_a_string(tmp_path):
    """A secret in a JavaScript backtick string is still a secret."""
    found = _scan_text(tmp_path, "app.js",
                       'const authToken = `Zx91qKp4vWmTn83LcRd7Qa`;\n', ["secrets"])
    assert found


def test_hyphenated_placeholders_are_not_secrets(tmp_path):
    for value in ("your-api-key-here", "replace-me-placeholder", "token-goes-here",
                  "sample-secret-value", "redacted-for-docs"):
        found = _scan_text(tmp_path, f"c_{abs(hash(value))}.py",
                           f'API_KEY = "{value}"\n', ["secrets"])
        assert not found, f"{value} is a placeholder, not a credential"


def test_every_container_shape_is_a_workload():
    """Job, CronJob and Pod were not classified as compute, so a third of
    injected Kubernetes defects matched no rule at all."""
    from arbiter.graph import K8S_KINDS
    for kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                 "Pod", "Job", "CronJob", "ReplicationController"):
        assert K8S_KINDS.get(kind) == "compute", f"{kind} must be compute"


def test_kubernetes_claims_are_not_scored_by_aws_properties(tmp_path):
    """A PVC is a block_store, but encryption lives on its StorageClass. This
    rule fired on every PersistentVolumeClaim in Kubernetes' own examples."""
    found = _scan_text(tmp_path, "pvc.yaml",
                       "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: c\n"
                       "spec:\n  resources:\n    requests:\n      storage: 5Gi\n",
                       ["resource_policy"])
    assert not [f for f in found if "unencrypted-volume" in f.rule_id]


def test_unhardened_workload_is_reported(tmp_path):
    """Kubernetes defaults are the insecure ones, so the finding is about what
    is absent. Without these rules a deliberately vulnerable Kubernetes
    repository produced two findings."""
    found = _scan_text(tmp_path, "deploy.yaml",
                       "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: w\n"
                       "spec:\n  template:\n    spec:\n      containers:\n"
                       "      - name: app\n        image: app:1.0\n",
                       ["resource_policy"])
    rules = {f.rule_id.split(".")[-1] for f in found}
    assert "k8s-no-security-context" in rules
    assert "k8s-not-run-as-non-root" in rules


def test_hardened_workload_is_quiet(tmp_path):
    found = _scan_text(tmp_path, "deploy.yaml",
                       "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: w\n"
                       "spec:\n  template:\n    spec:\n      containers:\n"
                       "      - name: app\n        image: app:1.2.3\n"
                       "        securityContext:\n          allowPrivilegeEscalation: false\n"
                       "          runAsNonRoot: true\n          readOnlyRootFilesystem: true\n"
                       "          capabilities:\n            drop: [\"ALL\"]\n"
                       "        resources:\n          limits:\n            cpu: \"1\"\n",
                       ["resource_policy"])
    assert not found, [f.rule_id for f in found]


def test_local_dev_database_urls_are_downgraded(tmp_path):
    """docker/awesome-compose's four highest findings were all
    postgres://postgres:postgres@db:5432."""
    found = _scan_text(tmp_path, "main.py",
                       'DATABASE_URL = "postgres://postgres:postgres@db:5432/app"\n', ["secrets"])
    assert found and found[0].severity == "low" and found[0].confidence == "low"


def test_real_database_credentials_are_not_downgraded(tmp_path):
    found = _scan_text(tmp_path, "main.py",
                       'DATABASE_URL = "postgres://svc_42:Zx91qKp4vWmTn83LcRd7@db.internal:5432/app"\n',
                       ["secrets"])
    assert found and found[0].severity == "high"


def test_provider_scoping_is_honoured():
    from arbiter.graph import Resource
    from arbiter.probes import SATISFIED, _eval_assert
    rule = {"id": "x", "assert": "text_present", "values": ['"securitycontext"'],
            "match_providers": ["k8s"]}
    # the assertion itself is provider-blind; scoping happens in the probe,
    # so this only checks the assertion still evaluates predictably
    hardened = Resource("d", "compute", "k8s", "Deployment", {"securityContext": {"runAsNonRoot": True}})
    assert _eval_assert(hardened, rule) == SATISFIED


def test_cloudformation_and_kubernetes_are_not_labelled_terraform_source(tmp_path):
    """The `evaluated from source, not from a plan` note fired on repositories
    with no Terraform in them at all."""
    found = _scan_text(tmp_path, "deploy.yaml",
                       "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n"
                       "spec:\n  ports:\n  - port: 80\n", ["resource_policy"])
    assert not [f for f in found if "source-is-literal-hcl" in f.rule_id]


# --------------------------------------------------------------------------
# Unquoted values.
#
# A .env file, a Kubernetes Secret, a docker-compose file, an `export` line and
# a Dockerfile `ENV` all write secrets without quotes — and those are the
# places secrets most commonly leak. Every one of them was invisible.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name,content", [
    ("dotenv",        "API_KEY=Zx91qKp4vWmTn83LcRd7\n"),
    ("yaml",          "config:\n  api_key: Aa12QwErTy90ZxCv\n"),
    ("k8s_secret",    "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  password: cXVvYml0ZQ==\n"),
    ("shell_export",  "#!/bin/sh\nexport DB_PASSWORD=c5nkQ2p9Lm4Tx\n"),
    ("dockerfile_env","FROM alpine\nENV API_KEY=Zx91qKp4vWmTn83LcRd7\n"),
    ("properties",    "api.key=Zx91qKp4vWmTn83LcRd7\n"),
])
def test_unquoted_secrets_are_found(tmp_path, name, content):
    ext = {"dotenv": ".env", "yaml": ".yaml", "k8s_secret": ".yaml", "shell_export": ".sh",
           "dockerfile_env": "Dockerfile", "properties": ".properties"}[name]
    fname = ext if ext == "Dockerfile" else f"{name}{ext}"
    found = _scan_text(tmp_path, fname, content, ["secrets"])
    assert found, f"an unquoted secret in {name} must be found"


@pytest.mark.parametrize("label,content", [
    # An IAM action in a CloudFormation policy. The colon made it look like an
    # assignment and `GetSecretValue` like a value.
    ("iam_action",   "Statement:\n  - Action:\n      - secretsmanager: GetSecretValue\n"),
    # An expression being assigned, not a literal.
    ("code_expr",    "search_tokens=_get_search_tokens(text)\n"),
    # References to a secret, not the secret.
    ("secret_ref",   "volumes:\n  - secretName: my-tls-cert-2024\n"),
    ("secret_path",  "private_key_path=/etc/ssl/private/server.pem\n"),
    ("token_url",    "token_endpoint=https://auth.example.com/oauth/v2\n"),
    # Substitution, not a value.
    ("env_ref",      "API_KEY=${AWS_SECRET}\n"),
    ("bare_env_ref", "API_KEY=$AWS_SECRET\n"),
    ("yaml_tag",     "password: !vault|AES256abcdef\n"),
    ("version",      "secret_version=1.24.3\n"),
])
def test_unquoted_look_alikes_stay_quiet(tmp_path, label, content):
    found = _scan_text(tmp_path, f"{label}.yaml", content, ["secrets"])
    assert not found, f"{label} is not a credential: {[f.evidence for f in found]}"


def test_purely_alphabetic_unquoted_values_are_words(tmp_path):
    """A real secret essentially always carries a digit or a symbol. Without
    this, every `secretsmanager: DescribeSecret` in an IAM policy was a
    finding."""
    assert not _scan_text(tmp_path, "p.yaml", "  client_secret: DescribeSecret\n", ["secrets"])
    assert _scan_text(tmp_path, "q.yaml", "  client_secret: DescribeSecret9\n", ["secrets"])


# ---------------------------------------------------------------------------
# Severity by measured discrimination, not by intuition.
#
# A rule earns its severity by firing more on bad code than on good code. The
# three dependency-pinning rules were all "low". Measured stack-for-stack
# against the corpus, only one of them actually separates the two:
#
#   supply.unpinned-action       4.3x on Node, 219x on CloudFormation  -> low
#   supply.unpinned-npm-dep      1.1x  (0.68/kloc good, 0.73/kloc bad) -> info
#   supply.unpinned-python-dep   0.0x  (fires only on good code)       -> info
#
# "info" scores zero, so a repo is no longer graded down for something that
# carries no evidence. The findings are still reported.
# ---------------------------------------------------------------------------

def test_unpinned_npm_dep_is_informational(tmp_path):
    found = _scan_text(tmp_path, "package.json",
                       '{"dependencies": {"lodash": "^4.17.0"}}\n', ["supply_chain"])
    hits = [f for f in found if f.rule_id == "arbiter/supply.unpinned-npm-dep"]
    assert hits, "the rule must still report"
    assert hits[0].severity == "info"


def test_unpinned_python_dep_is_informational(tmp_path):
    found = _scan_text(tmp_path, "requirements.txt", "requests>=2.0\nflask\n",
                       ["supply_chain"])
    hits = [f for f in found if f.rule_id == "arbiter/supply.unpinned-python-dep"]
    assert len(hits) == 2
    assert all(f.severity == "info" for f in hits)


def test_unpinned_action_keeps_its_severity(tmp_path):
    """This is the one that discriminates, so it keeps scoring."""
    wf = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
    found = _scan_text(tmp_path, ".github/workflows/ci.yml", wf, ["supply_chain"])
    hits = [f for f in found if f.rule_id == "arbiter/supply.unpinned-action"]
    assert hits and hits[0].severity == "low"


def test_informational_findings_do_not_move_the_grade(tmp_path):
    """The point of the downgrade: a project full of caret ranges and nothing
    else must not be scored as if it had real problems."""
    from arbiter.core import SEV_WEIGHT
    assert SEV_WEIGHT["info"] == 0.0
    found = _scan_text(tmp_path, "package.json",
                       '{"dependencies": {"a": "^1.0.0", "b": "~2.0.0", "c": "*"}}\n',
                       ["supply_chain"])
    assert found and all(SEV_WEIGHT[f.severity] == 0.0 for f in found)


def test_corpus_separates_teaching_material_from_production_code(tmp_path):
    """Example repositories are a third population. Counting starter templates
    as well-maintained production code made the false-positive rate look about
    four times worse than it is."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "arbiter_corpus", Path(__file__).resolve().parents[1] / "tools" / "corpus.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert set(mod.POPULATIONS) == {"clean", "vulnerable", "examples"}
    labels = {name: exp for name, (exp, _) in mod.CORPUS.items()}
    for teaching in ("cdk-examples", "k8s-examples", "cfn-templates",
                     "compose-awesome", "helm-charts"):
        assert labels[teaching] == "examples", f"{teaching} is teaching material"
    # real production code must stay in the measurement group
    for production in ("requests", "flask", "express", "rust-ripgrep"):
        assert labels[production] == "clean"


# ---------------------------------------------------------------------------
# A report has to say what it looked at, not just what it found.
#
# Without per-language line counts the only denominator available is
# whole-repository size, and that is how a Kubernetes rule scores a perfect
# record inside a 400,000-line Go project containing forty lines of YAML: the
# other 399,960 lines were never eligible to fail. Rates computed that way are
# not wrong by a little, they are answering a different question.
# ---------------------------------------------------------------------------

def test_report_breaks_lines_down_by_language_and_role(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "deploy.yaml").write_text("kind: Pod\nmetadata:\n  name: a\n")
    (tmp_path / "README.md").write_text("# hi\n")
    rep = run_scan([str(tmp_path)], load_config(None), only=["quality"],
                   use_adapters=False)

    assert rep.loc_by_language.get("python") == 2
    assert rep.loc_by_language.get("yaml") == 3
    assert rep.loc_by_language.get("markdown") == 1
    assert rep.loc_by_role.get("docs") == 1
    # the breakdown must account for every line the whole-repo figure claims
    assert sum(rep.loc_by_language.values()) == sum(rep.loc_by_role.values())
    assert sum(rep.loc_by_language.values()) == sum(r.loc for r in rep.repos)


def test_language_breakdown_survives_serialization(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    rep = run_scan([str(tmp_path)], load_config(None), only=["quality"],
                   use_adapters=False)
    d = json.loads(json.dumps(rep.to_dict()))
    assert d["loc_by_language"]["python"] == 1
    assert d["loc_by_role"]["source"] == 1


# ---------------------------------------------------------------------------
# Two false positives found by widening the corpus, both of them criticals on
# well-maintained code -- the single worst kind of finding this tool can
# produce, because a critical is what turns somebody's build red.
# ---------------------------------------------------------------------------

def test_pem_header_with_a_placeholder_body_is_not_a_key(tmp_path):
    """Argo CD's operator manual shows how to register a repository
    credential. The key body in that example is three literal dots. Matching
    the BEGIN line alone reported it as a critical, high-confidence leaked
    private key."""
    doc = ("apiVersion: v1\nstringData:\n  sshPrivateKey: |\n"
           "    -----BEGIN OPENSSH PRIVATE KEY-----\n"
           "    ...\n"
           "    -----END OPENSSH PRIVATE KEY-----\n")
    assert not _scan_text(tmp_path, "manifests/creds.yaml", doc, ["secrets"])


@pytest.mark.parametrize("body", [
    "...", "<your-key-here>", "[REDACTED]", "xxxxxxxxxxxx", "{{ .Values.key }}",
    "YOUR PRIVATE KEY", "paste your key", "snip",
])
def test_written_placeholders_are_not_keys(tmp_path, body):
    doc = (f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n")
    found = _scan_text(tmp_path, f"k{abs(hash(body))}.pem", doc, ["secrets"])
    assert not [f for f in found if "private-key" in f.rule_id], \
        f"{body!r} is a stand-in, not key material"


def test_real_key_material_is_still_reported(tmp_path):
    """The check must only reject what is demonstrably a stand-in. A real body,
    including a deliberately truncated fixture one, still reports."""
    real = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXAIBAAKBgQDVgc+zdNmcxwg4xqdoiy/WpnYj0WFvE7A/zy0EfvnUhxhLAXlC\n"
            "bjQw5Sqxa8IwQVr4G/mR7wTTJtf/Nrt5bP+E2D4W9MtuL7tzZ9KS/7v3D3nninMP\n"
            "-----END RSA PRIVATE KEY-----\n")
    found = _scan_text(tmp_path, "deploy/server.key", real, ["secrets"])
    assert [f for f in found if f.severity == "critical"]

    short = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n"
    assert _scan_text(tmp_path, "deploy/short.key", short, ["secrets"])


def test_unterminated_pem_block_is_kept(tmp_path):
    """A block with no END marker cannot be read, so it is treated as real.
    The conservative direction is the one that keeps findings."""
    doc = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIICXAIBAAKBgQDVgc+zdNmcxwg4xqdoiy/WpnYj0WFvE7A/zy0EfvnUhxhLAXlC\n")
    assert _scan_text(tmp_path, "deploy/partial.key", doc, ["secrets"])


@pytest.mark.parametrize("path", [
    "integration/resources/tls/consul.key",   # traefik
    "e2e/certs/server.key",
    "acceptance/tls/key.pem",
    "hack/certs/dev.key",
    "docs/operator-manual/repo-creds.yaml",   # argo-cd
])
def test_non_deployment_paths_downgrade_real_keys(tmp_path, path):
    """Traefik commits real TLS keys under integration/resources/tls so its
    integration suite has something to serve. Same category as the keys under
    psf/requests' tests/certs -- a different word for the directory should not
    change the verdict from medium to critical."""
    real = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXAIBAAKBgQDVgc+zdNmcxwg4xqdoiy/WpnYj0WFvE7A/zy0EfvnUhxhLAXlC\n"
            "bjQw5Sqxa8IwQVr4G/mR7wTTJtf/Nrt5bP+E2D4W9MtuL7tzZ9KS/7v3D3nninMP\n"
            "-----END RSA PRIVATE KEY-----\n")
    found = [f for f in _scan_text(tmp_path, path, real, ["secrets"])
             if "private-key" in f.rule_id]
    assert found, "still reported — downgraded, never hidden"
    assert found[0].severity == "medium" and found[0].confidence == "low"
    assert "fixture" in found[0].title


def test_production_paths_are_not_caught_by_the_widened_pattern(tmp_path):
    """`integration` and `e2e` were added to the non-deployment paths. They
    must match a directory, not a word inside a filename."""
    real = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXAIBAAKBgQDVgc+zdNmcxwg4xqdoiy/WpnYj0WFvE7A/zy0EfvnUhxhLAXlC\n"
            "-----END RSA PRIVATE KEY-----\n")
    for path in ("src/integration_client.key", "deploy/e2e-gateway.pem"):
        found = [f for f in _scan_text(tmp_path, path, real, ["secrets"])
                 if "private-key" in f.rule_id]
        assert found and found[0].severity == "critical", path


# ---------------------------------------------------------------------------
# The worklist is the handoff between the half of training that needs nobody
# and the half that needs judgement. If it silently reports nothing, an
# unattended cycle looks identical to a healthy one.
# ---------------------------------------------------------------------------

def _worklist(tmp_path, corpus=None, disc=None, knowledge=None) -> str:
    import subprocess
    paths = {}
    for name, data in (("corpus", corpus), ("disc", disc), ("knowledge", knowledge)):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(data if data is not None else {}))
        paths[name] = str(p)
    out = tmp_path / "WORKLIST.md"
    subprocess.run(
        ["python", str(ROOT / "tools" / "worklist.py"),
         "--corpus-summary", paths["corpus"], "--discrimination", paths["disc"],
         "--knowledge", paths["knowledge"], "--out", str(out)],
        check=True, capture_output=True, cwd=str(ROOT))
    return out.read_text()


def test_worklist_raises_a_critical_on_good_code_first(tmp_path):
    corpus = {"rows": [
        {"repo": "some-lib", "expectation": "clean", "stack_label": "python",
         "loc": 50_000, "findings": 3, "critical": 1, "high": 0},
        {"repo": "goat", "expectation": "vulnerable", "stack_label": "python",
         "loc": 5_000, "findings": 40, "critical": 9, "high": 4},
    ]}
    text = _worklist(tmp_path, corpus=corpus, disc={"rows": []})
    assert "HIGHEST" in text
    assert "some-lib" in text
    # a critical on the deliberately broken repo is the correct answer, not an item
    assert "goat** (python): 9 critical" not in text


def test_worklist_flags_a_severity_the_measurement_does_not_support(tmp_path):
    disc = {"rows": [{
        "rule": "arbiter/secrets.made-up", "severity": "high", "dimension": "security",
        "judgeable": True, "thin": False, "weighted_ratio": 0.4,
        "clean_hits": 90, "vuln_hits": 2,
    }]}
    text = _worklist(tmp_path, corpus={"rows": []}, disc=disc)
    assert "arbiter/secrets.made-up" in text and "0.4x" in text


def test_worklist_does_not_judge_a_quality_rule(tmp_path):
    """There is no deliberately-badly-documented population, so a low ratio on
    a quality rule is a statement about codebase age, not about the rule."""
    disc = {"rows": [{
        "rule": "arbiter/ast.function-too-long", "severity": "low",
        "dimension": "quality", "judgeable": False, "thin": False,
        "weighted_ratio": 0.2, "clean_hits": 800, "vuln_hits": 33,
    }]}
    text = _worklist(tmp_path, corpus={"rows": []}, disc=disc)
    assert "function-too-long" not in text


def test_worklist_flags_a_rule_with_no_controls(tmp_path):
    know = {"rules": {
        "arbiter/secrets.uncontrolled": {
            "synthetic_positives": 500, "synthetic_negatives": 0},
        "arbiter/secrets.controlled": {
            "synthetic_positives": 500, "synthetic_negatives": 500},
    }}
    text = _worklist(tmp_path, corpus={"rows": []}, disc={"rows": []}, knowledge=know)
    assert "arbiter/secrets.uncontrolled" in text
    assert "arbiter/secrets.controlled" not in text


def test_worklist_flags_rules_nothing_has_ever_exercised(tmp_path):
    """A rule that fired on no repository and has no injection trials is an
    assertion, not a measurement — and it is invisible in every other table."""
    text = _worklist(tmp_path, corpus={"rows": []}, disc={"rows": []})
    assert "nothing has ever exercised" in text.lower()


def test_worklist_says_so_when_there_is_nothing_to_do(tmp_path):
    """With every declared rule measured and every check clean, the queue is
    empty — and an empty queue means the corpus has stopped teaching us
    anything, which is itself the finding."""
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "src"))
    from arbiter.probes import _load_resource_rules
    rows = [{"rule": f"arbiter/resource.{r['id']}", "severity": "medium",
             "dimension": "security", "judgeable": True, "thin": False,
             "weighted_ratio": 40.0, "clean_hits": 1, "vuln_hits": 40}
            for r in _load_resource_rules()]
    text = _worklist(tmp_path, corpus={"rows": []}, disc={"rows": rows})
    assert "widen it, not to run it again" in text


def test_worklist_reports_missing_input_rather_than_looking_clean(tmp_path):
    """An unattended cycle that failed halfway must not produce a worklist that
    reads like a clean bill of health."""
    import subprocess
    out = tmp_path / "W.md"
    subprocess.run(
        ["python", str(ROOT / "tools" / "worklist.py"),
         "--corpus-summary", str(tmp_path / "nope.json"),
         "--discrimination", str(tmp_path / "nope2.json"),
         "--knowledge", str(tmp_path / "nope3.json"), "--out", str(out)],
        check=True, capture_output=True, cwd=str(ROOT))
    text = out.read_text()
    assert "Incomplete" in text and "train_cycle.sh" in text


def test_worklist_raises_the_gap_only_a_person_can_close(tmp_path):
    """Calibration reads only the adjudicated ledger. With that ledger empty the
    machinery is inert, and no amount of nightly running will fill it."""
    know = {"rules": {"arbiter/x": {"synthetic_positives": 10, "synthetic_negatives": 10}},
            "adjudicated": {}}
    header = "No real finding has ever been reviewed by a person"
    text = _worklist(tmp_path, corpus={"rows": []}, disc={"rows": []}, knowledge=know)
    assert header in text and "arbiter feedback" in text

    reviewed = dict(know, adjudicated={"f:abcd": {"verdict": "true_positive"}})
    assert header not in _worklist(
        tmp_path, corpus={"rows": []}, disc={"rows": []}, knowledge=reviewed)
