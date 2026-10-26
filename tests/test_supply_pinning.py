"""Supply-chain pinning (ARB-130, ARB-131, ARB-132; FAIL-100).

What counts as pinned in each ecosystem is listed in src/arbiter/supply.py.
Each test below is one shape of reference, pinned or not, read the way the
ecosystem reads it.
"""
from __future__ import annotations

import pytest

from arbiter.engine import run_scan
from arbiter.policy import load_config

SHA = "8e5e7e5ab8b370d6c329ec480221332ada57f0ab"
DIGEST = "sha256:" + "0123456789abcdef" * 4


def _scan(tmp_path, files: dict[str, str]):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    cfg = dict(load_config(None))
    return run_scan([str(tmp_path)], cfg, only=["supply_chain"], use_adapters=False,
                    use_cache=False).active()


def _hits(found, rule: str):
    return sorted((f.location.path, f.location.start_line, f.evidence) for f in found
                  if f.rule_id == f"arbiter/supply.{rule}")


def _workflow(steps: str) -> str:
    return "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n" + steps


# ---------------------------------------------------------------------------
# FAIL-100: supply.unpinned-action read quoted refs and docker:// wrongly
# ---------------------------------------------------------------------------

def test_a_quoted_sha_pin_is_pinned(tmp_path):
    """`[^\\s#]+` ran over the closing quote, so `"actions/checkout@<sha>"`
    had the ref `<sha>"`, failed the 40-hex test and was reported."""
    wf = _workflow(f'      - uses: "actions/checkout@{SHA}"\n'
                   f"      - uses: 'actions/setup-node@{SHA}'  # v4\n")
    assert _hits(_scan(tmp_path, {".github/workflows/ci.yml": wf}), "unpinned-action") == []


def test_a_quoted_tag_is_reported_without_the_quote(tmp_path):
    wf = _workflow('      - uses: "actions/checkout@v4"\n'
                   "      - uses: 'org/repo/.github/workflows/x.yml@v2.7.0'\n")
    hits = _hits(_scan(tmp_path, {".github/workflows/ci.yml": wf}), "unpinned-action")
    assert [h[2] for h in hits] == ["actions/checkout@v4", "org/repo/.github/workflows/x.yml@v2.7.0"]
    assert [h[1] for h in hits] == [6, 7]


def test_a_docker_digest_is_not_an_unpinned_action(tmp_path):
    """`docker://alpine@sha256:<64 hex>` split at the `@` into an action
    `docker://alpine` with the ref `sha256:...`, which is not 40 hex."""
    wf = _workflow(f"      - uses: docker://alpine@{DIGEST}\n")
    found = _scan(tmp_path, {".github/workflows/ci.yml": wf})
    assert _hits(found, "unpinned-action") == []
    assert _hits(found, "unpinned-container-image") == []


@pytest.mark.parametrize("ref", ["docker://alpine:3.18", "docker://docker",
                                 "docker://ghcr.io/rhysd/actionlint:latest"])
def test_a_docker_tag_is_an_unpinned_image(tmp_path, ref):
    """`docker://alpine:3.18` has no `@`, so the action regex never matched
    it and a mutable image ran unchecked."""
    found = _scan(tmp_path, {".github/workflows/ci.yml": _workflow(f"      - uses: {ref}\n")})
    assert _hits(found, "unpinned-action") == []
    assert [h[2] for h in _hits(found, "unpinned-container-image")] == [f"uses:{ref}"]


def test_what_the_action_rule_always_did_still_holds(tmp_path):
    wf = _workflow(f"      - uses: actions/checkout@{SHA} # v4.2.2\n"
                   "      - uses: ./.github/actions/local\n"
                   "      - uses: actions/cache@v4\n"
                   "      - uses: org/repo/.github/workflows/reusable.yml@main\n")
    hits = _hits(_scan(tmp_path, {".github/workflows/ci.yml": wf}), "unpinned-action")
    assert [h[2] for h in hits] == ["actions/cache@v4", "org/repo/.github/workflows/reusable.yml@main"]


def test_a_composite_action_is_checked_like_a_workflow(tmp_path):
    action = ("name: setup\nruns:\n  using: composite\n  steps:\n"
              "    - uses: actions/setup-java@v5\n"
              f"    - uses: actions/cache@{SHA}\n"
              "    - uses: ./.github/actions/other\n")
    found = _scan(tmp_path, {".github/actions/setup/action.yml": action,
                             "docs/action.yaml": "uses: actions/checkout@v4\n"})
    hits = _hits(found, "unpinned-action")
    assert hits == [(".github/actions/setup/action.yml", 5, "actions/setup-java@v5")], \
        "an action.yaml with no `runs:` is not an action definition"


def test_the_fallback_reader_handles_quotes_too(tmp_path):
    """A CI file that is not YAML (or does not parse) falls back to a line
    pattern, which must not carry the quote either."""
    broken = ('jobs: {{ unparseable\n'
              f'      - uses: "actions/checkout@{SHA}"\n'
              '      - uses: "actions/cache@v4"\n')
    hits = _hits(_scan(tmp_path, {".github/workflows/ci.yml": broken}), "unpinned-action")
    assert [h[2] for h in hits] == ["actions/cache@v4"]


# ---------------------------------------------------------------------------
# supply.unpinned-container-image
# ---------------------------------------------------------------------------

def test_dockerfile_images(tmp_path):
    df = ("ARG BASE=python:3.12\nARG FROM_CLI\nARG PINNED=alpine@" + DIGEST + "\n"
          "FROM $BASE AS build\n"            # 4: resolved from the ARG default -> tag
          "FROM build AS test\n"             # 5: an earlier stage
          "FROM scratch\n"                   # 6
          "FROM ${FROM_CLI}\n"               # 7: only known at build time
          "FROM --platform=linux/amd64 ubuntu\n"   # 8: untagged
          "FROM ${PINNED}\n"                 # 9: resolved digest
          "COPY --from=ghcr.io/astral-sh/uv:0.4 /uv /bin/\n"   # 10: image -> tag
          "COPY --from=build /a /b\n"        # 11: a stage
          "COPY --from=later /a /b\n")       # 12: a bare word is a stage name
    hits = _hits(_scan(tmp_path, {"Dockerfile": df}), "unpinned-container-image")
    assert [(h[1], h[2]) for h in hits] == [(4, "dockerfile:python:3.12"), (8, "dockerfile:ubuntu"),
                                            (10, "dockerfile:ghcr.io/astral-sh/uv:0.4")]


def test_a_stage_named_like_an_image_is_a_stage_only_after_it_is_defined(tmp_path):
    df = "FROM node AS node\nFROM node\n"
    hits = _hits(_scan(tmp_path, {"build.Dockerfile": df}), "unpinned-container-image")
    assert [h[1] for h in hits] == [1]


def test_compose_images(tmp_path):
    compose = ("services:\n  web:\n    build: .\n    image: me/web:dev\n"
               "  worker:\n    image: me/web:dev\n"
               "  db:\n    image: postgres:16\n"
               f"  cache:\n    image: redis@{DIGEST}\n"
               "  q:\n    image: rabbitmq\n")
    hits = _hits(_scan(tmp_path, {"docker-compose.yml": compose}), "unpinned-container-image")
    assert [(h[1], h[2]) for h in hits] == [(8, "compose:postgres:16"), (12, "compose:rabbitmq")]


def test_kubernetes_images_leave_latest_to_the_resource_rule(tmp_path):
    """`:latest` is already resource.k8s-mutable-image-tag; this rule adds
    other tags and images with no tag at all, without reporting twice."""
    m = ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
         "      initContainers:\n        - name: i\n          image: busybox:1.36\n"
         "      containers:\n        - name: a\n          image: nginx:latest\n"
         "        - name: b\n          image: nginx\n"
         f"        - name: c\n          image: nginx@{DIGEST}\n")
    hits = _hits(_scan(tmp_path, {"k8s/app.yaml": m}), "unpinned-container-image")
    assert [(h[1], h[2]) for h in hits] == [(8, "k8s:busybox:1.36"), (13, "k8s:nginx")]


def test_a_helm_template_is_not_judged(tmp_path):
    t = ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
         "      containers:\n        - image: {{ .Values.image }}:{{ .Values.tag }}\n"
         "{{- if .Values.sidecar }}\n        - image: envoy\n{{- end }}\n")
    assert _hits(_scan(tmp_path, {"chart/templates/d.yaml": t}), "unpinned-container-image") == []


def test_gitlab_and_workflow_images(tmp_path):
    gl = (f"image: ruby:3.3\nservices:\n  - postgres:16\n  - name: redis@{DIGEST}\n"
          "test:\n  image:\n    name: node:latest\n  script: [rake]\n")
    wf = ("on: push\njobs:\n  b:\n    container:\n      image: node:20\n"
          f"    services:\n      db:\n        image: postgres@{DIGEST}\n"
          "      c:\n        image: redis\n    steps:\n      - run: true\n")
    found = _scan(tmp_path, {".gitlab-ci.yml": gl, ".github/workflows/ci.yml": wf})
    assert [(h[0], h[1]) for h in _hits(found, "unpinned-container-image")] == [
        (".github/workflows/ci.yml", 5), (".github/workflows/ci.yml", 10),
        (".gitlab-ci.yml", 1), (".gitlab-ci.yml", 3), (".gitlab-ci.yml", 7)]


def test_image_severity_comes_from_measurement(tmp_path):
    found = _scan(tmp_path, {"Dockerfile": "FROM alpine:3.20\n"})
    hit = [f for f in found if f.rule_id == "arbiter/supply.unpinned-container-image"]
    assert hit and (hit[0].severity, hit[0].confidence) == ("low", "high")
    assert hit[0].cwe == ["CWE-1357", "CWE-494"]


# ---------------------------------------------------------------------------
# supply.unpinned-python-dep (ARB-131)
# ---------------------------------------------------------------------------

def test_python_requirement_forms(tmp_path):
    req = ("requests>=2\n"                                    # 1 range
           "-e .\n"                                           # 2 the project itself
           "-e git+https://github.com/a/b@main#egg=b\n"       # 3 VCS at a branch
           f"-e git+https://github.com/a/c@{SHA}#egg=c\n"     # 4 VCS at a commit
           "flask==3.0.3 --hash=sha256:abc\n"                 # 5
           "foo===1.0\n"                                      # 6
           "bar==1.*\n"                                       # 7 wildcard
           "baz ; python_version < '3.11'\n"                  # 8 no version
           "-r other.txt\n--index-url https://x\n"            # 9-10 options
           f"qux @ git+https://github.com/a/q@{SHA}\n"        # 11
           "quux @ https://example.com/quux-1.0.tar.gz\n"     # 12 an archive
           "pytest-cov[toml] >= 4  # tests\n")                # 13
    hits = _hits(_scan(tmp_path, {"requirements/base.txt": req}), "unpinned-python-dep")
    assert [h[1] for h in hits] == [1, 3, 7, 8, 13]


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-dev.txt", "requirements_test.txt",
                                  "requirements/ci.txt", "constraints.txt", "constraints-py3.txt"])
def test_every_requirements_file_shape_is_read(tmp_path, name):
    assert _hits(_scan(tmp_path, {name: "requests\n"}), "unpinned-python-dep")


def test_a_prose_file_named_like_a_requirements_file_is_not_pip_input(tmp_path):
    """django/django docs/ref/models/constraints.txt is documentation."""
    prose = ("=====================\nConstraints reference\n=====================\n\n"
             "The classes defined in this module create database constraints.\n")
    assert _hits(_scan(tmp_path, {"docs/constraints.txt": prose}), "unpinned-python-dep") == []


def test_a_python_lockfile_beside_the_manifest_pins_it(tmp_path):
    found = _scan(tmp_path, {"app/requirements.txt": "requests>=2\n", "app/poetry.lock": "",
                             "other/requirements.txt": "flask\n"})
    assert [h[0] for h in _hits(found, "unpinned-python-dep")] == ["other/requirements.txt"]


def test_python_dep_stays_informational(tmp_path):
    found = _scan(tmp_path, {"requirements.txt": "requests\n"})
    assert {f.severity for f in found if "python-dep" in f.rule_id} == {"info"}


# ---------------------------------------------------------------------------
# supply.unpinned-npm-dep (ARB-131)
# ---------------------------------------------------------------------------

def test_npm_spec_forms():
    from arbiter.supply_deps import npm_spec_issue as issue
    floating = [">=1.0.0", ">1", "<2", "1.x", "1.2.X", "*", "", "2", "2.1", "^1 || ^2",
                "1.0.0 - 2.0.0", "latest", "next", "beta", "github:u/r", "u/r", "u/r#main",
                "git+https://github.com/u/r.git", "git+https://github.com/u/r.git#v1.2.3",
                "npm:other@^1", "^1.2.3", "~1.2.3"]
    pinned = ["1.2.3", "=1.2.3", "v1.2.3", "1.2.3-rc.1", f"github:u/r#{SHA}",
              f"git+https://github.com/u/r.git#{SHA}", "file:../x", "link:../x",
              "workspace:*", "npm:other@1.2.3", "https://example.com/x-1.0.0.tgz", None, 3]
    assert [s for s in floating if not issue(s)] == []
    assert [s for s in pinned if issue(s)] == []


def test_a_lockfile_beside_or_above_pins_npm_ranges(tmp_path):
    """All six FP labels of this rule were a range under a lockfile."""
    found = _scan(tmp_path, {
        "package-lock.json": "{}",
        "packages/a/package.json": '{"dependencies": {"x": "^1.0.0"}}',
        "standalone/sub/package.json": '{"devDependencies": {"y": ">=2"}}',
        "standalone/yarn.lock": "",
        "loose/package.json": '{"optionalDependencies": {"z": "next"}, "dependencies": {"w": "1.2.3"}}',
    })
    assert tmp_path.joinpath("loose").is_dir()
    # The root lockfile covers every package below it, loose/ included.
    assert _hits(found, "unpinned-npm-dep") == []


def test_npm_ranges_without_a_lockfile(tmp_path):
    found = _scan(tmp_path, {"package.json":
                             '{"dependencies": {"a": "^1.0.0", "b": "1.2.3", "c": "next"},'
                             ' "optionalDependencies": {"d": "1.x"}, "peerDependencies": {"e": ">=1"}}'})
    assert [h[2] for h in _hits(found, "unpinned-npm-dep")] == ["a@^1.0.0", "c@next", "d@1.x"]


# ---------------------------------------------------------------------------
# supply.unpinned-java-dep (ARB-132)
# ---------------------------------------------------------------------------

def _pom(version: str, deps: str, props: str = "", group: str = "org.acme") -> str:
    return (f"<project><groupId>{group}</groupId><artifactId>app</artifactId>"
            f"<version>{version}</version><properties>{props}</properties>"
            f"<dependencies>{deps}</dependencies></project>")


def _dep(g: str, a: str, v: str) -> str:
    return f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></dependency>\n"


def test_maven_dynamic_versions(tmp_path):
    deps = (_dep("g", "latest", "LATEST") + _dep("g", "release", "RELEASE")
            + _dep("g", "range", "[1.0,)") + _dep("g", "prop", "${r}")
            + _dep("g", "snap", "2.0-SNAPSHOT") + _dep("org.acme.mod", "sibling", "1.1-SNAPSHOT")
            + _dep("g", "exact", "2.0") + _dep("g", "unknown", "${not.here}"))
    pom = _pom("1.0.0", deps, "<r>(,2.0]</r>")
    hits = _hits(_scan(tmp_path, {"pom.xml": pom}), "unpinned-java-dep")
    assert [h[2] for h in hits] == ["g:latest:LATEST", "g:release:RELEASE", "g:range:[1.0,)",
                                    "g:prop:${r}", "g:snap:2.0-SNAPSHOT"]


def test_a_snapshot_build_may_depend_on_snapshots(tmp_path):
    pom = _pom("1.1-SNAPSHOT", _dep("g", "snap", "2.0-SNAPSHOT"))
    assert _hits(_scan(tmp_path, {"pom.xml": pom}), "unpinned-java-dep") == []


def test_gradle_dynamic_versions_and_locking(tmp_path):
    gradle = ("version = '1.0'\ndependencies {\n"
              "  implementation 'g:a:1.+'\n"
              "  implementation \"g:b:latest.release\"\n"
              "  implementation 'g:c:2.0' // 'g:d:+' in a comment\n"
              "  implementation group: 'g', name: 'e', version: 'latest.integration'\n"
              "  implementation libs.foo\n}\n"
              "plugins { id 'x.y' version '1.+' }\n")
    found = _scan(tmp_path, {"a/build.gradle": gradle, "b/build.gradle.kts": gradle,
                             "b/gradle.lockfile": ""})
    hits = _hits(found, "unpinned-java-dep")
    assert [(h[0], h[1]) for h in hits] == [("a/build.gradle", 3), ("a/build.gradle", 4),
                                            ("a/build.gradle", 6), ("a/build.gradle", 9)]


def test_a_version_catalog(tmp_path):
    toml = ('[versions]\nfoo = "1.+"\nbar = "2.0"\nbaz = { strictly = "[1.0, 2.0)" }\n'
            '[libraries]\nq = "g:q:latest.release"\nr = { module = "g:r", version.ref = "foo" }\n'
            's = { module = "g:s", version = "3.1" }\n')
    hits = _hits(_scan(tmp_path, {"gradle/libs.versions.toml": toml}), "unpinned-java-dep")
    assert [h[1] for h in hits] == [2, 4, 6]


# ---------------------------------------------------------------------------
# supply.unpinned-ruby-dep (ARB-132)
# ---------------------------------------------------------------------------

GEMFILE = ('source "https://rubygems.org"\n'
           'gem "rails"\n'                                   # 2 no requirement
           'gem "pg", ">= 1.0"\n'                            # 3 open
           'gem "puma", "~> 6.0"\n'
           'gem "w", ">= 1",\n  "< 2"\n'                     # 5-6 bounded across lines
           'gem "x", git: "https://github.com/a/x"\n'        # 7 git, no ref
           f'gem "y", github: "a/y", ref: "{SHA}"\n'
           'gem "z", path: "../z"\n'
           'gem "c", RAILS_VERSION\n'                        # a constant: not judged
           'gem "d", require: false  # dev only\n')          # 11 no requirement


def test_gemfile_forms(tmp_path):
    hits = _hits(_scan(tmp_path, {"Gemfile": GEMFILE}), "unpinned-ruby-dep")
    assert [h[1] for h in hits] == [2, 3, 7, 11]


def test_a_gemfile_lock_or_a_gemspec_silences_it(tmp_path):
    found = _scan(tmp_path, {"app/Gemfile": GEMFILE, "app/Gemfile.lock": "",
                             "gem/Gemfile": "gemspec\n" + GEMFILE})
    assert _hits(found, "unpinned-ruby-dep") == []


# ---------------------------------------------------------------------------
# supply.unpinned-terraform (ARB-132)
# ---------------------------------------------------------------------------

TF = ('module "a" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'                       # 1
      'module "b" {\n  source  = "terraform-aws-modules/vpc/aws"\n  version = "~> 5.0"\n}\n'  # 4
      'module "c" {\n  source  = "terraform-aws-modules/vpc/aws"\n  version = "5.1.2"\n}\n'
      'module "d" {\n  source = "git::https://example.com/m.git?ref=main"\n}\n'              # 12
      f'module "e" {{\n  source = "git::https://example.com/m.git?ref={SHA}"\n}}\n'
      'module "f" {\n  source = "github.com/a/b?ref=v1.2.3" # a tag\n}\n'
      'module "g" {\n  source = "github.com/a/b"\n}\n'                                       # 21
      'module "h" {\n  source = "./local"\n}\n'
      'terraform {\n  required_providers {\n'
      '    aws = { source = "hashicorp/aws" }\n'                                             # 29
      '    random = {\n      source  = "hashicorp/random"\n      version = "~> 3"\n    }\n'
      '  }\n}\n')


def test_terraform_modules_and_providers(tmp_path):
    hits = _hits(_scan(tmp_path, {"infra/main.tf": TF}), "unpinned-terraform")
    assert [h[1] for h in hits] == [1, 4, 12, 21, 29]


def test_a_terraform_lockfile_pins_providers(tmp_path):
    found = _scan(tmp_path, {"infra/main.tf": TF, "infra/.terraform.lock.hcl": ""})
    assert [h[1] for h in _hits(found, "unpinned-terraform")] == [1, 4, 12, 21]


# ---------------------------------------------------------------------------
# supply.unpinned-precommit, supply.unpinned-ci-include
# ---------------------------------------------------------------------------

def test_precommit_revs(tmp_path):
    cfg = ("repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n"
           f"  - repo: https://github.com/a/b\n    rev: '{SHA}'  # frozen: v1\n"
           "  - repo: local\n    hooks: []\n  - repo: meta\n    hooks: []\n")
    hits = _hits(_scan(tmp_path, {".pre-commit-config.yaml": cfg}), "unpinned-precommit")
    assert hits == [(".pre-commit-config.yaml", 3, "https://github.com/psf/black@24.1.0")]


def test_gitlab_includes(tmp_path):
    gl = ("include:\n  - remote: https://x.example/ci.yml\n"
          f"  - remote: https://x.example/{SHA}/ci.yml\n"
          "  - project: g/p\n    ref: main\n    file: a.yml\n"
          "  - project: g/q\n    file: a.yml\n"
          f"  - project: g/r\n    ref: {SHA}\n"
          "  - component: gitlab.com/g/c/lint@1.0\n"
          "  - local: a.yml\n  - template: Auto-DevOps.gitlab-ci.yml\n"
          "test:\n  script: [true]\n")
    hits = _hits(_scan(tmp_path, {".gitlab-ci.yml": gl}), "unpinned-ci-include")
    assert [h[1] for h in hits] == [2, 4, 7, 11]


def test_a_single_remote_include_string(tmp_path):
    hits = _hits(_scan(tmp_path, {".gitlab-ci.yml": "include: https://x.example/ci.yml\n"}),
                 "unpinned-ci-include")
    assert [h[1] for h in hits] == [1]


# ---------------------------------------------------------------------------
# supply.remote-script-piped
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "curl -fsSL https://get.example.com | sh",
    "curl -fsSL https://get.example.com | sudo -E bash -s -- --flag",
    "wget -qO- https://x | python3 -",
    'sh -c "$(curl -fsSL https://x)"',
    "bash <(curl -s https://x)",
    "iex ((New-Object System.Net.WebClient).DownloadString('https://x'))",
    "irm https://x | iex",
    "Invoke-WebRequest https://x | Invoke-Expression",
])
def test_remote_script_piped(tmp_path, cmd):
    found = _scan(tmp_path, {"scripts/setup.sh": f"#!/bin/sh\n{cmd}\n"})
    assert _hits(found, "remote-script-piped"), cmd


@pytest.mark.parametrize("cmd", [
    "curl -fsSLo install.sh https://x && sha256sum -c install.sh.sha256 && sh install.sh",
    "curl -s https://api.example.com | jq .version",
    "# curl https://x | sh  (documented, not run)",
    "curl https://x > f; bash f",
])
def test_a_download_that_is_checked_or_not_executed_is_not_piped(tmp_path, cmd):
    assert _hits(_scan(tmp_path, {"scripts/setup.sh": f"#!/bin/sh\n{cmd}\n"}),
                 "remote-script-piped") == []


def test_piped_scripts_in_dockerfile_and_ci_point_at_their_line(tmp_path):
    df = "FROM alpine@" + DIGEST + "\nRUN apk add curl && \\\n    curl -sL https://x | sh\n"
    wf = _workflow("      - name: x\n        run: |\n          echo hi\n"
                   "          curl -sL https://x | bash\n")
    found = _scan(tmp_path, {"Dockerfile": df, ".github/workflows/ci.yml": wf})
    assert [(h[0], h[1]) for h in _hits(found, "remote-script-piped")] == [
        (".github/workflows/ci.yml", 9), ("Dockerfile", 2)]
    assert {f.cwe[0] for f in found if "piped" in f.rule_id} == {"CWE-494"}
    assert {f.dimension for f in found if "piped" in f.rule_id} == {"security"}


# ---------------------------------------------------------------------------
# supply.unpinned-install-in-build
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,bad", [
    ("pip install requests", ["requests"]),
    ("pip install requests==2.32.3 flask", ["flask"]),
    ("python -m pip install --no-cache-dir 'virtualenv<21'", ["virtualenv<21"]),
    ("pip install -r requirements.txt", []),
    ("pip install -e .", []),
    ("pip install --require-hashes -r req.txt", []),
    ("python -m pip install --upgrade pip setuptools wheel", []),
    ("pip install ./dist/pkg.whl", []),
    ("pip install --no-index -f wheels pkg", []),
    ("pip install $PKG", []),
    ("npm install -g yarn", ["yarn"]),
    ("npm i -g @angular/cli@17.0.1 typescript@^5", ["typescript@^5"]),
    ("npm ci", []),
    ("npm install", []),
    ("npm install --global npm@${{ env.NPM_VERSION }}", []),
    ("gem install bundler", ["bundler"]),
    ("gem install bundler -v 2.5.22", []),
    ("gem install openssl -- --with-openssl-dir=/x", ["openssl"]),
    ("go install golang.org/x/tools/gopls@latest", ["golang.org/x/tools/gopls@latest"]),
    ("go install golang.org/x/tools/gopls@v0.16.2", []),
])
def test_install_commands(cmd, bad):
    from arbiter.supply import install_issues
    assert [p for _, p in install_issues(cmd)] == bad


def test_installs_in_dockerfile_and_ci_but_not_in_plain_scripts(tmp_path):
    df = ("FROM alpine@" + DIGEST + "\nRUN pip install --no-cache-dir \\\n"
          "    gunicorn uvicorn==0.30\n")
    wf = _workflow("      - run: npm install -g pnpm\n")
    found = _scan(tmp_path, {"Dockerfile": df, ".github/workflows/ci.yml": wf,
                             "scripts/dev.sh": "pip install requests\n"})
    hits = _hits(found, "unpinned-install-in-build")
    assert [(h[0], h[1]) for h in hits] == [(".github/workflows/ci.yml", 6), ("Dockerfile", 2)]
    assert {f.severity for f in found if "install-in-build" in f.rule_id} == {"info"}


# ---------------------------------------------------------------------------
# The probe as a whole
# ---------------------------------------------------------------------------

def test_every_new_rule_is_advisory_and_traced():
    from arbiter import rule_meta
    rules = rule_meta.shipped_rules()
    new = ["remote-script-piped", "unpinned-ci-include", "unpinned-container-image",
           "unpinned-install-in-build", "unpinned-java-dep", "unpinned-precommit",
           "unpinned-ruby-dep", "unpinned-terraform"]
    for r in new:
        rid = f"arbiter/supply.{r}"
        assert rule_meta.declared_tier(rid) == "advisory", rid
        assert set(rules[rid]["requirements"]) & {"ARB-130", "ARB-131", "ARB-132"}, rid
    assert rule_meta.declared_tier("arbiter/supply.unpinned-action") == "verified"


def test_a_lockfile_appearing_changes_the_cache_key(tmp_path):
    """A manifest's answer depends on whether a lockfile sits beside it, so
    the result cache must not replay the old answer once one is added."""
    from arbiter.core import RepoInfo
    from arbiter.inventory import build_inventory
    from arbiter.probes import ProbeContext
    from arbiter.supply import cache_context

    def digest():
        repo = RepoInfo(id="root", path=str(tmp_path), source=str(tmp_path))
        return cache_context(ProbeContext(repos=[repo], inventory=build_inventory([repo])))

    (tmp_path / "package.json").write_text('{"dependencies": {"a": "^1"}}')
    before = digest()
    (tmp_path / "src.js").write_text("x\n")
    assert digest() == before, "an unrelated file must not invalidate the cache"
    (tmp_path / "package-lock.json").write_text("{}")
    assert digest() != before


def test_a_cached_scan_sees_a_new_lockfile(tmp_path):
    from arbiter.engine import run_scan as scan
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "^1"}}')
    cache = tmp_path.parent / f"{tmp_path.name}-cache.json"
    cfg = dict(load_config(None))

    def hits():
        rep = scan([str(tmp_path)], cfg, only=["supply_chain"], use_adapters=False,
                   cache_path=str(cache))
        return [f for f in rep.active() if f.rule_id == "arbiter/supply.unpinned-npm-dep"]

    assert hits()
    (tmp_path / "package-lock.json").write_text("{}")
    assert hits() == []
