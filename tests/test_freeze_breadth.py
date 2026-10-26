"""The breadth-set freeze (tools/freeze_breadth.py, ARB-166): its filters run on
fixture metadata here, with no network. The Python configuration must stay the
one the committed Python breadth set was frozen with (ARB-163)."""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import urllib.parse

import pytest
from helpers import ROOT


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


FB = _load("freeze_breadth")
L = FB.LANGS


def _item(**kw) -> dict:
    it = {"full_name": "acme/app", "license": {"spdx_id": "MIT"}, "size": 1000,
          "description": "A self-hosted photo server", "is_template": False,
          "archived": False, "fork": False}
    it.update(kw)
    return it


# --- metadata screen -------------------------------------------------------

def test_metadata_accepts_an_application():
    assert FB.metadata_reason(_item(), set(), L["go"]) is None


@pytest.mark.parametrize("kw, prior, want", [
    ({}, {"acme/app"}, "used before"),
    ({"is_template": True}, set(), "template"),
    ({"archived": True}, set(), "archived"),
    ({"fork": True}, set(), "fork"),
    ({"license": {"spdx_id": "NOASSERTION"}}, set(), "licence"),
    ({"license": None}, set(), "licence"),
    ({"size": 400_001}, set(), "size"),
    ({"description": "Go SDK for the Acme API"}, set(), "library"),
    ({"description": "Ruby bindings to libfoo"}, set(), "library"),
    ({"description": "A boilerplate for Express apps"}, set(), "tutorial"),
    ({"description": "Header-only HTTP server"}, set(), "tutorial"),
])
def test_metadata_rejections(kw, prior, want):
    assert want in FB.metadata_reason(_item(**kw), prior, L["javascript"])


def test_size_limit_is_inclusive():
    assert FB.metadata_reason(_item(size=400_000), set(), L["java"]) is None


def test_python_keeps_its_original_filters():
    # The not-an-application words were added for ARB-166; the frozen Python
    # set was screened without them.
    assert FB.metadata_reason(_item(description="A boilerplate"), set(), L["python"]) is None


# --- language share --------------------------------------------------------

def test_share_needs_sixty_percent():
    assert FB.share_reason({"Go": 60, "HTML": 40}, L["go"])[0] is None
    why, share = FB.share_reason({"Go": 59, "HTML": 41}, L["go"])
    assert "< 60%" in why and share == pytest.approx(0.59)


def test_javascript_caps_typescript_below_ten_percent():
    js = L["javascript"]
    assert FB.share_reason({"JavaScript": 91, "TypeScript": 9}, js)[0] is None
    assert "TypeScript" in FB.share_reason({"JavaScript": 90, "TypeScript": 10}, js)[0]
    assert "JavaScript" in FB.share_reason({"JavaScript": 55, "TypeScript": 5, "CSS": 40}, js)[0]


def test_typescript_has_no_javascript_cap():
    assert FB.share_reason({"TypeScript": 60, "JavaScript": 40}, L["typescript"])[0] is None


def test_cpp_share_counts_cpp_not_c():
    assert FB.share_reason({"C++": 70, "C": 30}, L["cpp"])[0] is None
    assert FB.share_reason({"C++": 70, "C": 30}, L["c"])[0] is not None


def test_empty_language_counts_reject():
    assert FB.share_reason({}, L["ruby"])[0] is not None


# --- file-name tree --------------------------------------------------------

def _tree(*paths, truncated=False):
    return {"tree": [{"path": p} for p in paths], "truncated": truncated}


def test_tree_accepts_clean_paths_with_workflows():
    assert FB.tree_reason(_tree("src/main.go", ".github/workflows/ci.yml")) is None


@pytest.mark.parametrize("bad", ["docs/what?.md", "a/b:c", "aux.c", "src/CON", "dir./x",
                                 "trailing /x", 'q"uote', "pipe|x", "back\\slash"])
def test_tree_rejects_paths_windows_cannot_check_out(bad):
    assert "Windows" in FB.tree_reason(_tree(bad, ".github/workflows/ci.yml"))


def test_tree_rejects_a_truncated_tree():
    assert "truncated" in FB.tree_reason(_tree(".github/workflows/ci.yml", truncated=True))


def test_tree_requires_workflows():
    assert "workflows" in FB.tree_reason(_tree("src/main.c", ".github/dependabot.yml"))


# --- query, names, split ---------------------------------------------------

def test_cpp_query_is_encoded():
    q = FB.search_query(L["cpp"], "daemon", 1000)
    assert "C%2B%2B" in q and "+" not in q
    assert urllib.parse.unquote(q).split()[1] == "language:C++"
    assert "stars:>=1000" in q and "pushed:>=2026-08-26" in q


def test_lower_star_floor_reaches_the_query():
    assert "stars:>=300" in FB.search_query(L["ruby"], "rails", 300)


def test_name_collision_adds_the_owner():
    js = L["javascript"]
    assert FB.name_for(js, "Acme/App", set()) == "js-app"
    assert FB.name_for(js, "Other/App", {"js-app"}) == "js-other-app"


def test_split_is_seeded_and_keeps_every_repo():
    kept = [{"github": f"o{i}/r{i}"} for i in range(120)]
    a = FB.split([dict(r) for r in kept], L["go"], 30, 20261026)
    b = FB.split([dict(r) for r in kept], L["go"], 30, 20261026)
    assert a == b and len(a) == 120
    assert sum(r["slice"] == "dev" for r in a.values()) == 30
    dup = FB.split([{"github": "a/x"}, {"github": "b/x"}], L["go"], 1, 1)
    assert set(dup) == {"go-x", "go-b-x"}


def test_about_records_the_star_floor_and_seeds():
    text = FB.about(L["ruby"], 300, 30, 20261026)
    assert ">= 300 stars" in text and "seed 20261026" in text and "seed 20261027" in text


# --- Python unchanged ------------------------------------------------------

def test_python_config_matches_the_frozen_script():
    """Constants of the script the Python set was frozen with (commit ce7a346)."""
    old = subprocess.run(["git", "-C", str(ROOT), "show", "ce7a346:tools/freeze_breadth_python.py"],
                         capture_output=True, text=True, encoding="utf-8")
    if old.returncode:
        pytest.skip("base commit not in this clone")
    src = old.stdout
    topics = re.search(r"APP_TOPICS = \[(.*?)\]", src, re.S).group(1)
    py = L["python"]
    assert list(py.topics) == re.findall(r'"([^"]+)"', topics)
    assert py.min_stars == int(re.search(r"MIN_STARS = (\d+)", src).group(1))
    assert FB.SEED == int(re.search(r"SEED = (\d+)", src).group(1))
    assert FB.PUSHED_SINCE == re.search(r'PUSHED_SINCE = "([^"]+)"', src).group(1)
    assert FB.MAX_SIZE_KB == int(re.search(r"MAX_SIZE_KB = ([\d_]+)", src).group(1).replace("_", ""))
    assert (py.total, py.dev, py.prefix) == (180, 45, "py")
    assert FB.LIBRARY_WORDS.pattern in src


def test_python_manifest_is_never_overwritten():
    assert FB.main(["--language", "python", "--out",
                    str(ROOT / "tools" / "gold" / "breadth-r7-python-repos.json")]) == 2


# --- fetch scripts ---------------------------------------------------------

def test_heldout_script_lists_only_heldout_in_get_pinned_form():
    gb = _load("gold_benchmark")
    manifest = {"repos": {
        "go-a": {"url": "https://github.com/o/a.git", "sha": "a" * 40, "slice": "heldout"},
        "go-b": {"url": "https://github.com/o/b.git", "sha": "b" * 40, "slice": "dev"},
    }}
    slice_sh, heldout_sh = FB.fetch_scripts(L["go"], manifest)
    pins = gb.parse_pins(heldout_sh)
    assert [(p.name, p.language) for p in pins] == [("go-a", "go")]
    assert "breadth-r7-go-repos.json" in slice_sh and "corpus-r7go-breadth" in slice_sh
    assert heldout_sh.count("{") == heldout_sh.count("}")
    assert "fi\n}" in heldout_sh


# --- application screen (ARB-166) -----------------------------------------

@pytest.mark.parametrize("topic", ["library", "npm-package", "react-components", "vite-plugin",
                                   "go-library", "template", "awesome-list", "react-hooks"])
def test_library_topics_reject(topic):
    why = FB.metadata_reason(_item(topics=["self-hosted", topic]), set(), L["typescript"])
    assert why and topic in why


def test_application_topics_pass():
    assert FB.metadata_reason(_item(topics=["self-hosted", "docker", "dashboard"]), set(),
                              L["typescript"]) is None


def test_python_ignores_topics():
    assert FB.metadata_reason(_item(topics=["library"]), set(), L["python"]) is None


@pytest.mark.parametrize("marker", ["Dockerfile", "deploy/docker-compose.prod.yml", "compose.yaml",
                                    "Procfile", "fly.toml", "contrib/systemd/app.service",
                                    "electron-builder.yml", "src-tauri/tauri.conf.json",
                                    "platformio.ini", "sdkconfig.defaults", "debian/control",
                                    "man/tool.1", "doc/man/tool.8.in"])
def test_deployment_marker_is_recognised(marker):
    assert FB.tree_reason(_tree("src/x", ".github/workflows/ci.yml", marker), need_marker=True) is None


def test_a_repo_without_a_marker_is_rejected_only_when_asked():
    t = _tree("src/index.js", "package.json", "README.md", ".github/workflows/ci.yml")
    assert "deployment marker" in FB.tree_reason(t, need_marker=True)
    assert FB.tree_reason(t) is None


def test_scripts_pick_an_interpreter_that_runs():
    slice_sh, _ = FB.fetch_scripts(L["go"], {"repos": {}})
    assert "command -v python3 ||" not in slice_sh
    assert "for c in python3 python" in slice_sh
