"""Shipped per-language rule packs: structural checks for every IDE language.

## Why

Most native checks were written for Python first. The languages an interview
workspace (and most services) actually use -- TypeScript/JavaScript, Go, Java,
Ruby, Python -- each get a pack here, so a race, a missing timeout or an
injection is caught the same way whichever language the code is in.

## Packs

One YAML file per pack under `packs/rules/ast/` (`python.yaml`,
`typescript.yaml`, `go.yaml`, `java.yaml`, `ruby.yaml`). Each pack becomes its
own probe, `lang_<pack>`, so a grammar this machine lacks shows up as that one
language not assessed rather than as a clean pass.

```yaml
pack: go                    # rule ids become arbiter/go.<id>
languages: [go]             # inventory language names this pack reads
rules:
  - id: http-no-timeout
    title: "`http.Get` uses the default client, which never times out"
    severity: medium         # info | low | medium | high | critical
    confidence: medium       # low | medium | high
    dimension: quality       # quality | security | ...
    cwe: [CWE-400]
    controls: [NIST-800-218:PW.5]
    tags: [timeout]
    roles: [source]          # inventory roles to read; default [source]
    files: "*.[jt]sx"        # only files whose repo-relative path matches this
                             # fnmatch glob (`*` also crosses `/`), or any glob
                             # of a list: [config/environments/production.rb,
                             # "*/config/environments/production.rb"]
    query: |                 # tree-sitter query; @hit marks the finding
      (call_expression function: (selector_expression) @fn
        (#match? @fn "^http\\.(Get|Post|Head)$")) @hit
    # Optional context conditions, each a tree-sitter query:
    unless_inside: "..."     # skip a hit enclosed by any capture of this query
    unless_in_scope: "..."   # skip a hit whose enclosing function (or file) matches this
    requires_in_scope: "..." # only report a hit whose enclosing function (or file) matches this
    unless_in_file: "..."    # skip every hit when the file matches this
    requires_file: "..."     # only report in a file that matches this
    requirements: [ARB-062]  # the requirement(s) it was built or fixed under
    tier: advisory           # verified | advisory (rule_meta.py, docs/precision.md)
    # Python and Ruby: skip a string-building hit when every value spliced
    # into it is safe (see _splices_safe, _rb_splices_safe). Each is a
    # regex, full-matched:
    safe_splice_calls: "..." # callee of a call whose result is safe (`quote_name`);
                             # in Ruby the method name (`quote_table_name`)
    safe_splice_names: "..." # a name or attribute that is safe (`TABLE`, `inner_sql`)
    # Ruby only:
    safe_splice_text: "..."  # searched in an interpolation's source (`#{...}`):
                             # a match makes it safe (the query's own exclusion)
    safe_splice_values: "..." # full-matched against a value or a local's
                             # assigned value (`query_value("PRAGMA x")`)
    description: "..."
    remediation: "..."
```

`{text}` in a title is replaced by the hit's source text (one line, 60
characters). Evidence is `<id>:<normalised hit text>`, which keeps a finding's
fingerprint stable across line shifts.
"""
from __future__ import annotations

import fnmatch
import re
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING

from .core import Finding, Location

if TYPE_CHECKING:  # annotation only: probes imports this module to register the packs
    from .probes import ProbeContext

# The same directory as `probes.PACKS / "rules" / "ast"`, spelled out here so
# this module never imports `probes` at load time. `probes` imports this module
# at its end to register the packs, so a top-level import back made
# `import arbiter.lang_rules` (before `arbiter.probes`) a circular ImportError
# (ARB-078). `register_lang_rules` imports `probes` lazily, when it runs.
AST_PACKS = Path(__file__).parent / "packs" / "rules" / "ast"

# Node types that bound a function body, for `unless_in_scope`.
FUNCTION_TYPES: dict[str, set[str]] = {
    "python": {"function_definition", "lambda"},
    "javascript": {"function_declaration", "function_expression", "arrow_function",
                   "method_definition", "generator_function_declaration", "function"},
    "typescript": {"function_declaration", "function_expression", "arrow_function",
                   "method_definition", "generator_function_declaration", "function"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "java": {"method_declaration", "constructor_declaration", "lambda_expression"},
    "ruby": {"method", "singleton_method", "lambda"},
}

_KEYS = {"id", "title", "severity", "confidence", "dimension", "cwe", "controls", "tags",
         "roles", "files", "query", "unless_inside", "unless_in_scope", "unless_in_file",
         "requires_file", "requires_in_scope", "description", "remediation", "languages",
         "safe_splice_calls", "safe_splice_names", "safe_splice_text", "safe_splice_values", "taint",
         # Not detection logic: traceability and precision (rule_meta.py).
         "requirements", "tier", "precision_ref"}
# Keys of a rule's `taint:` block (Milestone 3, see dataflow.py).
_TAINT_KEYS = {"mode", "sources", "sinks", "sanitizers", "value", "where", "types", "hops", "requires", "built",
               "unless_element", "at", "inputs", "kill", "element0"}
TAINT_QUERY_KEYS = ("sources", "sinks", "sanitizers", "inputs")
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_CONFIDENCES = {"low", "medium", "high"}


class PackError(ValueError):
    """A pack that does not match the schema above. Raised at load time so a
    broken pack fails the test suite instead of silently checking nothing."""


def validate_pack(data: dict, name: str) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise PackError(f"{name}: expected a mapping with a `rules` list")
    if not data.get("languages"):
        raise PackError(f"{name}: `languages` is required")
    seen: set[str] = set()
    for i, rule in enumerate(data["rules"]):
        where = f"{name} rule {i} ({rule.get('id', '?')})"
        if not isinstance(rule, dict):
            raise PackError(f"{where}: not a mapping")
        unknown = set(rule) - _KEYS
        if unknown:
            raise PackError(f"{where}: unknown keys {sorted(unknown)}")
        for key in ("id", "title", "query", "remediation"):
            if not rule.get(key):
                raise PackError(f"{where}: `{key}` is required")
        if rule["id"] in seen:
            raise PackError(f"{where}: duplicate id")
        seen.add(rule["id"])
        from .rule_meta import RuleMetaError, validate_meta
        try:
            validate_meta(rule, where)
        except RuleMetaError as exc:
            raise PackError(str(exc)) from exc
        if rule.get("severity", "medium") not in _SEVERITIES:
            raise PackError(f"{where}: bad severity")
        if rule.get("confidence", "medium") not in _CONFIDENCES:
            raise PackError(f"{where}: bad confidence")
        for cwe in rule.get("cwe") or []:
            if not str(cwe).startswith("CWE-"):
                raise PackError(f"{where}: cwe entries look like CWE-89, got {cwe!r}")
        files = rule.get("files")
        if files is not None and not (
                (isinstance(files, str) and files)
                or (isinstance(files, list) and files
                    and all(isinstance(g, str) and g for g in files))):
            raise PackError(f"{where}: `files` is a glob or a non-empty list of globs")
        if "@hit" not in rule["query"]:
            raise PackError(f"{where}: query must capture @hit")
        if "taint" in rule:
            _validate_taint(rule["taint"], where)
        for key in ("safe_splice_calls", "safe_splice_names", "safe_splice_text", "safe_splice_values"):
            if key not in rule:
                continue
            langs = set(rule.get("languages") or data["languages"])
            if key in ("safe_splice_text", "safe_splice_values") and langs != {"ruby"}:
                raise PackError(f"{where}: `{key}` is implemented for Ruby only")
            if len(langs) != 1 or not langs <= {"python", "ruby"}:
                raise PackError(f"{where}: `{key}` is implemented for Python and Ruby only")
            try:
                re.compile(rule[key])
            except (re.error, TypeError) as exc:
                raise PackError(f"{where}: `{key}` is not a regex: {exc}") from exc


def _validate_taint(spec, where: str) -> None:
    if not isinstance(spec, dict):
        raise PackError(f"{where}: `taint` is a mapping")
    unknown = set(spec) - _TAINT_KEYS
    if unknown:
        raise PackError(f"{where}: unknown taint keys {sorted(unknown)}")
    mode = spec.get("mode", "source")
    if mode not in ("source", "nonconst"):
        raise PackError(f"{where}: taint `mode` is source or nonconst")
    sinks = spec.get("sinks")
    if sinks is None and not spec.get("value"):
        raise PackError(f"{where}: taint needs `sinks` (a query capturing @sink and @hit) or `value`")
    if sinks is not None and (not isinstance(sinks, str) or "@sink" not in sinks or "@hit" not in sinks):
        raise PackError(f"{where}: taint `sinks` is a query capturing @sink and @hit")
    if sinks is not None and mode == "source" and not any(
            isinstance(spec.get(k), str) and f"@{c}" in spec[k] for k, c in (("sources", "source"),
                                                                           ("inputs", "input"))):
        raise PackError(f"{where}: taint mode `source` needs a `sources` query capturing @source")
    if spec.get("inputs") is not None and not (isinstance(spec["inputs"], str) and "@input" in spec["inputs"]):
        raise PackError(f"{where}: taint `inputs` is a query capturing @input")
    if spec.get("kill", "clean") not in ("clean", "derived"):
        raise PackError(f"{where}: taint `kill` is clean or derived")
    if spec.get("kill") == "derived" and not spec.get("inputs"):
        raise PackError(f"{where}: taint `kill: derived` needs `inputs`")
    if spec.get("sanitizers") is not None and not (
            isinstance(spec["sanitizers"], str) and "@sanitizer" in spec["sanitizers"]):
        raise PackError(f"{where}: taint `sanitizers` is a query capturing @sanitizer")
    value = spec.get("value", [])
    if not (isinstance(value, list) and all(isinstance(v, str) and v for v in value)):
        raise PackError(f"{where}: taint `value` is a list of capture names of `query`")
    for key in ("where", "types"):
        m = spec.get(key, {})
        if not isinstance(m, dict):
            raise PackError(f"{where}: taint `{key}` maps a capture name to a regex")
        for cap, rx in m.items():
            try:
                re.compile(rx)
            except (re.error, TypeError) as exc:
                raise PackError(f"{where}: taint `{key}.{cap}` is not a regex: {exc}") from exc
    if spec.get("at", "sink") not in ("sink", "source"):
        raise PackError(f"{where}: taint `at` is sink or source")
    for key in ("unless_element", "element0"):
        if key in spec:
            try:
                re.compile(spec[key])
            except (re.error, TypeError) as exc:
                raise PackError(f"{where}: taint `{key}` is not a regex: {exc}") from exc
    hops = spec.get("hops", 1)
    if not isinstance(hops, int) or isinstance(hops, bool) or not 0 <= hops <= 2:
        raise PackError(f"{where}: taint `hops` is 0, 1 or 2")
    for key in ("requires", "built"):
        if not isinstance(spec.get(key, False), bool):
            raise PackError(f"{where}: taint `{key}` is true or false")


QUERY_KEYS = ("query", "unless_inside", "unless_in_scope", "unless_in_file", "requires_file",
              "requires_in_scope")


# File names standing in for each grammar a language can be parsed with, so a
# rule narrowed by `files:` is compiled only for the grammars it can meet: the
# JSX rules are `files: "*.[jt]sx"` because plain typescript has no JSX nodes.
_SAMPLE_FILES = {
    "typescript": ("a.ts", "a.mts", "a.cts", "a.tsx"),
    "javascript": ("a.js", "a.mjs", "a.cjs", "a.jsx"),
}


def _grammars(rule: dict, languages) -> set[str]:
    from . import ast as ts
    out: set[str] = set()
    for lang in languages:
        samples = _SAMPLE_FILES.get(lang)
        if not samples:
            if ts.ts_name(lang):
                out.add(ts.ts_name(lang))
            continue
        for sample in samples:
            if not _path_selected(rule, sample):
                continue
            g = ts.grammar_for(sample, lang)
            if g:
                out.add(g)
    return out


def compile_pack(data: dict, name: str) -> None:
    """Compile every query in a pack against every grammar it will run on.

    A query that does not compile used to surface only mid-scan, as the whole
    `lang_<pack>` probe erroring out: a `#` comment inside a `|` query block
    took the Go planted score from 41/41 to 4/41 with nothing pointing at the
    rule. Raised as a PackError, like a schema error, naming pack, rule and
    reason. Grammars this machine has not cached are skipped (never
    downloaded); that language is then reported as not assessed anyway.
    """
    from . import ast as ts
    if not ts.available():
        return
    cached = ts.cached_grammars()
    for i, rule in enumerate(data["rules"]):
        for grammar in sorted(_grammars(rule, rule.get("languages") or data["languages"]) & cached):
            queries = [(k, rule[k]) for k in QUERY_KEYS if rule.get(k)]
            queries += [(f"taint.{k}", rule["taint"][k]) for k in TAINT_QUERY_KEYS
                        if rule.get("taint") and rule["taint"].get(k)]
            for key, q in queries:
                try:
                    ts.compile_query(grammar, q)
                except ValueError as exc:
                    raise PackError(
                        f"{name} rule {i} ({rule['id']}): `{key}` does not compile "
                        f"for {grammar}: {exc}") from exc


def _compiled_stamp(text: str) -> Path:
    """Where a successful compile of this exact pack text is remembered.

    Compiling every query costs ~4s (the Ruby pack alone ~2s), too much to
    pay on every import. A stamp keyed on the pack's bytes, the tree-sitter
    versions and the cached grammars means the cost is paid once per pack
    edit or upgrade; a broken pack is never stamped, so it fails every load.
    """
    import hashlib
    from importlib import metadata

    from . import ast as ts
    try:
        versions = [metadata.version(d) for d in ("tree-sitter", "tree-sitter-language-pack")]
    except metadata.PackageNotFoundError:
        versions = ["?"]
    key = hashlib.sha256("\0".join(
        [text, *versions, *sorted(ts.cached_grammars())]).encode()).hexdigest()
    return _stamp_dir() / key


def _stamp_dir() -> Path:
    import os
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "arbiter" / "compiled-packs"


@cache
def load_packs() -> dict[str, dict]:
    import yaml
    out: dict[str, dict] = {}
    if not AST_PACKS.is_dir():
        return out
    for path in sorted(AST_PACKS.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        name = data.get("pack") or path.stem
        validate_pack(data, path.name)
        stamp = _compiled_stamp(text)
        if not stamp.exists():
            compile_pack(data, path.name)
            try:
                stamp.parent.mkdir(parents=True, exist_ok=True)
                stamp.touch()
            except OSError:
                pass  # unwritable cache: compile again next load, still correct
        out[name] = data
    return out


def _encloses(outer, inner) -> bool:
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


def _file_globs(rule: dict) -> list[str]:
    files = rule.get("files")
    if not files:
        return []
    return [files] if isinstance(files, str) else list(files)


def _path_selected(rule: dict, path: str) -> bool:
    """True when the rule has no `files:` or `path` matches one of its globs."""
    globs = _file_globs(rule)
    return not globs or any(fnmatch.fnmatch(path, g) for g in globs)


def _enclosing_function(node, language: str):
    types = FUNCTION_TYPES.get(language, set())
    cur = node.parent
    while cur is not None:
        if cur.type in types:
            return cur
        cur = cur.parent
    return None


def _matches(language: str, query: str, parsed) -> list:
    from . import ast as ts
    return [c["node"] for c in ts.run_query(language, query, parsed)]


def _snippet(text: str, limit: int) -> str:
    return " ".join(text.split())[:limit]


def run_pack(pack: str, ctx: ProbeContext) -> list[Finding]:
    from . import ast as ts

    data = load_packs()[pack]
    languages = set(data["languages"])
    out: list[Finding] = []
    for f in ctx.inventory.text_files():
        if f.language not in languages:
            continue
        parsed = None
        for rule in data["rules"]:
            if f.role not in (rule.get("roles") or ["source"]):
                continue
            if rule.get("languages") and f.language not in rule["languages"]:
                continue
            if not _path_selected(rule, f.path):
                continue
            if parsed is None:
                parsed = ts.parse_file(f.abspath, f.language)
                if parsed is None:
                    break
            out.extend(_run_rule(pack, rule, f, parsed))
    return out


def _run_rule(pack: str, rule: dict, f, parsed) -> list[Finding]:
    from . import ast as ts
    lang = f.language
    taint = rule.get("taint")
    try:
        if rule.get("unless_in_file") and _matches(lang, rule["unless_in_file"], parsed):
            return []
        file_ok = not rule.get("requires_file") or bool(_matches(lang, rule["requires_file"], parsed))
        if not file_ok and not (taint and not taint.get("requires")):
            return []
        caps = ts.run_query(lang, rule["query"], parsed) if file_ok else []
        hits = [c for c in caps if c["capture"] == "hit"]
        if not hits and not taint:
            return []
        inside = _matches(lang, rule["unless_inside"], parsed) if rule.get("unless_inside") else []
        scoped = _matches(lang, rule["unless_in_scope"], parsed) if rule.get("unless_in_scope") else []
        needed = (_matches(lang, rule["requires_in_scope"], parsed)
                  if rule.get("requires_in_scope") else None)
    except ValueError as exc:
        raise RuntimeError(f"rule arbiter/{pack}.{rule['id']}: {exc}") from exc

    def accept(node, use_requires: bool = True, whole_file: bool = False) -> bool:
        if any(_encloses(o, node) for o in inside):
            return False
        if scoped or (needed is not None and use_requires):
            # Outside any function, the file is the scope; so it is for a
            # value that crossed a function on its way (the check may sit
            # in either function, or in a third the value went through).
            scope = (parsed[0].root_node if whole_file else None) \
                or _enclosing_function(node, lang) or parsed[0].root_node
            if any(_encloses(scope, s) for s in scoped):
                return False
            if use_requires and needed is not None and not any(_encloses(scope, s) for s in needed):
                return False
        return True

    kept: list[dict] = []
    seen: set[int] = set()
    for hit in hits:
        node = hit["node"]
        if node.start_byte in seen:
            continue
        seen.add(node.start_byte)
        if (rule.get("safe_splice_calls") or rule.get("safe_splice_names")) \
                and lang == "python" and _splices_safe(node, rule):
            continue
        if not accept(node):
            continue
        kept.append(hit)
    if taint:
        try:
            kept = _taint_pass(rule, lang, parsed, kept, caps, accept)
        except ValueError as exc:
            raise RuntimeError(f"rule arbiter/{pack}.{rule['id']}: {exc}") from exc
    if lang == "ruby" and any(k.startswith("safe_splice_") for k in rule):
        # After the taint pass, which would otherwise report the same call
        # again as a sink of the string's own interpolations.
        kept = [h for h in kept if not _rb_splices_safe(h["node"], rule)]
    return [_finding(pack, rule, f, hit) for hit in kept]


def _finding(pack: str, rule: dict, f, hit: dict) -> Finding:
    text = _snippet(hit["text"], 60)
    return Finding(
        rule_id=f"arbiter/{pack}.{rule['id']}",
        title=rule["title"].replace("{text}", text),
        dimension=rule.get("dimension", "quality"),
        severity=rule.get("severity", "medium"),
        confidence=rule.get("confidence", "medium"),
        repo_id=f.repo_id, probe=f"lang_{pack}",
        location=Location(path=f.path, start_line=hit["start_line"],
                          end_line=hit["end_line"], repo_id=f.repo_id),
        description=rule.get("description", ""),
        remediation=rule["remediation"],
        evidence=f"{rule['id']}:{_snippet(hit['text'], 120)}",
        controls=list(rule.get("controls") or []),
        cwe=list(rule.get("cwe") or []),
        tags=["lang-rule", f.language, *(rule.get("tags") or [])],
    )


# ---------------------------------------------------------------------------
# One-hop data flow (`taint:`), see dataflow.py
# ---------------------------------------------------------------------------

def _hit_dict(node) -> dict:
    return {"capture": "hit", "type": node.type, "start_line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1, "node": node,
            "text": node.text.decode("utf-8", "replace") if node.text is not None else ""}


def _taint_pass(rule: dict, lang: str, parsed, kept: list[dict], caps: list[dict], accept) -> list[dict]:
    """Drop the rule's own hits whose `value` is provably constant, and add
    sink hits the data flow reaches. Returns the new list of hits."""
    try:
        return _taint_hits(rule, lang, parsed, kept, caps, accept)
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - see dataflow.analyse: never lose the rule's own hits
        import os
        if os.environ.get("ARBITER_DATAFLOW_STRICT"):
            raise
        return kept


def _taint_hits(rule: dict, lang: str, parsed, kept: list[dict], caps: list[dict], accept) -> list[dict]:
    from . import ast as ts
    from . import dataflow as df
    spec_cfg = rule["taint"]
    root = parsed[0].root_node
    funcs = FUNCTION_TYPES.get(lang, set())
    spec = df.Spec(mode=spec_cfg.get("mode", "source"), hops=spec_cfg.get("hops", 1))
    where = {k: re.compile(v) for k, v in (spec_cfg.get("where") or {}).items()}
    types = {k: re.compile(v) for k, v in (spec_cfg.get("types") or {}).items()}

    def constraints_ok(match: dict) -> bool:
        for cap, rx in where.items():
            for n in match.get(cap, []):
                if not rx.search(df.static_text(lang, n, funcs)):
                    return False
        for cap, rx in types.items():
            for n in match.get(cap, []):
                if not rx.search(df.declared_type(lang, n, funcs) or ""):
                    return False
        return True

    if spec_cfg.get("sources"):
        for m in ts.run_matches(lang, spec_cfg["sources"], parsed):
            if not constraints_ok(m):
                continue
            for n in m.get("source", []):
                spec.sources.add(df.nkey(n))
                spec.source_params.add(df.span(n))
    input_nodes = []
    if spec_cfg.get("inputs"):
        for m in ts.run_matches(lang, spec_cfg["inputs"], parsed):
            if not constraints_ok(m):
                continue
            for n in m.get("input", []):
                spec.inputs.add(df.nkey(n))
                spec.source_params.add(df.span(n))
                input_nodes.append(n)
    if spec_cfg.get("sanitizers"):
        for m in ts.run_matches(lang, spec_cfg["sanitizers"], parsed):
            for n in m.get("sanitizer", []):
                spec.sanitizers.add(df.nkey(n))

    value_names = set(spec_cfg.get("value") or [])
    kill_vals: dict[int, list] = {i: [] for i in range(len(kept))}
    if value_names and kept:
        # values pair with their hit by match: a declaration's value sits
        # outside the call it reaches (`String sql = ...; execute(sql)`)
        by_hit: dict[tuple, list] = {}
        for m in ts.run_matches(lang, rule["query"], parsed):
            for h in m.get("hit", []):
                vals = [v for name in value_names for v in m.get(name, [])]
                by_hit.setdefault((h.start_byte, h.end_byte), []).extend(vals)
        for i, hit in enumerate(kept):
            node = hit["node"]
            kill_vals[i] = list({df.nkey(v): v for v in by_hit.get((node.start_byte, node.end_byte), [])}.values())
    sinks: list[tuple] = []
    for m in (ts.run_matches(lang, spec_cfg["sinks"], parsed) if spec_cfg.get("sinks") else []):
        if not m.get("hit") or not m.get("sink") or not constraints_ok(m):
            continue
        sinks.append((m["hit"][0], m["sink"]))
    if spec.mode == "source" and not spec.sources and not spec.inputs and not any(kill_vals.values()):
        return kept
    watch = [v for vs in kill_vals.values() for v in vs] + [s for _h, ss in sinks for s in ss]
    if not watch:
        return kept
    seen = df.analyse(lang, root, spec, watch)
    if seen is None:
        return kept
    derived = spec_cfg.get("kill") == "derived"

    def killed(i: int) -> bool:
        vals = kill_vals[i]
        if not vals:
            return False
        kinds = [seen.get(df.nkey(v), df.UNK).kind for v in vals]
        if all(k == df.CLEAN for k in kinds):
            return True
        if derived and all(k <= df.DERIVED for k in kinds):
            # the function reads request input, and none of it gets here
            fn = _enclosing_function(kept[i]["node"], lang)
            return fn is not None and any(_encloses(fn, n) for n in input_nodes)
        return False

    out = [hit for i, hit in enumerate(kept) if not killed(i)]
    lines = {h["start_line"] for h in out}
    reported: set = set()
    starts = {h["node"].start_byte for h in out}
    for hit_node, sink_nodes in sinks:
        avs = [seen.get(df.nkey(s), df.UNK) for s in sink_nodes]
        if spec_cfg.get("built"):
            avs = [a for a in avs if a.built]
        if spec_cfg.get("element0"):
            rx0 = re.compile(spec_cfg["element0"])
            avs = [a for a in avs if a.items and a.items[0] == "list" and a.items[1]
                   and isinstance(a.items[1][0].const, str) and rx0.search(a.items[1][0].const)]
        if spec_cfg.get("unless_element"):
            rx = re.compile(spec_cfg["unless_element"])
            avs = [a for a in avs if not (a.items and a.items[0] == "list" and any(
                isinstance(e.const, str) and rx.search(e.const) for e in a.items[1]))]
        if spec.mode == "source" and spec_cfg.get("sources") and spec_cfg.get("inputs"):
            # with both, a sink must be reached from a `sources` node (the
            # built SQL); `inputs` alone only serve the `kill: derived` check
            src_spans = {(k[0], k[1]) for k in spec.sources}
            bad = [a for a in avs if a.kind == df.TAINT and src_spans & set(a.via)]
        elif spec.mode == "source":
            bad = [a for a in avs if a.kind == df.TAINT]
        else:
            bad = [a for a in avs if a.kind != df.CLEAN]
        if not bad:
            continue
        line = hit_node.start_point[0] + 1
        if hit_node.start_byte in starts or line in lines:
            continue
        via = set().union(*[a.via for a in bad])
        if any(h["node"].start_byte <= s and e <= h["node"].end_byte for h in out for s, e in via):
            continue
        if spec_cfg.get("at") == "source":
            # report where the value was built, when that is in the sink's own
            # function (the convention of the rule's own query)
            fn = _enclosing_function(hit_node, lang)
            srcs = [n for n in df.source_nodes(root, spec, via)
                    if _enclosing_function(n, lang) == fn and n.end_byte <= hit_node.start_byte]
            if srcs:
                hit_node = max(srcs, key=lambda n: n.start_byte)
                line = hit_node.start_point[0] + 1
                if line in lines:
                    continue
        sink_fn = _enclosing_function(hit_node, lang)
        srcs_all = df.source_nodes(root, spec, via)
        crossed = any(_enclosing_function(n, lang) != sink_fn for n in srcs_all) or any(
            not (sink_fn is not None and sink_fn.start_byte <= s0 and e0 <= sink_fn.end_byte)
            for s0, e0 in via)
        if not accept(hit_node, use_requires=bool(spec_cfg.get("requires")), whole_file=crossed):
            continue
        # one finding per source per function: the same value written to
        # three paths is one defect
        sig = (sink_fn.id if sink_fn is not None else None,
               frozenset((n.start_byte, n.end_byte) for n in srcs_all) or None)
        if sig[1] is not None and sig in reported:
            continue
        reported.add(sig)
        out.append(_hit_dict(hit_node))
        lines.add(line)
        starts.add(hit_node.start_byte)
    return out


# ---------------------------------------------------------------------------
# Python: values spliced into a built string, and whether each is safe
# ---------------------------------------------------------------------------
#
# Simple in-function constant tracking, for `python.sql-injection` (round 2,
# ARB-065). Django's cache backend writes `table = quote_name(self._table)`
# and then `"DELETE FROM %s" % table`; celery builds `col_name =
# preparer.quote_identifier(col.name)` before an f-string. A spliced value is
# safe when it is a literal, a call to a quoting function, a safe name (by
# the rule's regex), `str()` of a safe value, a `sep.join(...)` of safe
# elements, a conditional or string-format of safe values, or a local
# variable every assignment of which in the enclosing function is safe.
# A parameter, a loop variable, anything assigned from elsewhere, and any
# expression not listed are not. Round 3 (ARB-164, below) widens what
# counts as bound safely; it is still not data flow across files.

_LITERALS = {"integer", "float", "true", "false", "none"}


def _txt(node) -> str:
    return node.text.decode("utf-8", "replace") if node.text is not None else ""


def _splices(node) -> list | None:
    """The values spliced into a string-building expression; None if unknown."""
    t = node.type
    if t == "string":
        return [c.named_children[0] for c in node.named_children
                if c.type == "interpolation" and c.named_children]
    if t == "concatenated_string":
        out: list = []
        for c in node.named_children:
            out.extend(_splices(c) or [])
        return out
    if t == "parenthesized_expression" and node.named_children:
        inner = node.named_children[0]
        return _splices(inner) if inner.type in ("string", "concatenated_string",
                                                 "binary_operator", "call") else [inner]
    if t == "binary_operator":
        op = node.child_by_field_name("operator")
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if op is None or left is None or right is None:
            return None
        if _txt(op) == "%" and left.type in ("string", "concatenated_string"):
            values = _splices(left) or []
            if right.type == "tuple":
                return values + list(right.named_children)
            if right.type == "dictionary":
                return values + [p.child_by_field_name("value") for p in right.named_children
                                 if p.type == "pair"]
            return values + [right]
        if _txt(op) == "+":
            out = []
            for side in (left, right):
                inner = _splices(side) if side.type in ("string", "concatenated_string") \
                    or (side.type == "binary_operator" and _txt(side.child_by_field_name("operator")) == "+") \
                    else [side]
                if inner is None:
                    return None
                out.extend(inner)
            return out
        return None
    if t == "call":
        fn, args = node.child_by_field_name("function"), node.child_by_field_name("arguments")
        if fn is not None and fn.type == "attribute" and args is not None:
            obj, attr = fn.child_by_field_name("object"), fn.child_by_field_name("attribute")
            if attr is not None and _txt(attr) == "format" and obj is not None \
                    and obj.type in ("string", "concatenated_string"):
                out = list(_splices(obj) or [])
                for a in args.named_children:
                    if a.type == "keyword_argument":
                        out.append(a.child_by_field_name("value"))
                    else:
                        out.append(a)
                return out
    return None


# Round 3 (ARB-164): the values a statement splices are followed to where
# they are bound, in the whole file. On 45 real applications nine in ten
# findings spliced only the program's own constants: a table named in a
# module-level `_TABLE = "x"`, a loop over a literal list of tables, a
# `policy_name("scope")` helper that formats its argument, a WHERE clause
# grown from literal fragments with `+=`, a `"?"` placeholder list. A name
# is resolved the way Python does -- comprehension, enclosing functions,
# module -- and is safe when every binding of it is: an assignment or `+=`
# of a safe value, a `for` over a constant collection, a container filled
# (`append`, `extend`, `x[k] = v`) only with safe values. A call to a
# function defined in the same file is followed one or two hops: it is safe
# when every value it returns is, given which of its arguments are. A
# parameter of the function holding the statement, an attribute (`self.x`),
# an import, a `with`/`except` binding and any call this cannot see into
# stay unsafe, so whatever arrives from a caller is still reported.

_SCOPES = ("function_definition", "lambda")
_COMPREHENSIONS = ("generator_expression", "list_comprehension", "set_comprehension",
                   "dictionary_comprehension")
# Calls whose result carries no text of the caller's choosing.
_INT_CALLS = {"len", "int", "float", "bool", "round", "abs", "hash", "ord", "id"}
# Calls whose result is safe when every argument is.
_PURE_CALLS = {"str", "repr", "min", "max", "sorted", "reversed", "list", "tuple", "set",
               "frozenset", "enumerate", "zip", "sum", "dict", "range", "chr", "format"}
# String methods whose result is safe when the receiver and arguments are.
_PURE_METHODS = {"join", "format", "replace", "lower", "upper", "strip", "lstrip", "rstrip",
                 "title", "capitalize", "casefold", "removeprefix", "removesuffix", "ljust",
                 "rjust", "center", "zfill", "split", "rsplit", "splitlines", "encode",
                 "decode", "items", "keys", "values", "get", "copy", "format_map", "partition"}
# Methods that put a value into a container; anything else done with a
# container-bound name (passing it to a call, a slice assignment) makes it unsafe.
_FILL_METHODS = {"append", "extend", "insert", "add", "update", "setdefault", "appendleft"}
_READ_METHODS = {"copy", "count", "index", "get", "items", "keys", "values", "pop",
                 "popleft", "remove", "discard", "clear", "sort", "reverse"}
_PASS_OK = {"len", "join", "list", "tuple", "sorted", "reversed", "set", "frozenset",
            "enumerate", "zip", "any", "all", "bool", "str", "repr", "isinstance", "print",
            "min", "max", "sum", "iter", "next"}
_STEP_BUDGET = 4000
_MAX_HOPS = 2


def _target_names(node) -> set[str]:
    """Identifiers bound by an assignment or loop target (`a`, `a, (b, c)`)."""
    if node is None:
        return set()
    if node.type == "identifier":
        return {_txt(node)}
    if node.type in ("pattern_list", "tuple_pattern", "list_pattern", "tuple", "list",
                     "parenthesized_expression", "list_splat_pattern"):
        out: set[str] = set()
        for c in node.named_children:
            out |= _target_names(c)
        return out
    return set()


def _param_names(fn) -> dict:
    """Parameter name -> its default value node; None when it has none,
    "splat" for `*args` / `**kw`."""
    out: dict = {}
    params = fn.child_by_field_name("parameters")
    for p in (params.named_children if params is not None else []):
        if p.type == "identifier":
            out[_txt(p)] = None
        elif p.type in ("default_parameter", "typed_default_parameter"):
            n = p.child_by_field_name("name")
            if n is not None:
                out[_txt(n)] = p.child_by_field_name("value")
        elif p.type == "typed_parameter":
            for c in p.named_children:
                if c.type == "identifier":
                    out[_txt(c)] = None
                    break
                if c.type in ("list_splat_pattern", "dictionary_splat_pattern"):
                    for n in c.named_children:
                        out[_txt(n)] = "splat"
                    break
        elif p.type in ("list_splat_pattern", "dictionary_splat_pattern"):
            for n in p.named_children:
                out[_txt(n)] = "splat"
    return out


_CONTAINER_CALLS = {"list", "dict", "set", "deque", "collections.deque", "defaultdict",
                    "collections.defaultdict", "OrderedDict", "collections.OrderedDict"}


class _PyConst:
    """Whether a spliced Python value is provably the program's own constant.
    One instance per hit, over the hit's whole file."""

    def __init__(self, rule: dict, root):
        self.calls = rule.get("safe_splice_calls")
        self.names = rule.get("safe_splice_names")
        self.root = root
        self.steps = 0
        self.visiting: set = set()
        self.memo: dict = {}
        self.assumed = 0
        self._all_defs: list | None = None

    # -- where a name is bound ---------------------------------------------

    def _bindings(self, scope, name: str) -> list | None:
        """(kind, node) for every binding of `name` directly in `scope` (a
        function or the module; nested functions, classes, lambdas and
        comprehensions are their own scopes). None when it is bound in a way
        that is never safe: import, `with ... as`, `except ... as`, a def."""
        body = scope.child_by_field_name("body") if scope.type in _SCOPES else scope
        out: list = []
        stack = [body] if body is not None else []
        while stack:
            n = stack.pop()
            t = n.type
            if t in ("function_definition", "class_definition"):
                if _txt(n.child_by_field_name("name")) == name:
                    return None
                continue
            if t == "lambda" or t in _COMPREHENSIONS:
                continue
            if t == "assignment":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "identifier" and _txt(left) == name:
                    if right is not None:          # not a bare annotation
                        out.append(("value", right.child_by_field_name("right")
                                    if right.type == "assignment" else right))
                elif left is not None and name in _target_names(left):
                    kids = [c for c in left.named_children] \
                            if left.type in ("pattern_list", "tuple_pattern", "list_pattern") else []
                    at = next((i for i, c in enumerate(kids)
                               if c.type == "identifier" and _txt(c) == name), None)
                    out.append(("unpack", (right, at, len(kids))))
            elif t == "augmented_assignment":
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" and _txt(left) == name:
                    out.append(("value", n.child_by_field_name("right")))
            elif t == "named_expression":
                nm = n.child_by_field_name("name")
                if nm is not None and _txt(nm) == name:
                    out.append(("value", n.child_by_field_name("value")))
            elif t == "for_statement":
                if name in _target_names(n.child_by_field_name("left")):
                    out.append(("loop", n.child_by_field_name("right")))
            elif t in ("with_item", "except_clause"):
                if re.search(rf"\bas\s+\(?\s*{re.escape(name)}\b", _txt(n).split("\n")[0]):
                    return None
            elif t in ("import_statement", "import_from_statement"):
                for c in n.named_children:
                    alias = c.child_by_field_name("alias") if c.type == "aliased_import" else c
                    if alias is not None and _txt(alias).split(".")[0] == name:
                        return None
            stack.extend(n.children)
        return out

    @staticmethod
    def _declares(fn, kind: str, name: str) -> bool:
        stack = [fn.child_by_field_name("body")]
        while stack:
            n = stack.pop()
            if n is None or n.type in ("function_definition", "class_definition", "lambda"):
                continue
            if n.type == kind and any(_txt(c) == name for c in n.named_children):
                return True
            stack.extend(n.children)
        return False

    def _defs(self) -> list:
        if self._all_defs is None:
            out, stack = [], [self.root]
            while stack:
                n = stack.pop()
                if n.type == "function_definition":
                    out.append(n)
                stack.extend(n.children)
            self._all_defs = out
        return self._all_defs

    def _def_named(self, name: str):
        hits = [n for n in self._defs() if _txt(n.child_by_field_name("name")) == name]
        return hits[0] if len(hits) == 1 else None

    def resolve(self, ident):
        """Where `ident` gets its value, the way Python looks it up:
        ('comp', iterable) | ('param', fn) | ('bindings', scope, [...]) |
        ('function', def) | None (unknown, never safe)."""
        name = _txt(ident)
        child, cur = ident, ident.parent
        while cur is not None:
            t = cur.type
            if t in _COMPREHENSIONS:
                for c in cur.named_children:
                    if c.type == "for_in_clause" \
                            and name in _target_names(c.child_by_field_name("left")):
                        return ("comp", c.child_by_field_name("right"))
            elif t in _SCOPES and child.type != "parameters":
                if name in _param_names(cur):
                    return ("param", cur)
                if t == "function_definition":
                    if self._declares(cur, "global_statement", name):
                        break
                    if not self._declares(cur, "nonlocal_statement", name):
                        b = self._bindings(cur, name)
                        if b is None:
                            return None
                        if b:
                            return ("bindings", cur, b)
            child, cur = cur, cur.parent
        # a module binding any function may rebind with `global` is not constant
        if re.search(rf"\bglobal\s+(?:\w+\s*,\s*)*{re.escape(name)}\b", _txt(self.root)):
            return None
        b = self._bindings(self.root, name)
        if b is None:
            fn = self._def_named(name)
            return ("function", fn) if fn is not None else None
        if b:
            return ("bindings", self.root, b)
        return None

    # -- containers ---------------------------------------------------------

    def _fills_safe(self, scope, name: str, env) -> bool:
        """Every use of the container bound to `name` only reads it or puts a
        safe value in it. Handing it to a call this cannot see is unsafe."""
        stack = [scope]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type != "identifier" or _txt(n) != name:
                continue
            p = n.parent
            if p is None:
                continue
            if p.type == "attribute" and p.child_by_field_name("object") == n:
                call = p.parent
                if call is None or call.type != "call" or call.child_by_field_name("function") != p:
                    continue
                attr = _txt(p.child_by_field_name("attribute"))
                if attr in _FILL_METHODS:
                    args = call.child_by_field_name("arguments")
                    vals = [a for a in (args.named_children if args is not None else [])
                            if a.type != "comment"]
                    if attr == "insert":
                        vals = vals[1:]
                    if not all((self.collection_safe(v, env) if attr in ("extend", "update")
                                else self.safe(v, env)) for v in vals):
                        return False
                elif attr not in _READ_METHODS and attr not in _PURE_METHODS:
                    return False
            elif p.type == "subscript" and p.child_by_field_name("value") == n:
                a = p.parent
                if a is not None and a.type in ("assignment", "augmented_assignment") \
                        and a.child_by_field_name("left") == p \
                        and not self.safe(a.child_by_field_name("right"), env):
                    return False
            elif p.type == "argument_list":
                fn = p.parent.child_by_field_name("function") if p.parent is not None else None
                if fn is None or _txt(fn).rsplit(".", 1)[-1] not in _PASS_OK:
                    return False
            elif p.type == "keyword_argument":
                return False
        return True

    # -- values -------------------------------------------------------------

    def _name_safe(self, ident, env) -> bool:
        name = _txt(ident)
        r = self.resolve(ident)
        if r is None or r[0] == "function":
            return False
        if r[0] == "comp":
            return self.collection_safe(r[1], env)
        if r[0] == "param":
            key = (r[1].start_byte, name)
            if env and key in env:
                return env[key]
            return self._allowlisted(r[1], name, ident) or self._callers_safe(r[1], name)
        scope, binds = r[1], r[2]
        key = (scope.start_byte, name, tuple(sorted(env.items())) if env else ())
        if key in self.memo:
            return self.memo[key]
        if key in self.visiting:
            # `where = where + " AND x"`: safe if every other binding is
            self.assumed += 1
            return True
        self.visiting.add(key)
        before = self.assumed
        try:
            ok, container = True, False
            for kind, node in binds:
                if node is None:
                    ok = False
                elif kind == "loop":
                    ok = self.collection_safe(node, env)
                elif kind == "unpack":
                    ok = self._unpacked_safe(*node, env)
                else:
                    if node.type in ("list", "dictionary", "set") or node.type in _COMPREHENSIONS \
                            or (node.type == "call"
                                and _txt(node.child_by_field_name("function")) in _CONTAINER_CALLS):
                        container = True
                    ok = self.safe(node, env)
                if not ok:
                    break
            if ok and container:
                ok = self._fills_safe(scope, name, env)
        finally:
            self.visiting.discard(key)
        if not ok or self.assumed == before:
            self.memo[key] = ok
        return ok

    def _unpacked_safe(self, right, at, width: int, env) -> bool:
        """`a, b = right`: the value `a` takes. A tuple literal, or a same-file
        helper whose every return is a tuple, is checked position by
        position; anything else must be safe as a whole."""
        if right is None:
            return False
        if at is not None and right.type in ("expression_list", "tuple", "list") \
                and len(right.named_children) == width:
            return self.safe(right.named_children[at], env)
        if at is not None and right.type == "call":
            fn = right.child_by_field_name("function")
            target = None
            if fn is not None and fn.type == "identifier":
                r = self.resolve(fn)
                target = r[1] if r is not None and r[0] == "function" else None
            elif fn is not None and fn.type == "attribute":
                obj = fn.child_by_field_name("object")
                if obj is not None and _txt(obj) in ("self", "cls"):
                    target = self._method_named(right, _txt(fn.child_by_field_name("attribute")))
            if target is not None:
                args = right.child_by_field_name("arguments")
                argv = [a for a in (args.named_children if args is not None else [])
                        if a.type != "comment"]
                return self._helper_safe(target, argv, env, 0,
                                         method=fn.type == "attribute", pick=(at, width))
        return self.collection_safe(right, env)

    def _allowlisted(self, fn, name: str, use) -> bool:
        """`if sort_by not in self.SORTABLE_COLUMNS: sort_by = "id"` (or
        `raise` / `return`) at the top level of the function, before the
        use, and no other rebinding: whatever reaches the use is one of the
        allowlist's constants. The check may lower/upper/strip the value."""
        body = fn.child_by_field_name("body")
        guarded = False
        for st in (body.named_children if body is not None else []):
            if st.start_byte >= use.start_byte:
                break
            if st.type != "if_statement":
                continue
            cond = st.child_by_field_name("condition")
            if cond is None or cond.type != "comparison_operator" or len(cond.named_children) != 2 \
                    or not re.search(r"\bnot\s+in\b", _txt(cond)):
                continue
            left, right = cond.named_children
            if not re.fullmatch(rf"{re.escape(name)}(?:\.(?:lower|upper|strip|casefold)\(\))?",
                                _txt(left)):
                continue
            if not self.collection_safe(right, None):
                continue
            cons = st.child_by_field_name("consequence")
            stmts = [c for c in (cons.named_children if cons is not None else []) if c.type != "comment"]
            if stmts and all(self._fixes(c, name) for c in stmts) \
                    and any(c.type in ("raise_statement", "return_statement", "assignment")
                            for c in stmts):
                guarded = True
        if not guarded:
            return False
        binds = self._bindings(fn, name)
        return binds is not None and all(k == "value" and self.safe(v, None, 1) for k, v in binds)

    def _fixes(self, stmt, name: str) -> bool:
        """A statement in an allowlist guard's body: leave, log, or set the
        value to a constant."""
        if stmt.type in ("raise_statement", "return_statement", "pass_statement"):
            return True
        e = stmt     # the grammar has no expression_statement wrapper
        if e.type == "assignment":
            return _txt(e.child_by_field_name("left")) == name \
                    and self.safe(e.child_by_field_name("right"), None, 1)
        return e.type == "call"

    def _callers_safe(self, fn, name: str) -> bool:
        """A parameter of a module-private function (`_create_policy`) or of
        one nested in another is safe when the function is only ever called
        in this file, at least once, and every call passes a safe value.
        A public function can be called from anywhere, so its parameters
        stay unsafe."""
        fname = _txt(fn.child_by_field_name("name")) if fn.type == "function_definition" else ""
        nested = fn.parent is not None and fn.parent.type == "block" \
                and fn.parent.parent is not None and fn.parent.parent.type == "function_definition"
        if not fname or not (fname.startswith("_") and not fname.startswith("__") or nested):
            return False
        params = list(_param_names(fn).items())
        idx = next((i for i, (p, _) in enumerate(params) if p == name), None)
        if idx is None or params[idx][1] == "splat":
            return False
        method = fn.parent is not None and fn.parent.parent is not None \
                and fn.parent.parent.type == "class_definition"
        if method:
            return False        # `self._helper(x)` callers are not resolved by name
        key = ("callers", fn.start_byte, name)
        if key in self.memo:
            return self.memo[key]
        if key in self.visiting:
            return False
        self.visiting.add(key)
        try:
            ok = self._each_call_passes_safe(fn, fname, name, idx, params[idx][1])
        finally:
            self.visiting.discard(key)
        self.memo[key] = ok
        return ok

    def _each_call_passes_safe(self, fn, fname: str, name: str, idx: int, default) -> bool:
        calls = 0
        stack = [self.root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type != "identifier" or _txt(n) != fname or n == fn.child_by_field_name("name"):
                continue
            p = n.parent
            if p is None or p.type != "call" or p.child_by_field_name("function") != n:
                return False        # handed on as a callback: callers unknown
            if self.resolve(n) != ("function", fn):
                continue            # a different binding of the same name
            calls += 1
            args = p.child_by_field_name("arguments")
            argv = [a for a in (args.named_children if args is not None else [])
                    if a.type != "comment"]
            if any(a.type in ("list_splat", "dictionary_splat") for a in argv):
                return False
            positional = [a for a in argv if a.type != "keyword_argument"]
            kw = {_txt(a.child_by_field_name("name")): a.child_by_field_name("value")
                  for a in argv if a.type == "keyword_argument"}
            if idx < len(positional):
                val = positional[idx]
            elif name in kw:
                val = kw[name]
            elif default is not None:
                val = default
            else:
                return False
            if not self.safe(val, None, 1):
                return False
        return calls > 0

    def collection_safe(self, node, env) -> bool:
        """Every element a loop over `node` can yield is safe."""
        if node is None:
            return False
        if node.type == "call":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            argv = [a for a in (args.named_children if args is not None else [])
                    if a.type not in ("comment", "keyword_argument")]
            fname = _txt(fn) if fn is not None else ""
            if fname == "range":
                return True
            if fname in ("reversed", "sorted", "enumerate", "zip", "list", "tuple", "set",
                         "frozenset", "iter") and argv:
                return all(self.collection_safe(a, env) for a in argv)
            if fn is not None and fn.type == "attribute" and not argv \
                    and _txt(fn.child_by_field_name("attribute")) in ("items", "keys", "values", "copy"):
                return self.collection_safe(fn.child_by_field_name("object"), env)
        return self.safe(node, env)

    def safe(self, node, env=None, hops: int = 0) -> bool:
        if node is None:
            return False
        self.steps += 1
        if self.steps > _STEP_BUDGET:
            return False
        t = node.type
        if t in _LITERALS:
            return True
        if t in ("string", "concatenated_string"):
            parts = _splices(node)
            return parts is not None and all(self.safe(p, env, hops) for p in parts)
        if t == "binary_operator":
            parts = _splices(node)
            if parts is None:
                # arithmetic on safe values (`a * 2`) stays safe
                return self.safe(node.child_by_field_name("left"), env, hops) \
                    and self.safe(node.child_by_field_name("right"), env, hops)
            return all(self.safe(p, env, hops) for p in parts)
        if t in ("comparison_operator", "not_operator"):
            return True         # a bool
        if t in ("unary_operator", "boolean_operator"):
            return all(self.safe(c, env, hops) for c in node.named_children)
        if t == "parenthesized_expression":
            return bool(node.named_children) and self.safe(node.named_children[0], env, hops)
        if t == "conditional_expression":
            kids = node.named_children
            return len(kids) == 3 and self.safe(kids[0], env, hops) and self.safe(kids[2], env, hops)
        if t in ("list", "tuple", "set", "expression_list"):
            return all(self.safe(k, env, hops) for k in node.named_children if k.type != "comment")
        if t == "dictionary":
            for p in node.named_children:
                if p.type == "pair":
                    if not (self.safe(p.child_by_field_name("key"), env, hops)
                            and self.safe(p.child_by_field_name("value"), env, hops)):
                        return False
                elif p.type == "dictionary_splat":
                    if not self.safe(p, env, hops):
                        return False
                elif p.type != "comment":
                    return False
            return True
        if t in ("list_splat", "dictionary_splat"):
            return bool(node.named_children) and self.collection_safe(node.named_children[0], env)
        if t in _COMPREHENSIONS:
            body = node.child_by_field_name("body")
            if body is not None and body.type == "pair":
                return self.safe(body.child_by_field_name("key"), env, hops) \
                    and self.safe(body.child_by_field_name("value"), env, hops)
            return self.safe(body, env, hops)
        if t == "subscript":
            # an element of a constant container is constant, whatever the key
            return self.collection_safe(node.child_by_field_name("value"), env)
        if t in ("identifier", "attribute"):
            if self.names and re.fullmatch(self.names, _txt(node)):
                # an ALL_CAPS name is trusted by convention (it may be
                # imported), unless this file shows it changing: a
                # `global` rebinding, or a container handed to a call
                return t == "attribute" or self._convention_holds(node, env)
            return t == "identifier" and self._name_safe(node, env)
        if t == "call":
            return self._call_safe(node, env, hops)
        if t == "keyword_argument":
            return self.safe(node.child_by_field_name("value"), env, hops)
        return False

    def _convention_holds(self, ident, env) -> bool:
        name = _txt(ident)
        if re.search(rf"\bglobal\s+(?:\w+\s*,\s*)*{re.escape(name)}\b", _txt(self.root)):
            return False
        r = self.resolve(ident)
        if r is None or r[0] != "bindings":
            return True
        scope, binds = r[1], r[2]
        if any(n is not None and (n.type in ("list", "dictionary", "set") or n.type in _COMPREHENSIONS
                                  or n.type == "call"
                                  and _txt(n.child_by_field_name("function")) in _CONTAINER_CALLS)
               for k, n in binds if k == "value"):
            return self._fills_safe(self.root, name, env)
        return True

    def _call_safe(self, node, env, hops: int) -> bool:
        fn, args = node.child_by_field_name("function"), node.child_by_field_name("arguments")
        if fn is None:
            return False
        callee = _txt(fn)
        if self.calls and re.fullmatch(self.calls, callee):
            return True
        if callee in _INT_CALLS:
            return True
        if args is not None and args.type == "generator_expression":
            argv = [args]       # `", ".join(q(c) for c in cols)`: no argument list
        else:
            argv = [a for a in (args.named_children if args is not None else [])
                    if a.type != "comment"]
        if callee in _PURE_CALLS:
            return all(self.safe(a, env, hops) for a in argv)
        if fn.type == "attribute":
            obj, attr = fn.child_by_field_name("object"), fn.child_by_field_name("attribute")
            a = _txt(attr) if attr is not None else ""
            if a == "join" and len(argv) == 1:
                arg = argv[0]
                if arg.type == "binary_operator" and _txt(arg.child_by_field_name("operator")) == "*":
                    # `", ".join(["%s"] * len(keys))`: a placeholder list
                    return self.safe(obj, env, hops) \
                        and self.safe(arg.child_by_field_name("left"), env, hops)
                return self.safe(obj, env, hops) and self.collection_safe(arg, env)
            if a == "get" and argv and obj is not None:
                # `{"read": "read_at"}.get(event)`: one of the mapping's own
                # values or the default, whatever the key
                return self.collection_safe(obj, env) and all(self.safe(x, env, hops) for x in argv[1:])
            if a in _PURE_METHODS:
                return self.safe(obj, env, hops) and all(self.safe(x, env, hops) for x in argv)
            if obj is not None and obj.type == "identifier" and _txt(obj) in ("self", "cls"):
                target = self._method_named(node, a)
                if target is not None:
                    return self._helper_safe(target, argv, env, hops, method=True)
            return False
        if fn.type == "identifier":
            r = self.resolve(fn)
            if r is not None and r[0] == "function":
                return self._helper_safe(r[1], argv, env, hops)
        return False

    @staticmethod
    def _method_named(node, name: str):
        cur = node.parent
        while cur is not None and cur.type != "class_definition":
            cur = cur.parent
        body = cur.child_by_field_name("body") if cur is not None else None
        found = []
        for c in (body.named_children if body is not None else []):
            d = c.child_by_field_name("definition") if c.type == "decorated_definition" else c
            if d is not None and d.type == "function_definition" \
                    and _txt(d.child_by_field_name("name")) == name:
                found.append(d)
        return found[0] if len(found) == 1 else None

    def _helper_safe(self, fn, argv, env, hops: int, method: bool = False,
                     pick: tuple | None = None) -> bool:
        """A same-file function's result, given which arguments are safe:
        safe when every value it returns is."""
        if hops >= _MAX_HOPS or any(a.type in ("list_splat", "dictionary_splat") for a in argv):
            return False
        params = list(_param_names(fn).items())
        if method and params and params[0][0] in ("self", "cls"):
            params = params[1:]
        positional = [a for a in argv if a.type != "keyword_argument"]
        keywords = {_txt(a.child_by_field_name("name")): a.child_by_field_name("value")
                    for a in argv if a.type == "keyword_argument"}
        bound: dict = {}
        for i, (pname, default) in enumerate(params):
            if default == "splat":
                ok = False
            elif i < len(positional):
                ok = self.safe(positional[i], env, hops)
            elif pname in keywords:
                ok = self.safe(keywords[pname], env, hops)
            else:
                ok = default is not None and self.safe(default, None, hops)
            bound[(fn.start_byte, pname)] = ok
        returns, stack = [], [fn.child_by_field_name("body")]
        while stack:
            n = stack.pop()
            if n is None or n.type in ("function_definition", "class_definition", "lambda"):
                continue
            if n.type == "yield":
                return False
            if n.type == "return_statement":
                returns.append(n.named_children[0] if n.named_children else None)
                continue
            stack.extend(n.children)
        if not returns:
            return False
        if pick is not None:
            at, width = pick
            vals = []
            for r in returns:
                if r is None or r.type not in ("expression_list", "tuple") \
                        or len(r.named_children) != width:
                    return False
                vals.append(r.named_children[at])
            returns = vals
        return all(r is None or self.safe(r, bound, hops + 1) for r in returns)


def _whole_build(node):
    """The whole string-building expression a hit belongs to. The query
    anchors on the SQL-shaped literal, so in `"ALTER TABLE " + str(a) + " TO "
    + str(b)` the hit is only the innermost `"ALTER TABLE " + str(a)`; the
    values spliced further out must be judged too."""
    cur = node
    while cur.parent is not None:
        p = cur.parent
        if p.type == "parenthesized_expression":
            cur = p
            continue
        if p.type == "binary_operator" and p.child_by_field_name("operator") is not None \
                and _txt(p.child_by_field_name("operator")) in ("+", "%") \
                and p.child_by_field_name("left") == cur:
            cur = p
            continue
        break
    return cur


def _splices_safe(hit, rule: dict) -> bool:
    parts = _splices(_whole_build(hit))
    if not parts:
        return False
    root = hit
    while root.parent is not None:
        root = root.parent
    pc = _PyConst(rule, root)
    return all(pc.safe(p) for p in parts)


def register_lang_rules() -> None:
    from . import ast as ts
    from .probes import Probe, register
    for pack, data in load_packs().items():
        grammars = sorted({g for lang in data["languages"] for g in [ts.ts_name(lang)] if g}
                          | ({"tsx"} if "typescript" in data["languages"] else set()))
        register(Probe(
            name=f"lang_{pack}",
            scope="file",
            dimensions=sorted({r.get("dimension", "quality") for r in data["rules"]}) or ["quality"],
            checks=max(1, len(data["rules"])),
            stacks=list(data["languages"]),
            modules=["tree_sitter_language_pack"],
            grammars=grammars,
            run=lambda ctx, _pack=pack: run_pack(_pack, ctx),
            cacheable=True,
        ))


def pack_path(pack: str) -> Path:
    return AST_PACKS / f"{pack}.yaml"


# ---------------------------------------------------------------------------
# Source no pack reads (ARB-144)
# ---------------------------------------------------------------------------
#
# Inventory languages that are not programming languages: configuration,
# markup, data and infrastructure, each read by probes of its own (the
# resource rules, the secrets probe, the drift probes). A file in any other
# recognised language is source that a rule pack should have read.
NON_PROGRAMMING_LANGUAGES = frozenset({
    "yaml", "json", "toml", "ini", "dotenv", "markdown", "rst", "html", "css",
    "sql", "terraform", "hcl", "dockerfile", "unknown",
})
UNASSESSED_PROBE = "lang_unsupported"
# The outcome that stands for files the walk saw and did not read (ARB-150).
FILES_NOT_READ_PROBE = "files_not_read"
_FALLBACK_PACK_LANGUAGES = frozenset({"python", "javascript", "typescript", "go", "java", "ruby"})
_FALLBACK_CHECKS_PER_LANGUAGE = 30


def pack_languages() -> set[str]:
    """Every inventory language some shipped pack reads."""
    try:
        return {lang for d in load_packs().values() for lang in d["languages"]}
    except Exception:  # noqa: BLE001 - a broken pack fails elsewhere; the mapping must still answer
        return set(_FALLBACK_PACK_LANGUAGES)


def _checks_per_language() -> int:
    """What one missing pack would have contributed to the coverage
    denominator: the mean size of the packs that exist."""
    try:
        sizes = [len(d["rules"]) for d in load_packs().values()]
    except Exception:  # noqa: BLE001 - see pack_languages
        sizes = []
    return max(1, round(sum(sizes) / len(sizes))) if sizes else _FALLBACK_CHECKS_PER_LANGUAGE


def unassessed_languages(inv) -> dict[str, dict]:
    """Programming languages present in the source that no pack reads, each
    with its file count, line count and share of all source lines, largest
    first. Source means roles `source` and `test`; generated code, docs,
    configuration and data are not counted on either side."""
    supported = pack_languages()
    total = 0
    found: dict[str, dict] = {}
    for f in inv.files:
        if f.binary or f.role not in ("source", "test") or f.language in NON_PROGRAMMING_LANGUAGES:
            continue
        total += f.lines
        if f.language in supported:
            continue
        cell = found.setdefault(f.language, {"files": 0, "lines": 0, "share": 0.0})
        cell["files"] += 1
        cell["lines"] += f.lines
    for cell in found.values():
        cell["share"] = round(cell["lines"] / total, 4) if total else 0.0
    return dict(sorted(found.items(), key=lambda kv: (-kv[1]["lines"], kv[0])))


def not_assessed_outcome(inv):
    """A `skipped` outcome naming the languages no pack reads, sized as the
    packs they lack would have been, so they count against coverage the way
    an uninstalled analyzer does. None when every source language has a
    pack."""
    from .core import ProbeOutcome
    found = unassessed_languages(inv)
    if not found:
        return None
    files = sum(c["files"] for c in found.values())
    lines = sum(c["lines"] for c in found.values())
    share = sum(c["share"] for c in found.values())
    return ProbeOutcome(
        name=UNASSESSED_PROBE, status="skipped",
        reason=(f"no rule pack for {', '.join(found)}: {files} source file(s), "
                f"{lines:,} line(s), {share:.0%} of source lines not assessed"),
        dimensions=["security", "quality"],
        checks=_checks_per_language() * len(found),
        applicable=True,
    )


def files_not_read_outcome(inv):
    """A `skipped` outcome for the source-like files the walk did not read
    (a NUL byte, over the size cap, UTF-16 without a mark, a link out of
    the tree; inventory.walk_repo), sized as one rule pack so the gap
    counts against coverage. None when every source-like file was read.
    Directories the walk never enters are reported, not counted: what is
    vendored stays vendored (ARB-150)."""
    from .core import ProbeOutcome
    from .inventory import Inventory
    whole: Inventory = inv.whole or inv
    named = whole.skipped_source_like()
    if not named:
        return None
    by_reason: dict[str, int] = {}
    for s in named:
        by_reason[s["reason"]] = by_reason.get(s["reason"], 0) + 1
    reasons = "; ".join(f"{n} {r}" for r, n in
                        sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0])))
    return ProbeOutcome(
        name=FILES_NOT_READ_PROBE, status="skipped",
        reason=(f"{len(named)} source-like file(s) were not read "
                f"({whole.skipped_source_share():.0%} of source-like files): {reasons}"),
        dimensions=["security", "quality"],
        checks=_checks_per_language(),
        applicable=True,
    )


# ---------------------------------------------------------------------------
# Ruby: the same question for an interpolated string argument
# ---------------------------------------------------------------------------
#
# `ruby.sql-injection` (round 4): every one of its gold findings labelled
# `v3` was a false positive, and eight of them interpolate only values that
# cannot carry outside data: a literal picked by a condition (`#{enforced ?
# 'ENFORCED' : 'NOT ENFORCED'}`, `#{' IF EXISTS' if if_exists}`) beside
# `quote_table_name(...)`, or a PRAGMA setting read back from the database
# a few lines earlier (`old = query_value("PRAGMA foreign_keys")`, then
# `execute("PRAGMA foreign_keys = #{old}")`). A call whose first argument is
# a string is skipped when every interpolation in it is safe: its source
# matches `safe_splice_text`, or its value is a literal, a constant, a
# conditional of safe values, a call `safe_splice_calls` names, a value
# `safe_splice_values` matches, or a local every assignment of which in the
# enclosing method is safe. A parameter, a block or loop variable, an
# instance variable and a bare name never assigned (a method call) are not.

_RB_LITERALS = {"integer", "float", "true", "false", "nil", "simple_symbol", "constant",
                "string_content", "escape_sequence"}
_RB_SCOPES = {"method", "singleton_method", "class", "module", "program"}


def _rb_scope(node):
    cur = node.parent
    while cur is not None and cur.type not in _RB_SCOPES:
        cur = cur.parent
    return cur


def _rb_assignments(scope, name: str) -> list | None:
    """Right-hand sides assigned to local `name` in this method; None when it
    is a parameter, a block or loop variable, or bound some other way."""
    word = re.compile(rf"(?<![\w@$:.]){re.escape(name)}(?![\w?!])")
    params = scope.child_by_field_name("parameters")
    if params is not None and word.search(_txt(params)):
        return None
    out: list = []
    stack = list(scope.named_children)
    while stack:
        n = stack.pop()
        if n.type in ("method", "singleton_method", "class", "module"):
            continue
        if n.type in ("block_parameters", "lambda_parameters", "exception_variable",
                      "left_assignment_list", "for"):
            target = n.child_by_field_name("pattern") if n.type == "for" else n
            if target is not None and word.search(_txt(target)):
                return None
        if n.type in ("assignment", "operator_assignment"):
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier" and _txt(left) == name:
                if right is None:
                    return None
                out.append(right)
        stack.extend(n.named_children)
    return out


def _rb_value_safe(node, rule: dict, scope, depth: int = 0) -> bool:
    if node is None or depth > 4:
        return False
    t = node.type
    values = rule.get("safe_splice_values")
    if values and re.fullmatch(values, _txt(node)):
        return True
    if t in _RB_LITERALS:
        return True
    if t == "string":
        return all(c.type in _RB_LITERALS or
                   (c.type == "interpolation" and _rb_interpolation_safe(c, rule, scope, depth + 1))
                   for c in node.named_children)
    if t == "parenthesized_statements":
        kids = [k for k in node.named_children if k.type != "comment"]
        return len(kids) == 1 and _rb_value_safe(kids[0], rule, scope, depth + 1)
    if t == "conditional":
        return _rb_value_safe(node.child_by_field_name("consequence"), rule, scope, depth + 1) \
            and _rb_value_safe(node.child_by_field_name("alternative"), rule, scope, depth + 1)
    if t in ("if_modifier", "unless_modifier"):
        return _rb_value_safe(node.child_by_field_name("body"), rule, scope, depth + 1)
    if t == "call":
        calls = rule.get("safe_splice_calls")
        m = node.child_by_field_name("method")
        return bool(calls and m is not None and re.fullmatch(calls, _txt(m)))
    if t == "identifier":
        names = rule.get("safe_splice_names")
        if names and re.fullmatch(names, _txt(node)):
            return True
        if scope is None:
            return False
        rhs = _rb_assignments(scope, _txt(node))
        return bool(rhs) and all(_rb_value_safe(r, rule, scope, depth + 1) for r in rhs)
    return False


def _rb_interpolation_safe(interp, rule: dict, scope, depth: int = 0) -> bool:
    text_rx = rule.get("safe_splice_text")
    if text_rx and re.search(text_rx, _txt(interp)):
        return True
    kids = [k for k in interp.named_children if k.type != "comment"]
    return len(kids) == 1 and _rb_value_safe(kids[0], rule, scope, depth)


def _rb_splices_safe(hit, rule: dict) -> bool:
    """A call whose first argument is a string every interpolation of which
    is safe. Anything else (a heredoc, a local, a concatenation) is not
    judged here and keeps its finding."""
    if hit.type != "call":
        return False
    args = hit.child_by_field_name("arguments")
    first = next((a for a in (args.named_children if args is not None else []) if a.type != "comment"), None)
    if first is None or first.type != "string":
        return False
    interps = [c for c in first.named_children if c.type == "interpolation"]
    if not interps:
        return False
    scope = _rb_scope(hit)
    return all(_rb_interpolation_safe(i, rule, scope) for i in interps)
