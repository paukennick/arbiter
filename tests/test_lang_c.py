"""The C/C++ pack (ARB-161): detection, function boundaries and the rules.

The planted pairs in fixtures/planted/{c,cpp} are scored by
tests/test_planted_corpus.py. These tests pin each rule's catch beside the
lookalike it must stay silent on, so removing a rule, or loosening one until
its lookalike fires, fails here with the shape named.
"""
from __future__ import annotations

import textwrap

import pytest

from arbiter import ast as ts
from arbiter.engine import run_scan
from arbiter.inventory import RepoInfo, build_inventory
from arbiter.lang_rules import load_packs
from arbiter.policy import load_config

needs_c = pytest.mark.skipif(
    not ts.available() or not {"c", "cpp"} <= ts.cached_grammars(),
    reason="tree-sitter or the c/cpp grammars not available")


def _write(root, files: dict[str, str]) -> None:
    for name, code in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")


def _scan(tmp_path, files: dict[str, str]):
    _write(tmp_path, files)
    return run_scan([str(tmp_path)], load_config(None), only=["lang_c"],
                    use_adapters=False, use_cache=False)


def _rules(tmp_path, code: str, name: str = "app.c") -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for f in _scan(tmp_path, {name: code}).active():
        out.setdefault(f.rule_id.split(".")[-1], []).append(f.location.start_line)
    return out


def _inventory(tmp_path, files: dict[str, str]):
    _write(tmp_path, files)
    return build_inventory([RepoInfo(id="root", path=str(tmp_path))])


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("marker", ["Makefile", "meson.build", "configure.ac", "main.c", "api.h"])
def test_the_c_stack_is_detected(tmp_path, marker):
    assert "c" in _inventory(tmp_path, {marker: "x\n"}).stacks


@pytest.mark.parametrize("ext", [".hxx", ".c++", ".ipp", ".inl", ".cc", ".hpp"])
def test_cpp_extensions_map_to_cpp(tmp_path, ext):
    inv = _inventory(tmp_path, {f"a{ext}": "int x;\n"})
    assert [f.language for f in inv.files] == ["cpp"]


def test_a_header_is_c_in_a_c_repo_and_cpp_beside_cpp_sources(tmp_path):
    c_only = _inventory(tmp_path / "c", {"api.h": "int f(void);\n", "api.c": "int f(void) { return 0; }\n"})
    assert {f.path: f.language for f in c_only.files} == {"api.h": "c", "api.c": "c"}
    mixed = _inventory(tmp_path / "cpp", {"include/api.h": "class A {};\n", "src/a.cpp": "int g() { return 0; }\n"})
    assert {f.path: f.language for f in mixed.files} == {"include/api.h": "cpp", "src/a.cpp": "cpp"}


@needs_c
def test_a_makefile_alone_does_not_run_the_pack(tmp_path):
    # A Makefile marks the c stack in a Python repository too; the pack must
    # not then read as having assessed C and found it clean.
    rep = _scan(tmp_path, {"Makefile": "all:\n\tpython app.py\n", "app.py": "x = 1\n"})
    outcome = next(o for o in rep.probes if o.name == "lang_c")
    assert outcome.status != "ran" and not outcome.applicable
    rep = _scan(tmp_path / "with_c", {"Makefile": "all:\n", "a.c": "int main(void) { return 0; }\n"})
    assert next(o for o in rep.probes if o.name == "lang_c").status == "ran"


# ---------------------------------------------------------------------------
# Function boundaries
# ---------------------------------------------------------------------------

@needs_c
def test_cpp_functions_include_qualified_templates_operators_and_destructors(tmp_path):
    src = tmp_path / "a.cpp"
    src.write_text(textwrap.dedent('''
        template <class T> T Foo<T>::bar(int x) const { return x; }
        Foo::~Foo() {}
        bool Foo::operator==(const Foo& o) const { return true; }
        struct S { void m() {} S& operator=(const S& o) { return *this; } ~S() {} };
        int* make() { return 0; }
        const std::string& name(int a) { return s; }
        template <typename T> T maxof(T a, T b) { return a > b ? a : b; }
        Foo::Foo(int x) : x_(x) {}
    ''').lstrip(), encoding="utf-8")
    got = [(f.start_line, f.name) for f in ts.functions(str(src), "cpp")]
    assert got == [(1, "Foo<T>::bar"), (2, "Foo::~Foo"), (3, "Foo::operator=="), (4, "m"),
                   (4, "operator="), (4, "~S"), (5, "make"), (6, "name"), (7, "maxof"),
                   (8, "Foo::Foo")]


@needs_c
def test_c_functions_include_pointer_returning_ones(tmp_path):
    src = tmp_path / "a.c"
    src.write_text("char *dup(const char *s) { return 0; }\nstatic char **argvv(void) { return 0; }\n"
                   "int main(void) { return 0; }\n", encoding="utf-8")
    assert [f.name for f in ts.functions(str(src), "c")] == ["dup", "argvv", "main"]


# ---------------------------------------------------------------------------
# The pack
# ---------------------------------------------------------------------------

def test_pack_reads_c_and_cpp_and_declares_a_cwe_on_every_rule():
    pack = load_packs()["c"]
    assert pack["languages"] == ["c", "cpp"]
    assert {r["id"] for r in pack["rules"]} == {
        "gets-call", "unbounded-copy", "command-injection", "format-string", "insecure-random-secret"}
    assert all(r.get("cwe") and r.get("remediation") and r.get("description") for r in pack["rules"])


@needs_c
def test_gets_is_reported_and_fgets_and_a_method_named_gets_are_not(tmp_path):
    code = '''
    #include <stdio.h>
    void f(char *b, int n, struct reader *r) {
        gets(b);
        fgets(b, n, stdin);
        r->gets(b);
    }
    '''
    assert _rules(tmp_path, code).get("gets-call") == [3]


@needs_c
def test_unbounded_copies_are_reported_and_bounded_ones_are_not(tmp_path):
    code = '''
    #include <stdio.h>
    #include <string.h>
    void f(char *d, size_t n, const char *s) {
        strcpy(d, s);
        strcat(d, s);
        sprintf(d, "%s", s);
        strncpy(d, s, n);
        snprintf(d, n, "%s", s);
        strncat(d, s, n);
    }
    '''
    assert _rules(tmp_path, code).get("unbounded-copy") == [4, 5, 6]


@needs_c
def test_a_shell_command_from_a_variable_is_reported_and_constant_ones_are_not(tmp_path):
    code = '''
    #include <stdio.h>
    #include <stdlib.h>
    #define CLEAR "clear"
    int f(const char *host) {
        char cmd[256];
        snprintf(cmd, sizeof cmd, "ping %s", host);
        system(cmd);
        popen(host, "r");
        system("ls -l");
        system(CLEAR);
        system(NULL);
        const char *fixed = "date";
        system(fixed);
        int rc = system(fixed);
        if (system(fixed) != 0)
            return rc;
        return 0;
    }
    '''
    assert _rules(tmp_path, code).get("command-injection") == [7, 8]


@needs_c
def test_cpp_std_system_on_a_built_string_is_reported(tmp_path):
    code = '''
    #include <cstdlib>
    #include <string>
    int run(const std::string& host) {
        std::string cmd = "ping " + host;
        std::system("uptime");
        return std::system(cmd.c_str());
    }
    '''
    assert _rules(tmp_path, code, "run.cpp").get("command-injection") == [6]


@needs_c
def test_a_non_literal_format_is_reported_in_each_position(tmp_path):
    code = '''
    #include <stdio.h>
    #include <syslog.h>
    void f(char *b, size_t n, const char *msg) {
        printf(msg);
        fprintf(stderr, msg);
        syslog(LOG_ERR, msg);
        snprintf(b, n, msg);
        printf("%s", msg);
        fprintf(stderr, "%s\\n", msg);
        syslog(LOG_ERR, "%s", msg);
        snprintf(b, n, "%s", msg);
    }
    '''
    assert _rules(tmp_path, code).get("format-string") == [4, 5, 6, 7]


@needs_c
def test_constant_formats_and_printf_wrappers_are_silent(tmp_path):
    code = '''
    #include <stdarg.h>
    #include <stdio.h>
    #define FMT "%d\\n"
    void wrap(const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        printf(fmt);
    }
    void f(int n, const char *msg) {
        printf(FMT, n);
        printf(_("hello\\n"));
        printf(n ? "yes\\n" : "no\\n");
        const char *f2 = "%d\\n";
        printf(f2, n);
        if (printf(f2, n) < 0)
            return;
        printf(msg);
    }
    '''
    # Only the last call: the format is a parameter of a non-variadic function.
    assert _rules(tmp_path, code).get("format-string") == [19]


@needs_c
def test_rand_into_a_secret_is_reported_and_into_jitter_is_not(tmp_path):
    code = '''
    #include <stdlib.h>
    void f(char *session_token, int n) {
        int jitter_ms = rand() % 100;
        long nonce = random();
        for (int i = 0; i < n; i++)
            session_token[i] = "abc"[rand() % 3];
        int tokenizer_state = rand();
        int key = rand() % 64;
    }
    '''
    assert _rules(tmp_path, code).get("insecure-random-secret") == [4, 6]


@needs_c
def test_cpp_rand_into_a_camel_case_token_is_reported(tmp_path):
    code = '''
    #include <cstdlib>
    #include <string>
    std::string make() {
        std::string sessionToken;
        for (int i = 0; i < 32; ++i) sessionToken += "abcdef"[std::rand() % 6];
        auto retry_slot = std::rand() % 10;
        return sessionToken;
    }
    '''
    assert _rules(tmp_path, code, "make.cpp").get("insecure-random-secret") == [5]
