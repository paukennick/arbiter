"""Globstar path matching for house rules (ARB-147).

`fnmatch` is not a path matcher: its `*` crosses `/`, so `src/**/*.py` is
`src/*.py` with extra steps and misses nothing -- except that `**/*` written
as "every file" then fails to match a file at the root, because fnmatch's
`**/` insists on a slash. Forbid-policies built on either pattern were
false-clean on exactly the files they named. On Windows, `fnmatch.fnmatch`
also folds case, so the same rule matched different files on a developer's
machine and in Linux CI.

The semantics here are the ones every shell and `.gitignore` reader agrees
on, and they hold on every OS:

* `*` matches any run of characters within one path segment; `?` one;
* `[...]` is a character class;
* `**` as a whole segment matches zero or more segments (`a/**/b` matches
  `a/b`, `a/x/b`, `a/x/y/b`; `**/x` matches `x` at any depth, the root
  included; `x/**` matches everything under `x`; `**` alone matches
  everything);
* matching is against the whole repo-relative path, case-sensitively;
  a leading `./` on the pattern is ignored.

A pattern with no `/` is matched against the whole path too, so `*.py`
means the root's `.py` files -- `**/*.py` is "any depth", as it is
everywhere else.
"""
from __future__ import annotations

import re
from functools import lru_cache

_SEGMENT = r"[^/]*"


@lru_cache(maxsize=1024)
def _compile(pattern: str) -> "re.Pattern[str]":
    pat = pattern.replace("\\", "/")
    while pat.startswith("./"):
        pat = pat[2:]
    parts = pat.split("/")
    out: list[str] = []
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part == "**":
            # Zero or more whole segments; `(?:.*/)?` when something follows,
            # `.*` at the end so `x/**` takes everything under `x`.
            out.append(".*" if last else "(?:.*/)?")
            continue
        out.append(_segment_regex(part) + ("" if last else "/"))
    return re.compile("^" + "".join(out) + "$")


def _segment_regex(seg: str) -> str:
    buf: list[str] = []
    i = 0
    while i < len(seg):
        ch = seg[i]
        if ch == "*":
            buf.append(_SEGMENT)
        elif ch == "?":
            buf.append("[^/]")
        elif ch == "[":
            j = seg.find("]", i + 1)
            if j == -1:
                buf.append(re.escape(ch))
            else:
                body = seg[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                buf.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            buf.append(re.escape(ch))
        i += 1
    return "".join(buf)


def match(path: str, pattern: str) -> bool:
    """Whether `path` (repo-relative, `/`-separated) matches the globstar
    `pattern`. Case-sensitive on every OS."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return _compile(pattern).match(path) is not None


def any_match(path: str, patterns) -> bool:
    return any(match(path, p) for p in patterns)
