#!/usr/bin/env bash
#
# Install the external analyzers Arbiter wraps, at pinned versions.
#
# Why this file exists
# --------------------
# The adapters were written, shipped, and never once run end to end, because
# getting the six tools installed was a manual step nobody had written down.
# When they were finally installed by hand, checkov alone contributed 477
# findings on a single repository -- more than three times everything the
# native probes found.
#
# A missing analyzer is not an error here. Arbiter records it as "not assessed"
# with the binary named, and the coverage figure drops accordingly, which is
# the whole point of the coverage model. So this script reports what it got and
# what it did not, and always exits 0. A failed install must not fail a build;
# it must show up honestly in the next report.
#
# Versions are pinned because an analyzer that changes underneath you changes
# your findings, and Arbiter's determinism guarantee covers its own inputs.
# Bump them deliberately, then re-run tools/calibrate_external.py -- the
# measured severities are keyed to check ids that a new version may add to,
# rename, or drop.
#
# Nothing here is bundled with Arbiter -- each tool is fetched from its own
# upstream (PyPI or a GitHub release) at install time. Redistributing the
# binaries themselves is a separate, unresolved question (docs/licensing.md,
# requirement L-6), so this script stays on the safe side of it: it only ever
# drives the operator's own install of someone else's tool.
#
#   ./tools/install_tools.sh              # everything, no prompts (CI/scripted)
#   ./tools/install_tools.sh checkov      # just one, no prompt
#   ./tools/install_tools.sh -y           # everything, skip the confirm prompt
#
# Run with no arguments at an interactive terminal and it asks which of the
# six to install and then asks you to confirm before touching anything.
# Pass -y/--yes to skip that confirmation (selection by name still works).
#
set -uo pipefail

CATALOG_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/arbiter/tooling.json"
IFS=$'\t' read -r CATALOG_CHECKOV CATALOG_SEMGREP CATALOG_BANDIT CATALOG_RUFF \
  CATALOG_TRIVY CATALOG_GITLEAKS CATALOG_SEMGREP_RULES CATALOG_GRAMMARS < <(
  python3 - "$CATALOG_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    catalog = json.load(source)
versions = {tool["name"]: tool["version"] for tool in catalog["analyzers"]}
print("\t".join([
    versions["checkov"],
    versions["semgrep"],
    versions["bandit"],
    versions["ruff"],
    versions["trivy"],
    versions["gitleaks"],
    catalog["semgrep_rules_ref"],
    " ".join(catalog["tree_sitter"]["default_grammars"]),
]))
PY
)
if [ -z "${CATALOG_CHECKOV:-}" ] || [ -z "${CATALOG_GRAMMARS:-}" ]; then
  echo "Could not read tool versions from $CATALOG_FILE" >&2
  exit 2
fi

CHECKOV_VERSION="${CHECKOV_VERSION:-$CATALOG_CHECKOV}"
SEMGREP_VERSION="${SEMGREP_VERSION:-$CATALOG_SEMGREP}"
BANDIT_VERSION="${BANDIT_VERSION:-$CATALOG_BANDIT}"
RUFF_VERSION="${RUFF_VERSION:-$CATALOG_RUFF}"
TRIVY_VERSION="${TRIVY_VERSION:-$CATALOG_TRIVY}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-$CATALOG_GITLEAKS}"
SEMGREP_RULES_REF="${SEMGREP_RULES_REF:-$CATALOG_SEMGREP_RULES}"
ARBITER_GRAMMARS="${ARBITER_GRAMMARS:-$CATALOG_GRAMMARS}"

# Must match arbiter.adapters.cache_dir() -- the adapter reads the rules from
# here at scan time, so a mismatch here is a silent "config not found" there.
ARBITER_CACHE_DIR="${ARBITER_CACHE_DIR:-$HOME/.cache/arbiter}"
TRIVY_CACHE_DIR="$ARBITER_CACHE_DIR/trivy-cache"

TOOL_LICENSES=(
  "checkov:Apache-2.0"
  "semgrep:LGPL-2.1"
  "bandit:Apache-2.0"
  "ruff:MIT"
  "trivy:Apache-2.0"
  "gitleaks:MIT"
)

YES=0
WANT=()
for arg in "$@"; do
  case "$arg" in
    -y|--yes) YES=1 ;;
    *) WANT+=("$arg") ;;
  esac
done

# No tools named on the command line, run at a real terminal: ask instead of
# silently defaulting to "all five". A script (CI, another script piping in)
# has no terminal on stdin/stdout, so it keeps the old no-args-means-everything
# behaviour and never blocks on a prompt.
if [ ${#WANT[@]} -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
  echo "Which analyzers do you want to install?"
  for entry in "${TOOL_LICENSES[@]}"; do
    printf '  %-10s %s\n' "${entry%%:*}" "${entry##*:}"
  done
  echo
  read -r -p "Enter names separated by spaces, or press enter for all: " SEL
  if [ -n "$SEL" ]; then
    read -r -a WANT <<< "$SEL"
  fi
fi

[ ${#WANT[@]} -eq 0 ] && WANT=(checkov semgrep bandit ruff trivy gitleaks)

wants() { for w in "${WANT[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1; }

if [ "$YES" -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
  echo
  echo "About to install: ${WANT[*]}"
  echo "Each is fetched from its own upstream (pip or a GitHub release);"
  echo "nothing is bundled with or redistributed by Arbiter itself."
  read -r -p "Continue? [Y/n] " CONFIRM
  case "$CONFIRM" in
    [nN]*) echo "Aborted -- nothing installed."; exit 0 ;;
  esac
fi

PIP_FLAGS=""
# Debian's externally-managed marker refuses a plain pip install. In a
# container that is exactly what we want to do anyway.
python3 -c "import sys; sys.exit(0)" 2>/dev/null && \
  pip install --help 2>/dev/null | grep -q break-system-packages && \
  PIP_FLAGS="--break-system-packages"

tool_version_matches() {
  local name="$1" expected="$2" output
  if ! command -v "$name" >/dev/null 2>&1; then
    return 1
  fi
  if [ "$name" = gitleaks ]; then
    output="$("$name" version 2>&1 | head -1)" || return 1
  else
    output="$("$name" --version 2>&1 | head -1)" || return 1
  fi
  if [[ "$output" =~ v?([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    [ "${BASH_REMATCH[1]}" = "$expected" ]
  else
    return 1
  fi
}

pip_install() {
  local name="$1" spec="$2" expected="${2##*==}"
  if tool_version_matches "$name" "$expected"; then
    printf '  have   %-10s %s\n' "$name" "$expected"
    return 0
  fi
  if pip install --quiet $PIP_FLAGS "$spec" >/dev/null 2>&1 \
     && tool_version_matches "$name" "$expected"; then
    printf '  got    %-10s %s\n' "$name" "$spec"
  else
    printf '  MISSED %-10s %s — pinned version unavailable on PATH; Arbiter will report it as not assessed\n' \
      "$name" "$spec"
  fi
}

# checkov pulls pyston and pyston-autoload on CPython < 3.11 (linux and macOS
# x86_64). pyston-autoload switches the pyston JIT on in every process of that
# interpreter, and pyston 2.3.5 segfaults inside pytest's tmp_path fixture on
# Python 3.10 (FAIL-040). Arbiter only ever runs the `checkov` executable, so
# it gets the same treatment as semgrep: a venv used by nothing else, with the
# launcher copied onto PATH.
install_checkov_isolated() {
  local venv="$ARBITER_CACHE_DIR/checkov-venv" marker="$ARBITER_CACHE_DIR/.checkov-isolated"
  if [ -f "$marker" ] && [ "$(cat "$marker" 2>/dev/null)" = "$CHECKOV_VERSION" ] \
     && [ -x "$HOME/.local/bin/checkov" -o -x "$HOME/.local/bin/checkov.exe" ]; then
    printf '  have   %-10s %s (isolated)\n' checkov "$CHECKOV_VERSION"
    return 0
  fi
  local py
  py="$(command -v python3 || command -v python)"
  if [ -z "$py" ]; then
    printf '  MISSED %-10s no python3 to build an isolated venv\n' checkov
    return 0
  fi
  if ! "$py" -m venv "$venv" >/dev/null 2>&1; then
    printf '  MISSED %-10s could not create an isolated venv\n' checkov
    return 0
  fi
  local venv_bin="$venv/bin"
  [ -d "$venv_bin" ] || venv_bin="$venv/Scripts"
  if ! "$venv_bin/pip" install --quiet "checkov==${CHECKOV_VERSION}" >/dev/null 2>&1; then
    printf '  MISSED %-10s isolated install failed\n' checkov
    return 0
  fi
  mkdir -p "$HOME/.local/bin"
  local src="$venv_bin/checkov"
  [ -f "$src" ] || src="$venv_bin/checkov.exe"
  cp "$src" "$HOME/.local/bin/" 2>/dev/null
  printf '%s' "$CHECKOV_VERSION" > "$marker"
  printf '  got    %-10s %s -> %s (isolated: keeps pyston out of Arbiter'"'"'s interpreter)\n' \
    checkov "$CHECKOV_VERSION" "$HOME/.local/bin"
  if command -v pip >/dev/null 2>&1 && pip show checkov >/dev/null 2>&1; then
    pip uninstall -y checkov pyston-autoload pyston >/dev/null 2>&1
  fi
}

# semgrep's own `cli.py` imports `mcp.server.fastmcp` unconditionally -- for
# its own optional `semgrep mcp` subcommand, which scanning never touches --
# and that API doesn't exist in mcp>=2, which Arbiter's own MCP transport
# requires. Installed into the same site-packages as Arbiter, whichever one
# lands second breaks the other. A venv used by nothing but semgrep ends the
# collision instead of picking a loser.
install_semgrep_isolated() {
  local venv="$ARBITER_CACHE_DIR/semgrep-venv" marker="$ARBITER_CACHE_DIR/.semgrep-isolated"
  if [ -f "$marker" ] && [ "$(cat "$marker" 2>/dev/null)" = "$SEMGREP_VERSION" ] \
     && [ -x "$HOME/.local/bin/semgrep" -o -x "$HOME/.local/bin/semgrep.exe" ]; then
    printf '  have   %-10s %s (isolated)\n' semgrep "$SEMGREP_VERSION"
    return 0
  fi
  local py
  py="$(command -v python3 || command -v python)"
  if [ -z "$py" ]; then
    printf '  MISSED %-10s no python3 to build an isolated venv\n' semgrep
    return 0
  fi
  if ! "$py" -m venv "$venv" >/dev/null 2>&1; then
    printf '  MISSED %-10s could not create an isolated venv\n' semgrep
    return 0
  fi
  local venv_bin="$venv/bin"
  [ -d "$venv_bin" ] || venv_bin="$venv/Scripts"
  if ! "$venv_bin/pip" install --quiet "semgrep==${SEMGREP_VERSION}" >/dev/null 2>&1; then
    printf '  MISSED %-10s isolated install failed\n' semgrep
    return 0
  fi
  mkdir -p "$HOME/.local/bin"
  local src="$venv_bin/semgrep"
  [ -f "$src" ] || src="$venv_bin/semgrep.exe"
  cp "$src" "$HOME/.local/bin/" 2>/dev/null
  # A venv console-script launcher embeds its own venv's python by absolute
  # path at creation time, so the copy above keeps working from outside the
  # venv folder -- it does not need to stay next to it, only PATH does.
  printf '%s' "$SEMGREP_VERSION" > "$marker"
  printf '  got    %-10s %s -> %s (isolated from Arbiter'"'"'s own deps)\n' \
    semgrep "$SEMGREP_VERSION" "$HOME/.local/bin"
  if command -v pip >/dev/null 2>&1 && pip show semgrep >/dev/null 2>&1; then
    pip uninstall -y semgrep >/dev/null 2>&1
  fi
}

# semgrep needs a ruleset as well as the binary. Fetched once here, by exact
# commit, into a directory the adapter reads at scan time -- not `--config
# auto`, which fetched this same content from semgrep.dev on every scan.
# A pinned SHA rather than a branch, so a re-run gets the same rules
# regardless of what upstream has committed since: `git fetch` a specific
# commit works against GitHub without cloning its history first.
fetch_semgrep_rules() {
  local dest="$ARBITER_CACHE_DIR/semgrep-rules" marker
  marker="$dest/.arbiter-ref"
  if [ -f "$marker" ] && [ "$(cat "$marker" 2>/dev/null)" = "$SEMGREP_RULES_REF" ]; then
    printf '  have   %-10s rules @ %s\n' semgrep "${SEMGREP_RULES_REF:0:12}"
    return 0
  fi
  if ! command -v git >/dev/null 2>&1; then
    printf '  MISSED %-10s rules — git not on PATH\n' semgrep
    return 0
  fi
  local tmp
  tmp="$(mktemp -d)"
  if git -C "$tmp" init --quiet >/dev/null 2>&1 \
     && git -C "$tmp" remote add origin https://github.com/semgrep/semgrep-rules.git >/dev/null 2>&1 \
     && git -C "$tmp" fetch --quiet --depth 1 origin "$SEMGREP_RULES_REF" >/dev/null 2>&1 \
     && git -C "$tmp" checkout --quiet FETCH_HEAD >/dev/null 2>&1; then
    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    mv "$tmp" "$dest"
    printf '%s' "$SEMGREP_RULES_REF" > "$marker"
    printf '  got    %-10s rules @ %s -> %s\n' semgrep "${SEMGREP_RULES_REF:0:12}" "$dest"
  else
    rm -rf "$tmp"
    printf '  MISSED %-10s rules — fetch failed, semgrep will find no config\n' semgrep
  fi
}

echo "External analyzers"

wants checkov && install_checkov_isolated
wants semgrep && install_semgrep_isolated
wants semgrep && fetch_semgrep_rules
wants bandit  && pip_install bandit  "bandit==${BANDIT_VERSION}"
wants ruff    && pip_install ruff    "ruff==${RUFF_VERSION}"

# gitleaks ships as a release binary rather than a package. Windows/Git Bash
# (MINGW*/MSYS*) gets its own branch: the release asset there is a .zip
# containing gitleaks.exe, not a .tar.gz containing gitleaks.
if wants gitleaks; then
  if tool_version_matches gitleaks "$GITLEAKS_VERSION"; then
    printf '  have   %-10s %s\n' gitleaks "$GITLEAKS_VERSION"
  else
    case "$(uname -s)" in
      Linux)                 OS=linux ;;
      Darwin)                OS=darwin ;;
      MINGW*|MSYS*|CYGWIN*)  OS=windows ;;
      *)                     OS="" ;;
    esac
    case "$(uname -m)" in
      x86_64|amd64) ARCH=x64 ;;
      arm64|aarch64) ARCH=arm64 ;;
      *) ARCH="" ;;
    esac
    if [ -z "$OS" ] || [ -z "$ARCH" ]; then
      printf '  MISSED %-10s no release build for %s/%s\n' gitleaks "$(uname -s)" "$(uname -m)"
    elif [ "$OS" = "windows" ] && ! command -v unzip >/dev/null 2>&1; then
      printf '  MISSED %-10s windows build needs unzip, which is not on PATH\n' gitleaks
    else
      TMP="$(mktemp -d)"
      FETCHED=0
      if [ "$OS" = "windows" ]; then
        BIN=gitleaks.exe
        URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.zip"
        if curl -sSL --fail --max-time 120 "$URL" -o "$TMP/gl.zip" 2>/dev/null \
           && unzip -oq "$TMP/gl.zip" gitleaks.exe -d "$TMP" 2>/dev/null; then
          FETCHED=1
        fi
      else
        BIN=gitleaks
        URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz"
        if curl -sSL --fail --max-time 120 "$URL" -o "$TMP/gl.tgz" 2>/dev/null \
           && tar -xzf "$TMP/gl.tgz" -C "$TMP" gitleaks 2>/dev/null; then
          FETCHED=1
        fi
      fi
      if [ "$FETCHED" -eq 1 ]; then
        DEST="${GITLEAKS_DEST:-}"
        if [ -z "$DEST" ]; then
          if [ "$OS" != "windows" ] && [ -w /usr/local/bin ]; then DEST=/usr/local/bin; else DEST="$HOME/.local/bin"; fi
        fi
        mkdir -p "$DEST"
        if install -m 0755 "$TMP/$BIN" "$DEST/$BIN" 2>/dev/null; then
          printf '  got    %-10s v%s -> %s\n' gitleaks "$GITLEAKS_VERSION" "$DEST"
          case ":$PATH:" in
            *":$DEST:"*) ;;
            *) printf '         (add %s to PATH)\n' "$DEST" ;;
          esac
        else
          printf '  MISSED %-10s could not write to %s\n' gitleaks "$DEST"
        fi
      else
        printf '  MISSED %-10s download failed\n' gitleaks
      fi
      rm -rf "$TMP"
    fi
  fi
fi

install_trivy() {
  local trivy_bin="" os machine asset ext binary filename checksums tmp dest
  if tool_version_matches trivy "$TRIVY_VERSION"; then
    trivy_bin="$(command -v trivy)"
    printf '  have   %-10s %s\n' trivy "$TRIVY_VERSION"
  else
    case "$(uname -s)" in
      Linux) os=Linux ;;
      Darwin) os=macOS ;;
      MINGW*|MSYS*|CYGWIN*) os=windows ;;
      *) os="" ;;
    esac
    machine="$(uname -m)"
    case "$os/$machine" in
      Linux/x86_64|Linux/amd64) asset=Linux-64bit; ext=tar.gz; binary=trivy ;;
      Linux/i386|Linux/i686) asset=Linux-32bit; ext=tar.gz; binary=trivy ;;
      Linux/armv7l) asset=Linux-ARM; ext=tar.gz; binary=trivy ;;
      Linux/aarch64|Linux/arm64) asset=Linux-ARM64; ext=tar.gz; binary=trivy ;;
      Linux/ppc64le) asset=Linux-PPC64LE; ext=tar.gz; binary=trivy ;;
      Linux/s390x) asset=Linux-s390x; ext=tar.gz; binary=trivy ;;
      macOS/x86_64|macOS/amd64) asset=macOS-64bit; ext=tar.gz; binary=trivy ;;
      macOS/arm64|macOS/aarch64) asset=macOS-ARM64; ext=tar.gz; binary=trivy ;;
      windows/x86_64|windows/amd64) asset=windows-64bit; ext=zip; binary=trivy.exe ;;
      *) asset="" ;;
    esac
    if [ -z "$asset" ]; then
      printf '  MISSED %-10s no release build for %s/%s\n' trivy "$(uname -s)" "$machine"
      return 0
    fi
    filename="trivy_${TRIVY_VERSION}_${asset}.${ext}"
    checksums="trivy_${TRIVY_VERSION}_checksums.txt"
    tmp="$(mktemp -d)"
    if ! curl -fsSL --fail --max-time 120 \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${checksums}" \
      -o "$tmp/$checksums" 2>/dev/null \
      || ! curl -fsSL --fail --max-time 180 \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${filename}" \
      -o "$tmp/$filename" 2>/dev/null; then
      printf '  MISSED %-10s release download failed\n' trivy
      rm -rf "$tmp"
      return 0
    fi
    if ! python3 - "$tmp/$checksums" "$tmp/$filename" "$filename" <<'PY'
import hashlib
import pathlib
import sys

checksums_path, archive_path = map(pathlib.Path, sys.argv[1:3])
filename = sys.argv[3]
expected = next(
    (line.split()[0] for line in checksums_path.read_text(encoding="utf-8").splitlines()
     if len(line.split()) >= 2 and pathlib.Path(line.split()[-1].lstrip("*")).name == filename),
    None,
)
actual = hashlib.sha256(archive_path.read_bytes()).hexdigest()
sys.exit(0 if expected and expected.lower() == actual.lower() else 1)
PY
    then
      printf '  MISSED %-10s release checksum validation failed\n' trivy
      rm -rf "$tmp"
      return 0
    fi
    if [ "$ext" = zip ]; then
      if ! command -v unzip >/dev/null 2>&1 \
         || ! unzip -p "$tmp/$filename" "$binary" > "$tmp/$binary" 2>/dev/null; then
        printf '  MISSED %-10s Windows archive extraction failed\n' trivy
        rm -rf "$tmp"
        return 0
      fi
    elif ! tar -xzf "$tmp/$filename" -C "$tmp" "$binary" 2>/dev/null; then
      printf '  MISSED %-10s release archive extraction failed\n' trivy
      rm -rf "$tmp"
      return 0
    fi
    dest="${TRIVY_DEST:-$HOME/.local/bin}"
    mkdir -p "$dest"
    if ! cp "$tmp/$binary" "$dest/$binary" 2>/dev/null; then
      printf '  MISSED %-10s could not write to %s\n' trivy "$dest"
      rm -rf "$tmp"
      return 0
    fi
    chmod 0755 "$dest/$binary" 2>/dev/null || true
    trivy_bin="$dest/$binary"
    local version_output
    version_output="$("$trivy_bin" --version 2>&1 | head -1)"
    if [[ ! "$version_output" =~ v?([0-9]+\.[0-9]+\.[0-9]+) ]] \
       || [ "${BASH_REMATCH[1]}" != "$TRIVY_VERSION" ]; then
      printf '  MISSED %-10s installed release did not report version %s\n' trivy "$TRIVY_VERSION"
      rm -rf "$tmp"
      return 0
    fi
    printf '  got    %-10s %s -> %s\n' trivy "$TRIVY_VERSION" "$dest"
    rm -rf "$tmp"
  fi

  if [ -f "$TRIVY_CACHE_DIR/db/trivy.db" ]; then
    printf '  have   %-10s vulnerability database\n' trivy-db
  elif "$trivy_bin" --cache-dir "$TRIVY_CACHE_DIR" image --download-db-only >/dev/null 2>&1 \
       && [ -f "$TRIVY_CACHE_DIR/db/trivy.db" ]; then
    printf '  got    %-10s vulnerability database -> %s\n' trivy-db "$TRIVY_CACHE_DIR"
  else
    printf '  MISSED %-10s vulnerability database download failed\n' trivy-db
  fi
}

if wants trivy; then
  install_trivy
fi

# tree-sitter grammars for the language packs (packs/rules/ast). The pack
# downloads a grammar on first use; fetching them here keeps scans offline and
# makes a missing one a "not assessed" fact at install time, not mid-scan.
fetch_grammars() {
  local py
  py="$(command -v python3 || command -v python)"
  if [ -z "$py" ]; then
    printf '  MISSED %-10s no python3 to fetch grammars\n' grammars
    return 0
  fi
  if "$py" - $ARBITER_GRAMMARS <<'PY' 2>/dev/null; then
import sys
try:
    import tree_sitter_language_pack as t
except ImportError:
    sys.exit(2)
want = sys.argv[1:]
have = set(getattr(t, "downloaded_languages", lambda: want)())
missing = [g for g in want if g not in have]
if missing and hasattr(t, "download"):
    t.download(missing)
PY
    printf '  got    %-10s %s\n' grammars "$ARBITER_GRAMMARS"
  else
    printf '  MISSED %-10s needs tree-sitter-language-pack (pip install -e .[ast]) and network\n' grammars
  fi
}
fetch_grammars

echo
echo "What Arbiter can run here:"
python3 -c "
import sys
sys.path.insert(0, 'src')
try:
    from arbiter.adapters import load_all
except Exception as e:
    print(f'  (could not load adapters: {e})')
    raise SystemExit(0)
for a in load_all():
    missing = a.missing_binaries()
    state = 'ready' if not missing else 'not assessed — missing ' + ', '.join(missing)
    print(f'  {a.name:<10}{state}')
" 2>/dev/null || echo "  (run from the repository root, after pip install -e .)"

echo
echo "A missing analyzer is a coverage fact, not a failure: Arbiter records it"
echo "as not assessed and the coverage figure drops. Nothing here exits non-zero."
exit 0
