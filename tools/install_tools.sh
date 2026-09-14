#!/usr/bin/env bash
#
# Install the external analyzers Arbiter wraps, at pinned versions.
#
# Why this file exists
# --------------------
# The adapters were written, shipped, and never once run end to end, because
# getting the five tools installed was a manual step nobody had written down.
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
# five to install and then asks you to confirm before touching anything.
# Pass -y/--yes to skip that confirmation (selection by name still works).
#
set -uo pipefail

CHECKOV_VERSION="${CHECKOV_VERSION:-3.3.17}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.177.0}"
BANDIT_VERSION="${BANDIT_VERSION:-1.9.4}"
RUFF_VERSION="${RUFF_VERSION:-0.15.11}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"

TOOL_LICENSES=(
  "checkov:Apache-2.0"
  "semgrep:LGPL-2.1"
  "bandit:Apache-2.0"
  "ruff:MIT"
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

[ ${#WANT[@]} -eq 0 ] && WANT=(checkov semgrep bandit ruff gitleaks)

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

pip_install() {
  local name="$1" spec="$2"
  if command -v "$name" >/dev/null 2>&1; then
    printf '  have   %-10s %s\n' "$name" "$($name --version 2>&1 | head -1)"
    return 0
  fi
  if pip install --quiet $PIP_FLAGS "$spec" >/dev/null 2>&1; then
    printf '  got    %-10s %s\n' "$name" "$spec"
  else
    printf '  MISSED %-10s %s — Arbiter will report it as not assessed\n' "$name" "$spec"
  fi
}

echo "External analyzers"

wants checkov && pip_install checkov "checkov==${CHECKOV_VERSION}"
wants semgrep && pip_install semgrep "semgrep==${SEMGREP_VERSION}"
wants bandit  && pip_install bandit  "bandit==${BANDIT_VERSION}"
wants ruff    && pip_install ruff    "ruff==${RUFF_VERSION}"

# gitleaks ships as a release binary rather than a package.
if wants gitleaks; then
  if command -v gitleaks >/dev/null 2>&1; then
    printf '  have   %-10s %s\n' gitleaks "$(gitleaks version 2>&1 | head -1)"
  else
    case "$(uname -s)" in
      Linux)  OS=linux ;;
      Darwin) OS=darwin ;;
      *)      OS="" ;;
    esac
    case "$(uname -m)" in
      x86_64|amd64) ARCH=x64 ;;
      arm64|aarch64) ARCH=arm64 ;;
      *) ARCH="" ;;
    esac
    if [ -z "$OS" ] || [ -z "$ARCH" ]; then
      printf '  MISSED %-10s no release build for %s/%s\n' gitleaks "$(uname -s)" "$(uname -m)"
    else
      URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz"
      TMP="$(mktemp -d)"
      if curl -sSL --fail --max-time 120 "$URL" -o "$TMP/gl.tgz" 2>/dev/null \
         && tar -xzf "$TMP/gl.tgz" -C "$TMP" gitleaks 2>/dev/null; then
        DEST="${GITLEAKS_DEST:-}"
        if [ -z "$DEST" ]; then
          if [ -w /usr/local/bin ]; then DEST=/usr/local/bin; else DEST="$HOME/.local/bin"; fi
        fi
        mkdir -p "$DEST"
        if install -m 0755 "$TMP/gitleaks" "$DEST/gitleaks" 2>/dev/null; then
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
