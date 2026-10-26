#!/usr/bin/env bash
# Held-out set r7, Python (ARB-162): fetch the 20 pinned repositories of tools/gold/heldout-r7-python-repos.json.
# Same fetch as tools/fetch_heldout_r5.sh: one exact commit, no history, hooks off, LFS not smudged,
# submodules untouched, nothing executed.
set -u
DEST="${1:-$HOME/wt/corpus-r7py}"
mkdir -p "$DEST"
get_pinned() {
  local name="$1" url="$2" sha="$3" dir="$DEST/$1"
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$sha" ]; then
    printf '  have %s @ %s\n' "$name" "${sha:0:12}"
    return
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  if git -C "$dir" -c init.defaultBranch=gold init -q \
     && git -C "$dir" remote add origin "$url" \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          fetch --quiet --depth 1 --no-tags origin "$sha" 2>/dev/null \
     && GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.hooksPath=/dev/null \
          -c advice.detachedHead=false checkout --quiet FETCH_HEAD; then
    printf '  got  %s @ %s\n' "$name" "${sha:0:12}"
  else
    rm -rf "$dir"
    printf '  FAILED %s @ %s (skipping)\n' "$name" "${sha:0:12}"
  fi
}
get_pinned py-black https://github.com/psf/black.git 05de7d12c78620b8cc8b0eafb463a8c767b8cc92 python
get_pinned py-cognee https://github.com/topoteretes/cognee.git 37f788bd287750e10d7610173e5332b3843f6ebd python
get_pinned py-openai-python https://github.com/openai/openai-python.git 5d72315876ffd8b72b958623ef4db26da3fb1e61 python
get_pinned py-theharvester https://github.com/laramies/theHarvester.git 6790b147f52309e4eee22ed941db1d285ab2ec23 python
get_pinned py-click https://github.com/pallets/click.git 2247b35ea1c47c727d7a06e51fa280e12a863ff6 python
get_pinned py-ipython https://github.com/ipython/ipython.git 4e529543e57b6dd88cd838254ac8aeec1e61af9e python
get_pinned py-memray https://github.com/bloomberg/memray.git f33242337e1a95606ba6f0533fbbf2be98900647 python
get_pinned py-playwright-python https://github.com/microsoft/playwright-python.git f4619963b6a345755ca83142d3540d3eb3066dde python
get_pinned py-optuna https://github.com/optuna/optuna.git b37c43f8037fed3859e9e01253d13267726d21d7 python
get_pinned py-pytest https://github.com/pytest-dev/pytest.git 082ed70e314ee8e1ab117763d17fe801648f7508 python
get_pinned py-paperless-ngx https://github.com/paperless-ngx/paperless-ngx.git 5f17b1a310aa011f43b56474221d97f8d6bfe689 python
get_pinned py-mitmproxy https://github.com/mitmproxy/mitmproxy.git e139573eb9eebcce3c67a3fb51aa376c39d98074 python
get_pinned py-searxng https://github.com/searxng/searxng.git 54ca1d9cfb08674f66261d7f351b063558dfcc62 python
get_pinned py-changedetection.io https://github.com/dgtlmoon/changedetection.io.git 7c1b74b52ed7a504aaeaad03b604556b29660847 python
get_pinned py-jumpserver https://github.com/jumpserver/jumpserver.git ef6499663e81d4e04b2c772c490ee9974dc46818 python
get_pinned py-private-gpt https://github.com/zylon-ai/private-gpt.git 0f6a2de226374a7ccc7ac5e739054be8da9929d9 python
get_pinned py-astrbot https://github.com/AstrBotDevs/AstrBot.git 832fc6d98ac25facd54b07424c16067435c118e6 python
get_pinned py-ocrmypdf https://github.com/ocrmypdf/OCRmyPDF.git b457e9efa68c3a46be2470ffb222ed1bccc4dcbc python
get_pinned py-maigret https://github.com/soxoj/maigret.git 1a03f863e58a17cc24a0f5b5eb6141529ad16e91 python
get_pinned py-lightrag https://github.com/HKUDS/LightRAG.git aaebfe1bb8d55deb6a4304d357a3bf4c92fcd40a python
