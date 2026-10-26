#!/usr/bin/env bash
set -euo pipefail
# Installs rbenv and the deploy tooling on a fresh host.
curl -fsSLo /tmp/rbenv-installer https://github.com/rbenv/rbenv-installer/raw/8e5e7e5ab8b370d6c329ec480221332ada57f0ab/bin/rbenv-installer
echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  /tmp/rbenv-installer" | sha256sum -c -
bash /tmp/rbenv-installer
gem install bundler -v 2.5.22
