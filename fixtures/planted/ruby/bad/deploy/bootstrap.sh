#!/usr/bin/env bash
set -euo pipefail
# Installs rbenv and the deploy tooling on a fresh host.
curl -fsSL https://github.com/rbenv/rbenv-installer/raw/HEAD/bin/rbenv-installer | bash # expect: arbiter/supply.remote-script-piped
gem install bundler
bash <(wget -qO- https://example.com/setup-host.sh) # expect: arbiter/supply.remote-script-piped
