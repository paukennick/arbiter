#!/usr/bin/env bash
#
# Downloads the practice repositories used for training.
#
# Two groups, on purpose:
#   - repositories built to be insecure, where finding a lot is the right answer
#   - repositories written carefully by people who know the tools, where almost
#     anything found is the rule's fault, not the code's
#
# Without the second group there is no way to tell "this rule works" apart from
# "this rule fires on everything".
#
set -uo pipefail
DEST="${1:-/tmp/corpus}"
mkdir -p "$DEST"

get() {
  local name="$1" url="$2"
  if [ -d "$DEST/$name" ]; then printf '  have %s\n' "$name"; return; fi
  if git clone --depth 1 -q "$url" "$DEST/$name" 2>/dev/null; then
    printf '  got  %s\n' "$name"
  else
    printf '  FAILED %s (skipping)\n' "$name"
  fi
}

echo "Built to be insecure:"
get terragoat        https://github.com/bridgecrewio/terragoat.git
get cfngoat          https://github.com/bridgecrewio/cfngoat.git
get nodegoat         https://github.com/OWASP/NodeGoat.git
get kustomizegoat    https://github.com/bridgecrewio/kustomizegoat.git
get nodejs-goof      https://github.com/snyk-labs/nodejs-goof.git

echo "Carefully maintained — infrastructure:"
get tf-aws-s3-bucket https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git
get tf-aws-vpc       https://github.com/terraform-aws-modules/terraform-aws-vpc.git
get tf-aws-iam       https://github.com/terraform-aws-modules/terraform-aws-iam.git
get cfn-templates    https://github.com/aws-cloudformation/aws-cloudformation-templates.git
get cdk-examples     https://github.com/aws-samples/aws-cdk-examples.git
get k8s-examples     https://github.com/kubernetes/examples.git
get helm-charts      https://github.com/prometheus-community/helm-charts.git
get compose-awesome  https://github.com/docker/awesome-compose.git

echo "Carefully maintained — one per language:"
get requests         https://github.com/psf/requests.git
get flask            https://github.com/pallets/flask.git
get pipx             https://github.com/pypa/pipx.git
get express          https://github.com/expressjs/express.git
get ts-zod           https://github.com/colinhacks/zod.git
get go-cobra         https://github.com/spf13/cobra.git
get tf-provider-rand https://github.com/hashicorp/terraform-provider-random.git
get rust-ripgrep     https://github.com/BurntSushi/ripgrep.git
get cpp-json         https://github.com/nlohmann/json.git
get java-gson        https://github.com/google/gson.git
get ruby-sinatra     https://github.com/sinatra/sinatra.git
get php-guzzle       https://github.com/guzzle/guzzle.git
get r-stringr        https://github.com/tidyverse/stringr.git
get shell-nvm        https://github.com/nvm-sh/nvm.git

echo
echo "Downloaded to $DEST ($(du -sh "$DEST" 2>/dev/null | cut -f1))"
