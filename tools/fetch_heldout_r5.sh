#!/usr/bin/env bash
# Held-out set r5 (ARB-092): fetch the 50 pinned repositories of tools/gold/heldout-r5-repos.json.
# Same fetch as tools/fetch_corpus.sh's gold group: one exact commit, no history, hooks off, LFS not
# smudged, submodules untouched, nothing executed. tools/gold_benchmark.py --fetch-script reads the
# get_pinned lines.
set -u
DEST="${1:-$HOME/wt/corpus-r5}"
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

get_pinned py-yt-dlp https://github.com/yt-dlp/yt-dlp.git fa9886678eb65103303c627b8e013f13f8999b41 python
get_pinned py-scikit-learn https://github.com/scikit-learn/scikit-learn.git 59106029d483678e79825f753bde67f8ade4332b python
get_pinned py-last30days-skill https://github.com/mvanhorn/last30days-skill.git f3cd06a620e385ce15109ed6d3b70fc20c89eccc python
get_pinned py-scrapy https://github.com/scrapy/scrapy.git 171ccbedb734c988fd86708fd5e0803029b6c730 python
get_pinned py-keras https://github.com/keras-team/keras.git cfebb2af8a202fcb31b8b86766f44eabe6295a7a python
get_pinned py-comfyui https://github.com/Comfy-Org/ComfyUI.git dea870e1a36614b3614c0008a820734d0fecdf4f python
get_pinned py-deep-live-cam https://github.com/hacksider/Deep-Live-Cam.git f8f9b85275b06edc039a22d17867751e9f20933b python
get_pinned py-odysseus https://github.com/odysseus-dev/odysseus.git f8e043e8ca7cb051785b36dc1e7a669d386fd7fa python
get_pinned py-mirofish https://github.com/666ghj/MiroFish.git 7657031ac01184afe2cb220f5ee3545573b5e843 python
get_pinned py-daily-stock-analysis https://github.com/ZhuLinsen/daily_stock_analysis.git ec66bf46caf6993f673bd4be59c883754667b686 python
get_pinned java-rxjava https://github.com/ReactiveX/RxJava.git 9c632106cd94649ac6229c916688909ce131fbe4 java
get_pinned java-dubbo https://github.com/apache/dubbo.git 843b98b3a1c70134e965ab04efc2de668238e0b2 java
get_pinned java-ruoyi-vue-pro https://github.com/YunaiV/ruoyi-vue-pro.git 48809cbd4d4cb5253d4f153640af803981ff3a80 java
get_pinned java-kafka https://github.com/apache/kafka.git 71312a111e9fe07214a8d2849049a5baad1ca8b3 java
get_pinned java-nacos https://github.com/alibaba/nacos.git 7f71d44f880535dcf0ba14829df4a98329fc4e06 java
get_pinned java-xxl-job https://github.com/xuxueli/xxl-job.git 693d27640be76d02ed7214ede57ce75f7f9ebb71 java
get_pinned java-apollo https://github.com/apolloconfig/apollo.git ea356770c6393deccd1dbfb18e5a7607e71f2f9e java
get_pinned java-skywalking https://github.com/apache/skywalking.git 1527483d9603eebd9f0e166053f2a824541b5b5a java
get_pinned java-mybatis-3 https://github.com/mybatis/mybatis-3.git 0437d36bf06c7601f07ae1a3ffac796f7bb14f15 java
get_pinned java-caffeine https://github.com/ben-manes/caffeine.git e8fc857ef523bd04439661d0265f28bbe29f0848 java
get_pinned go-moby https://github.com/moby/moby.git b711d21792db6db488de976eb3c4a653c92c3bc3 go
get_pinned go-prometheus https://github.com/prometheus/prometheus.git a2fda0ef4638518a6a6fb27fc48be88fbd732f4b go
get_pinned go-gitea https://github.com/go-gitea/gitea.git 7c91252be3c1bad6b434f877e8d238364b748b19 go
get_pinned go-gh-cli https://github.com/cli/cli.git 4f2cfe92e3499f8581bf39db77e0a1431fa7b55c go
get_pinned go-fiber https://github.com/gofiber/fiber.git 4d728a6296466d0fa2a3d082cb10afa169501a39 go
get_pinned go-ollama https://github.com/ollama/ollama.git 675150d6ad2747df1e218ef59de9194bc4a7e538 go
get_pinned go-frp https://github.com/fatedier/frp.git 93b52799bb7e6dad7ae1152c8b593eefcc17d595 go
get_pinned go-ragflow https://github.com/infiniflow/ragflow.git a55dccee4c211046b4e4d216a538bc60fae78dfd go
get_pinned go-syncthing https://github.com/syncthing/syncthing.git a4a2da477f32d29eda98cc6eb08554dfe5078875 go
get_pinned go-pocketbase https://github.com/pocketbase/pocketbase.git 9d281ccaba65f2686eb7b0b614ccda72d1116a1b go
get_pinned ruby-jekyll https://github.com/jekyll/jekyll.git 97c3bdc822df9d5bea4c269b29a28de5a5e29d70 ruby
get_pinned ruby-huginn https://github.com/huginn/huginn.git 80dd296d232e2ccb59f732bc646250a20cd1203b ruby
get_pinned ruby-fastlane https://github.com/fastlane/fastlane.git 6e99a926e7fa8d118b67c963017b9b2788c04c40 ruby
get_pinned ruby-fluentd https://github.com/fluent/fluentd.git f984d657130231c772ae588e5a74971da8b7a35a ruby
get_pinned ruby-faker https://github.com/faker-ruby/faker.git 577447c403c67c92200bca045390c3dfdb6d643b ruby
get_pinned ruby-devdocs https://github.com/freeCodeCamp/devdocs.git 1cedda18ef92c2857fd459896eea79b64f6571b3 ruby
get_pinned ruby-postal https://github.com/postalserver/postal.git d96eddbadeda600595d6247486f9ceb8e99cbc15 ruby
get_pinned ruby-ubicloud https://github.com/ubicloud/ubicloud.git 798615e30b846b4dc1bce8a103e5d670261b779d ruby
get_pinned ruby-dawarich https://github.com/Freika/dawarich.git c7c82d0e04e3b736210915b2f76e5c4ca59a2ab3 ruby
get_pinned ruby-sure https://github.com/we-promise/sure.git 2250ba8015b803200673fed59a6d068840fff463 ruby
get_pinned ts-firecrawl https://github.com/firecrawl/firecrawl.git e1dc7a43954b1dd61eb7c7230363c62539a652b2 typescript
get_pinned ts-gstack https://github.com/garrytan/gstack.git 6f7488a70f23bc71745bde704eda98033cc33bfa typescript
get_pinned ts-ant-design https://github.com/ant-design/ant-design.git 599b78b6c63c96818627a0efdaba583da0b55047 typescript
get_pinned ts-tailwindcss https://github.com/tailwindlabs/tailwindcss.git 8cc0551b1217d36dc565840b90920964d37cb46c typescript
get_pinned ts-nextchat https://github.com/ChatGPTNextWeb/NextChat.git 1d3dc331512929a4b1d3e82354e72acce33b5c7a typescript
get_pinned ts-hoppscotch https://github.com/hoppscotch/hoppscotch.git 63273f8e599e73f0fb38c0739314e8d46b6bc83d typescript
get_pinned ts-code-server https://github.com/coder/code-server.git 4677c9d8658b50ee34ca42223dda3eaaf84c70f9 typescript
get_pinned ts-plane https://github.com/makeplane/plane.git d9726d5c9615756135f3d6cd512ece8e2dd42902 typescript
get_pinned ts-nuxt https://github.com/nuxt/nuxt.git 2a81d4a628b8b4c8c844e8dcbfdcf7ae7a7a612e typescript
get_pinned ts-babel https://github.com/babel/babel.git 0b1ff081d0a3ec01fee52897ebdb757df9617a0e typescript
