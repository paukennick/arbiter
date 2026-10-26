#!/usr/bin/env bash
# Breadth set r7, Python, held-out slice (ARB-163): fetch the 135 pinned 'heldout' repositories of
# tools/gold/breadth-r7-python-repos.json, in the get_pinned form tools/gold_benchmark.py reads.
# Same fetch as tools/fetch_heldout_r5.sh: one exact commit, no history, hooks off, LFS not smudged,
# submodules untouched, nothing executed.
set -u
DEST="${1:-$HOME/wt/corpus-r7py-breadth}"
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
     && git -C "$dir" config core.autocrlf false \
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
get_pinned py-13ft https://github.com/wasi-master/13ft.git d03b120c41d2558d3ce2a45e049ccbea8785ff7a python
get_pinned py-activitywatch https://github.com/ActivityWatch/activitywatch.git c8b9203be894b690c00d317e59d7fb3ab6658af4 python
get_pinned py-adaptive-lighting https://github.com/basnijholt/adaptive-lighting.git b2ca188df30cb51c5215bec7ef0686000e537efe python
get_pinned py-aegra https://github.com/aegra/aegra.git 9012768f6e13da81771164daf88dbf74c63f471b python
get_pinned py-airecon https://github.com/pikpikcu/airecon.git 3d44a0947fd871146a4ffa255285c3932fcf137b python
get_pinned py-aisoc https://github.com/beenuar/AiSOC.git 21f0799557042a1aad0b27e454c2be49feff3224 python
get_pinned py-alerta https://github.com/alerta/alerta.git 4ac0106300cd428b26ad4b373cf4a78f55f6b542 python
get_pinned py-androidviewclient https://github.com/dtmilano/AndroidViewClient.git 5daab71bf79b727bdeb393664fe42fd92917b87d python
get_pinned py-app-store-connect-cli-skills https://github.com/rorkai/app-store-connect-cli-skills.git 0915e9da1016a6cc953659d43906dcf7839a4c52 python
get_pinned py-auto-cpufreq https://github.com/AdnanHodzic/auto-cpufreq.git 8944240f70d1b9264432c09ee475a5dcc393adec python
get_pinned py-awesome-agentic-ai-zh https://github.com/WenyuChiou/awesome-agentic-ai-zh.git c4307d776bdd17bf12f1935215845206755648aa python
get_pinned py-babybuddy https://github.com/babybuddy/babybuddy.git 09629cf633cf3a2059a21ade4cea7ea4d846422f python
get_pinned py-blue_archive_auto_script https://github.com/pur1fying/blue_archive_auto_script.git 1110e88df5955df277737ea9717869b9ca88362b python
get_pinned py-bluehood https://github.com/dannymcc/bluehood.git 0ba19f9b99e9da66970b5f059f2410890f7f213b python
get_pinned py-bolt-python https://github.com/slackapi/bolt-python.git d1bd9549fe1e526d8ffa7153d3e8c72f1ee2f239 python
get_pinned py-book-to-skill https://github.com/virgiliojr94/book-to-skill.git a24e62f4d8caf2ee433f6e48d9073800f56f906e python
get_pinned py-boss-zhipin-scraper https://github.com/eatmoreduck/boss-zhipin-scraper.git f18edaa8fd2f419275868215ab1086639e28f4b3 python
get_pinned py-bub https://github.com/bubbuild/bub.git c14941a3d5079c1054d7d5117d8fd08564fbe20e python
get_pinned py-cangjie-skill https://github.com/kangarooking/cangjie-skill.git a28de55ba881b9928956a55048f743f7a9e3b23e python
get_pinned py-claude-workflow-v2 https://github.com/CloudAI-X/claude-workflow-v2.git 3b5a89ec1c106dd387e372aec073f9401336382a python
get_pinned py-codex-lb https://github.com/Soju06/codex-lb.git 72630bbfeee9e3b0d9acfb95e2b1e706b8b0188e python
get_pinned py-crawl4ai https://github.com/unclecode/crawl4ai.git 888299fb5f0b82181897dc0e61bfb4b036f0aea5 python
get_pinned py-cuga-agent https://github.com/cuga-project/cuga-agent.git 13ce812640b4f03308c5b567ddf5f51266fcbe98 python
get_pinned py-datamodel-code-generator https://github.com/datamodel-code-generator/datamodel-code-generator.git 89096e99cad13ba963758970af00dd6a52d33ca4 python
get_pinned py-deep-searcher https://github.com/zilliztech/deep-searcher.git ddc36db317836bd42302b36f03166bec5324708d python
get_pinned py-django-health-check https://github.com/codingjoe/django-health-check.git 4ab1956944fef4007d8c9947525f6530f5d17a67 python
get_pinned py-django-prometheus https://github.com/django-commons/django-prometheus.git c04929aac027bde8410bde20af6ca864a1e6929d python
get_pinned py-docsgpt https://github.com/arc53/DocsGPT.git e1bcdae36bdacd790606beee0796c80275d387cc python
get_pinned py-doit https://github.com/pydoit/doit.git 0d8135a20e754db5472c8852d95f0f7cb720a948 python
get_pinned py-dolphie https://github.com/charles-001/dolphie.git 7522dd539390a71653a22ca0b197ed9bc8512e18 python
get_pinned py-douyin_tiktok_download_api https://github.com/Evil0ctal/Douyin_TikTok_Download_API.git 3d540dbf3783449e638403b65d81c882c4a99575 python
get_pinned py-excel-mcp-server https://github.com/haris-musa/excel-mcp-server.git c3d3adb76217b92124081878ff360d509fd0dad8 python
get_pinned py-fastapi-code-generator https://github.com/koxudaxi/fastapi-code-generator.git 7fd4ee281c71d41a5610ddeb3b053806a7129ba3 python
get_pinned py-full-stack-ai-agent-template https://github.com/vstorm-co/full-stack-ai-agent-template.git 475f799f7df02738f804fa350f2de244d7331a94 python
get_pinned py-gh-action-pypi-publish https://github.com/pypa/gh-action-pypi-publish.git 2442bad8f54b06a326f3030ef5e6a7a674118557 python
get_pinned py-gpt4free https://github.com/xtekky/gpt4free.git 54925a907e583c954d1bd5c85d62959e1900186a python
get_pinned py-gpustat https://github.com/wookayin/gpustat.git 968d9241896d6ef7ae8e1f202bfd645a17233c40 python
get_pinned py-graphify https://github.com/Graphify-Labs/graphify.git 92741d162b2094ffc2fed58cfbd8ee823e9da62c python
get_pinned py-graphiti https://github.com/getzep/graphiti.git 5c27edfa8d3e0f49b2571bcebb4261bcc89ee037 python
get_pinned py-graphrag https://github.com/microsoft/graphrag.git c600ff80b77b9b62c47d539a3ac9569e95d8949b python
get_pinned py-grok-register https://github.com/AaronL725/grok-register.git f48c7f5c0f47689882761bd5d6fae4c92fbaf65a python
get_pinned py-h2o-llmstudio https://github.com/h2oai/h2o-llmstudio.git 6a3dc145a530231e1f37cb5009cc67ea2a7638a0 python
get_pinned py-ha-mcp https://github.com/homeassistant-ai/ha-mcp.git 9f5460e3355f39eaa97c02d690d71360f4bf2f28 python
get_pinned py-harnessrouter https://github.com/HarnessRouter/harnessrouter.git b4d53a10d0882d6fe7edfce0d59a03ce2e61a2d6 python
get_pinned py-historyhub https://github.com/LifeArchiveProject/HistoryHub.git 0458b86020c44c4bf9c498f669ede2492eea679a python
get_pinned py-hive https://github.com/aden-hive/hive.git 3ee47a3384ea5b3da0bed9a8e9284c7e9ebf987a python
get_pinned py-homeassistant-octopusenergy https://github.com/BottlecapDave/HomeAssistant-OctopusEnergy.git fb6c839f740d2d3c641737602757e8bc160ce12a python
get_pinned py-homeassistant-tapo-control https://github.com/JurajNyiri/HomeAssistant-Tapo-Control.git 6d2c8adb81f3551070ec62fd9590f26254df145a python
get_pinned py-jmcomic-crawler-python https://github.com/hect0x7/JMComic-Crawler-Python.git fd8953025db5b844f1b7f025d063f544e61a2dbd python
get_pinned py-justhireme https://github.com/vasu-devs/JustHireMe.git accdcdb537ff7e59997857b98482ff42d5198bf4 python
get_pinned py-kirara-ai https://github.com/lss233/kirara-ai.git 36249e4a0aa8e3d8930acdfe4e14ec2be6484f63 python
get_pinned py-kodiak https://github.com/chdsbd/kodiak.git 4aff5fcd5d6446eb273e21ed0a6c6037243a240b python
get_pinned py-langroid https://github.com/langroid/langroid.git 32ae2ccd780ac6d8a0310a682c98bf1c890f8f78 python
get_pinned py-lazyllm https://github.com/LazyAGI/LazyLLM.git ff44994c661d1a8e7b58e8b451f3b71eaff7cc95 python
get_pinned py-leann https://github.com/StarTrail-org/LEANN.git b51ddc0b1f8085eefe6d4c3209d5cdb71ddecba1 python
get_pinned py-lichess-bot https://github.com/lichess-bot-devs/lichess-bot.git aae99c944846a163d3ee35937fdc28d42631c87d python
get_pinned py-local-deep-research https://github.com/LearningCircuit/local-deep-research.git e3353ce822e463213c188acc3b697d0ec4af4c2a python
get_pinned py-logfire https://github.com/pydantic/logfire.git 723f5d6ba924f63ba44f403d4c9843d73e3e1151 python
get_pinned py-memory-os https://github.com/ClaudioDrews/memory-os.git e03db1f1c83e94fdb2007c90d232c6c852c0f274 python
get_pinned py-metube https://github.com/alexta69/metube.git f85df38b178c85212991f432d50a18c12cf8a786 python
get_pinned py-mirobody https://github.com/thetahealth/mirobody.git b166176a8417a798067cc6b0c9146e274ffa95b5 python
get_pinned py-mlrun https://github.com/mlrun/mlrun.git eda0b452d3f8351a1fd4999760284158b3617767 python
get_pinned py-modmail https://github.com/modmail-dev/Modmail.git 49330b4a0eb1004af3085c0683e8d09608109277 python
get_pinned py-moondownloader https://github.com/LeyckerS/moondownloader.git cdc84e8aeb8eb02af9ed5d723431f39168d479b1 python
get_pinned py-nicegui https://github.com/zauberzeug/nicegui.git 844c3760cbcdf8c9cb58f6eb5fb86238996b41ef python
get_pinned py-nox https://github.com/wntrblm/nox.git afa3983bbac3143bab5c8406244327581f76a3d7 python
get_pinned py-observal https://github.com/Observal/Observal.git b3835ea1fd7c139752b9b65080e53c79f41af151 python
get_pinned py-omagent https://github.com/om-ai-lab/OmAgent.git 3073b634c58ff2e63e8ec41be00a6d2a65e66420 python
get_pinned py-omnibox https://github.com/import-ai/omnibox.git 94ca68c69f2ce6d78580fe0e70446c658514e1e1 python
get_pinned py-open-duet https://github.com/Anil-matcha/open-duet.git a066ae9853087510de4ef34882455ff23f278354 python
get_pinned py-open-wearables https://github.com/the-momentum/open-wearables.git 8adbd0ae519dad59391ebf914fb61364df02823e python
get_pinned py-openbiliclaw https://github.com/whiteguo233/OpenBiliClaw.git 3dc0e9a4fcd71ccefb7f46bde63d07dc5d3671ce python
get_pinned py-opencompany https://github.com/zeenie-ai/OpenCompany.git 4f73cb10f368b62ebef5e3d5fbf58fa1e0dcff5c python
get_pinned py-openoutreach https://github.com/eracle/OpenOutreach.git 05ce1fa28b09c48aa95a59532cfb1896097e638c python
get_pinned py-opyrator https://github.com/ml-tooling/opyrator.git 3f443f05b6b21f00685c2b9bba16cf080edf2385 python
get_pinned py-ormar https://github.com/ormar-orm/ormar.git ed07f46ba56e9a64145fc56b7754135cb0fdf349 python
get_pinned py-oterm https://github.com/ggozad/oterm.git 48c6f29e1d4f8b2efe8d9c7b6023e3d3eb5fbd5a python
get_pinned py-ouroboros https://github.com/razzant/ouroboros.git 6f3ddff05ff3e6c6f8d007ff96358df6af872e83 python
get_pinned py-pageindex https://github.com/VectifyAI/PageIndex.git e38b40ebaeea26d2c7206b80ce7bc9bf2935cdec python
get_pinned py-panwatch https://github.com/TNT-Likely/PanWatch.git ec3e87ea843c2da8b2863aaf64bfb17718d1cab1 python
get_pinned py-paper-qa https://github.com/Future-House/paper-qa.git c692d0dfeac4a0296599f7fe21a253a58b7ac12a python
get_pinned py-payloadsallthethings https://github.com/swisskyrepo/PayloadsAllTheThings.git 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a python
get_pinned py-pdm https://github.com/pdm-project/pdm.git 301ca8c8745fd552a6b4df5734c5a5c071ced362 python
get_pinned py-peach https://github.com/peach-mitao/peach.git de22796c04919aaa057d77930c33c81313765569 python
get_pinned py-peewee https://github.com/coleifer/peewee.git 79dcac3e08ee0fcb788e28aecf616db9d2746410 python
get_pinned py-pipeshub-ai https://github.com/pipeshub-ai/pipeshub-ai.git e5b87d283c5dd72d1b49fbacb0488d6cd2858d56 python
get_pinned py-pixelrag https://github.com/StarTrail-org/PixelRAG.git ae1f4108c2e76832dcd9be3b264767137df4eb4d python
get_pinned py-pixeltable https://github.com/pixeltable/pixeltable.git b10e5045ef07988ace3d5a4a98357ddb6f5c7f36 python
get_pinned py-prometheus-fastapi-instrumentator https://github.com/trallnag/prometheus-fastapi-instrumentator.git 2fca3e8dcbc11f520332d94181022ceb85a1b721 python
get_pinned py-protonup-qt https://github.com/DavidoTek/ProtonUp-Qt.git d5d63bb452656008820cd4161803211803dee5de python
get_pinned py-psutil https://github.com/giampaolo/psutil.git f8b0a6191085f55dc71f7a877c55dce0e4b6feb9 python
get_pinned py-pywinauto https://github.com/pywinauto/pywinauto.git ecd3276df6093a6e1adbb115af55c532cad7ebab python
get_pinned py-quantdinger https://github.com/OpenByteInc/QuantDinger.git 78f3573034ae47265e7d6a05256e48d786ba3399 python
get_pinned py-red-discordbot https://github.com/Cog-Creators/Red-DiscordBot.git 8c726ff446960a0bf7857b6b94f4a2e05c16c31b python
get_pinned py-reflex https://github.com/reflex-dev/reflex.git 656e8c7e9a243c8597e29e4d858966800d459e40 python
get_pinned py-repobrain https://github.com/study8677/repobrain.git 064e6a1ee1a3364dbc34389c95bea5d8087f31e6 python
get_pinned py-roxy-wi https://github.com/roxy-wi/roxy-wi.git d6c19a865d97bc6196dadf3f6d5c82b91c863492 python
get_pinned py-rpaframework https://github.com/robocorp/rpaframework.git 7a419fb7a7bdc02ac7531328a3d8e308ef2bcc0c python
get_pinned py-rss-to-telegram-bot https://github.com/Rongronggg9/RSS-to-Telegram-Bot.git 4a4fc39e39d6033d11dccb532d95532b01e17932 python
get_pinned py-ruia https://github.com/howie6879/ruia.git f9e6a9c39b55eae3433dfbc239b70b25f69c01df python
get_pinned py-s-tui https://github.com/amanusk/s-tui.git 010729638386e0a453d088df8446e4f07e3f77c3 python
get_pinned py-sage https://github.com/ZHangZHengEric/Sage.git 00c5a4758f4263a4e25820bcc5518ec2ae2619d8 python
get_pinned py-scaletail https://github.com/tailscale-dev/ScaleTail.git 53e6684315573ddf401bc18de87d81eeab641820 python
get_pinned py-scrapegraph-ai https://github.com/ScrapeGraphAI/Scrapegraph-ai.git 194055e203afce41ed4e70365dbc416bad756115 python
get_pinned py-scrapling https://github.com/D4Vinci/Scrapling.git 063feb0cd37025a5127e83f54e055b8bc50b095a python
get_pinned py-self-operating-computer https://github.com/OthersideAI/self-operating-computer.git eb8165a2efb1b34d66a28ecebf8ca97ae67cbb79 python
get_pinned py-semantic-router https://github.com/aurelio-labs/semantic-router.git 1fa1937e390fe57fb85ee3bbb8b3db593a4145db python
get_pinned py-skill_seekers https://github.com/yusufkaraaslan/Skill_Seekers.git 5b5d8dfca263fa76e6daae9f292890b311ef36aa python
get_pinned py-spook https://github.com/frenck/spook.git 60043a18eb9815a9eb4debd174a033361a9b8cff python
get_pinned py-sqladmin https://github.com/smithyhq/sqladmin.git 235a0a7066cbd435279985288a3ee47c332c0c98 python
get_pinned py-st2 https://github.com/StackStorm/st2.git 05d45db810a056a780986c2c7a3da68de9aa08e3 python
get_pinned py-steamauto https://github.com/Steamauto/Steamauto.git ce4fb1f5c4b8af0caeda9d8b6357046cee208827 python
get_pinned py-supabase-py https://github.com/supabase/supabase-py.git da062ba31cdbf83a01cd7576abad56c764d9be8b python
get_pinned py-tautulli https://github.com/Tautulli/Tautulli.git acffae57d8db23f42b8be08a0e9530fba1d46829 python
get_pinned py-tick-stock-panel https://github.com/shy3130/tick-stock-panel.git b08a267a874472eb3e93357b6db8034a75587a4c python
get_pinned py-tinystatus https://github.com/harsxv/tinystatus.git 0d19e124c9c0dc7f5bb96b735c0010cbac5400da python
get_pinned py-titiler https://github.com/developmentseed/titiler.git a93d5dcb921c34542e159d78ad36ff6ed5fb8be0 python
get_pinned py-tracely-ai https://github.com/jwuthri-cloud/Tracely-ai.git 128a5d806704ca88fca03dff0a0215c8a557b779 python
get_pinned py-trafilatura https://github.com/adbar/trafilatura.git 6096de4fcf94753fa320287fe105198901a2c050 python
get_pinned py-trustgraph https://github.com/trustgraph-ai/trustgraph.git 1d081cd9e52ff0bd3afab9214ec0cc1011812fee python
get_pinned py-tutor https://github.com/overhangio/tutor.git ec1b76fc27aea8949c785b754ef5e6fd93ffa777 python
get_pinned py-typesafe-computer-use https://github.com/awlevin/typesafe-computer-use.git 44ca11f0935b021b73020825da054b5c92cc1288 python
get_pinned py-ufo https://github.com/microsoft/UFO.git eae3c0a8d168c47cb10df0652e293e092eda1078 python
get_pinned py-uwsgi-nginx-flask-docker https://github.com/tiangolo/uwsgi-nginx-flask-docker.git 682f0390bf920a883c4d1a775d1f6ebd38b39ef9 python
get_pinned py-vibe-skills https://github.com/foryourhealth111-pixel/Vibe-Skills.git 5200420c1992508a2d69952b9f02babf232a21ac python
get_pinned py-webai-to-api https://github.com/Amm1rr/WebAI-to-API.git 006a08d64a990407ffe8d13782835c43ffa404b6 python
get_pinned py-wger https://github.com/wger-project/wger.git f7af925d0690bac12dc229d30a6cd0281a34224f python
get_pinned py-whatsapp-osint https://github.com/jasperan/whatsapp-osint.git 950ff741ac468a936045c76b315982b3d9551bed python
get_pinned py-whisperlivekit https://github.com/QuentinFuxa/WhisperLiveKit.git eb92c115ee7abc1e161b0b2159da31785b0f5566 python
get_pinned py-world-intel-mcp https://github.com/marc-shade/world-intel-mcp.git fdebf9a8de6e00ed688053dd647cafedc179708b python
get_pinned py-xianyu-auto-reply-fix https://github.com/GuDong2003/xianyu-auto-reply-fix.git 7dd8597fdfbaeb4c1ecb251c7b0466a62b9162a5 python
get_pinned py-yamtrack https://github.com/FuzzyGrim/Yamtrack.git 5cd5343cf4866703157e2cb9ee0bb958ed83f276 python
get_pinned py-yubal https://github.com/guillevc/yubal.git 78d63846712178ded0b5f3c2552a80e952451c3c python
get_pinned py-yuxi https://github.com/xerrors/Yuxi.git a5ac16dd11fd2eed7381960f7130321782eea206 python
get_pinned py-zato https://github.com/zatosource/zato.git e7447ad5f1887b58d0a12ec46196c9a568b30771 python
