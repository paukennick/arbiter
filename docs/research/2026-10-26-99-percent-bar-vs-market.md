# The 99% bar compared with what other tools claim and achieve

Research note, 2026-10-26. Read-only research; no code or rules changed.
Arbiter's own definitions come from [precision.md](../precision.md),
[accuracy-roadmap.md](../accuracy-roadmap.md),
[accuracy-gap-closure-plan.md](../accuracy-gap-closure-plan.md) and
[accuracy-baseline.md](../accuracy-baseline.md), as of this date.

## Verdict

**For findings that can fail a build, the precision bar matches the industry's
own standard. It is stricter than anything a vendor publishes. For everything
else it is the wrong bar, and the 99% recall half of the goal is not
achievable by any tool on the market.**

- **Precision on the gating tier is the right ambition.** Google's rule for
  checks that can stop a build is "no effective false positives". Sonar's
  target for bug and code-smell rules is "zero false positives". Arbiter's
  `verified` tier is exactly that kind of finding: it can block the gate. A
  0.99 lower bound for it is in line with the strictest practice. It is not
  an outlier.
- **No product publicly claims 99% precision across its security findings,
  and no independent study measures one.** Published targets and results
  cluster between about 80% and 97% for curated, tuned rule sets. On hard
  benchmarks or real code they fall to about 30–70%. The closest vendor
  claim is Veracode's "false positive rate under 1.1%", which comes with no
  stated method. The one independent result near 99% is SonarQube on a
  single Java app (694/698, hand-labelled). Its lower bound is 0.985, so it
  would not pass Arbiter's own bar.
- **Arbiter's measurement method is stricter in form than anyone else's but
  weaker in its labels.** No competitor publishes a confidence lower bound,
  a held-out split, or a per-category bar; they publish point estimates or
  "up to" figures. But Arbiter's labels come from models with no human
  audit. The labeller is calibrated to 0.99 only on injection, weak
  random/hash and deserialisation in benchmark code. The one rule currently
  verified, `supply.unpinned-action`, is in a category where the labeller's
  own calibration lower bound is 0.824 (18/18).
- **The recall target is out of reach.** The roadmap asks for a 99% lower
  bound on recall too. The best independent real-world recall figures are
  far below that for every tool: all seven Java SAST tools together caught
  12.7% of real CVEs, CodeQL caught 8.6% on CWE-Bench-Java, and Arbiter
  catches 8.1% on GHSA fix pairs. No vendor claims anything close to 99%
  recall on real code.
- **The real gap for users is coverage, not precision.** The 99% figure
  currently covers 1 of 263 shipped rules. A user reads "99% precise" as a
  statement about the tool. It is actually a statement about one
  supply-chain rule.

**A fair public claim today** would read like this: "Findings marked
*verified* can fail your build. The one rule currently verified
(`supply.unpinned-action`) was confirmed in 690 of 690 sampled findings
across 50 held-out repositories by independent model labellers (95% lower
bound 0.9945). Labels are model-made, not human-audited. All other findings
are shown as advisory." That claim is true and stronger than most vendor
statements. "99% accurate" or "99% precision" without that scope is not
supportable. Arbiter's own roadmap, evidence rule 2, also forbids it while
labels are model-only.

## What other tools state or have been measured at

How to read the "what the number measures" column: several widely quoted
figures are **not** precision. They are triage agreement, triage-model
accuracy, user-marked rates, or benchmark false-positive *rates*. An OWASP
Benchmark FPR is the share of safe test cases flagged. That is not 1 minus
precision, because about half the benchmark's cases are vulnerable by
design. NIST makes this point in
[Evaluating Bug Finders (2015)](https://www.nist.gov/system/files/documents/2021/03/24/Evaluating_Bug_Finders_COUFLESS_2015.pdf):
a tool that flags everything still scores 50% precision on such a set.

| Tool | Stated / measured figure | What the number measures | Scope | How measured, who labelled | Source (date) |
|---|---|---|---|---|---|
| **Google Tricorder** (internal) | < 10% "effective false positives" required for code-review checks; fleet-wide just below 5%; compiler (build-breaking) checks: **no** effective false positives | Share of findings developers did not act on, including real bugs they ignored | Per check, in code review | Developer "Not useful" vs "Please fix" clicks; checks disabled if they miss the bar | Sadowski et al., [CACM 61(4), 2018](https://cacm.acm.org/research/lessons-from-building-static-analysis-tools-at-google/); [Software Engineering at Google, ch. 20](https://abseil.io/resources/swe-book/html/ch20.html) |
| **SonarQube / SonarQube Cloud** | Target: vulnerabilities > 80% true positives; bugs and code smells "zero false-positives are expected" | Per-rule design target | Rule types | Vendor target, no measurement given | [Sonar rules docs](https://docs.sonarsource.com/sonarqube-cloud/standards/managing-rules/rules) (fetched 2026-10-26) |
| SonarQube | 3.2% false-positive rate | Share of user-reviewed issues marked false positive | 137 M issues users gave feedback on in 2025; all issue types, not security only | Users' own markings; self-selected sample | [Sonar blog, 2026-02-19](https://www.sonarsource.com/blog/how-sonarqube-minimizes-false-positives/) |
| SonarQube (independent) | Precision 0.99 (694/698; Wilson lower bound 0.985 by our arithmetic) | Precision | One Java app (OpenMRS), default security rules | Two researchers classified alerts; inter-rater check | Elder et al., [arXiv 2208.01595, 2022](https://arxiv.org/abs/2208.01595) |
| SonarQube Community 9.9 (independent) | Precision 51.9%, recall 95.6%, FPR 94.6% | Benchmark precision | OWASP Benchmark v1.2, **Java** | Benchmark expected results | Xiong & Zhang, [arXiv 2601.22952v2, 2026-06-27](https://arxiv.org/html/2601.22952v2) |
| **CodeQL** (independent) | Precision 60.3%, recall 97.0%, FPR 68.2% | Benchmark precision | OWASP Benchmark v1.2, Java | Benchmark expected results | [arXiv 2601.22952v2](https://arxiv.org/html/2601.22952v2) |
| CodeQL (independent) | 66% true positives (1,039/1,577) | Precision | 258 embedded C projects | Manual review by authors | [arXiv 2310.00205](https://arxiv.org/pdf/2310.00205) |
| CodeQL (independent) | Caught 7 of 81 applicable real CVEs (8.6%) | Recall | CWE-Bench-Java | CVE ground truth | [arXiv 2609.04535](https://arxiv.org/html/2609.04535v1) |
| CodeQL (vendor) | Each query tagged `@precision` low / medium / high / very-high; default suite keeps high and very-high | Qualitative per-query label | Per query | No numeric threshold published | [CodeQL metadata docs](https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/) |
| GitHub Copilot Autofix | Fixes "more than two-thirds" of found vulnerabilities with little or no editing | Fix quality, not detection precision | Supported CodeQL alerts | GitHub internal | [GitHub blog, 2024](https://github.blog/news-insights/product-news/found-means-fixed-introducing-code-scanning-autofix-powered-by-github-copilot-and-codeql/) |
| **Semgrep CE** (independent) | Precision 56.3%, recall 90.4%, FPR 74.8% | Benchmark precision | OWASP Benchmark v1.2, Java | Benchmark expected results | [arXiv 2601.22952v2](https://arxiv.org/html/2601.22952v2) |
| Semgrep Pro (vendor-commissioned) | 1 false positive on WebGoat, 0 on Juice Shop; TPR 72–75% | Counts on two training apps | Two deliberately vulnerable apps | Doyensec, paid by Semgrep | [Semgrep blog 2025](https://semgrep.dev/blog/2025/security-research-comparing-semgrep-community-edition-and-semgrep-code-for-static-analysis/) |
| Semgrep Assistant | "96% agreement" with researchers | Agreement on findings researchers called **true** positives (recall-like). Agreement on false positives: **41%** | 2,000+ findings | Semgrep's own researchers | [Semgrep blog, 2025-01-22](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/) |
| Semgrep Assistant | Users agree with auto-triage 95% of the time | User agreement with triage | 250,000+ findings, 45+ enterprises | User feedback | [Semgrep blog 2025](https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories/) |
| **Veracode** | "False positive rate under 1.1%" | Not defined | "Out of the box" | **No method, dataset or definition published** | [Veracode product page](https://www.veracode.com/security/static-analysis-tool/) (fetched 2026-10-26) |
| **Checkmarx** | ~5% FP (vendor); F1 0.64 for the 2026 hybrid engine | Not defined / F1 | Vendor-chosen set | Vendor | [Checkmarx press release, 2026-06-15](https://checkmarx.com/press-releases/checkmarx-one-achieves-industrys-highest-scanning-fidelity-outperforming-both-legacy-tools-and-ai-models/) |
| Checkmarx (third-party) | 36.3% FPR | Probably benchmark FPR | Legacy engine, reportedly OWASP Benchmark | Second-hand, via a 2024 Tolly report quoted by Mobb | [Mobb blog](https://www.mobb.ai/blog/sast-tools-false-positive-comparison) — **not verified** |
| **Fortify** | Audit Assistant "up to 98%" / "97% average" accuracy; SCA "100% TPR" on OWASP 1.2 | Accuracy of the triage model; TPR with no FPR given | Customer audits; benchmark | Vendor | [OpenText blog](https://blogs.opentext.com/increase-speed-and-accuracy-with-ai-driven-static-analysis-auditing/); [Fortify data sheet](https://www.microfocus.com/en-gb/media/data-sheet/fortify-static-code-analyzer-static-application-security-testing-ds-a4.pdf) |
| **Snyk Code** | OWASP Benchmark score 0.72 (2023) | Youden score (TPR − FPR) | OWASP Benchmark, language unstated | Vendor; no method | [Snyk Customer Value Study 2023](https://go.snyk.io/rs/677-THP-415/images/customer-value-study-2023.pdf) |
| Snyk Code (independent) | Precision 0.282, recall 0.167 (Python); precision 0.686, recall 0.523 (C#) | Precision / recall | RealVuln Python; C# benchmark | Hand labels (RealVuln); benchmark | [RealVuln, arXiv 2604.13764](https://arxiv.org/abs/2604.13764) (figures via search summary); [arXiv 2508.04448](https://arxiv.org/pdf/2508.04448) |
| **Coverity** | ~20% false positives (vendor's long-standing aim, "below 20% for stable checkers"); CMU estimate 12.7–35.7%, mean 24.2% | Share of findings false | Per checker / overall | Vendor statement; small academic study | Christakis & Bird 2016 (below); [Almossawi et al.](https://www.researchgate.net/publication/267853048_Analysis_Tool_Evaluation_Coverity_Prevent) |
| **Infer** (Meta) | False positives "less than 20%"; fix rate ~0% in batch mode vs > 70% at code review | Share false; share fixed | Production code at Facebook | Internal | O'Hearn et al., [CACM 2019](https://cacm.acm.org/research/scaling-static-analyses-at-facebook/) |
| **PVS-Studio** | 10–15% false positives after tuning; "9 of 10 warnings" real after configuration | Share false | One C project (EFL), tuned | Vendor case study | [PVS-Studio blog](https://pvs-studio.com/en/blog/posts/cpp/0523/) |
| **Bandit** (independent) | ~44% precision (81 TP / 186 flagged) | Precision | Command injection in 6 large Python projects | Manual verification | [arXiv 2505.15088](https://arxiv.org/pdf/2505.15088) |
| **eslint-plugin-security** | 50% precision overall (11/22); 20% for `detect-object-injection` | Precision | 78 hand-written patterns | Blog by a competing plugin's author | [ofriperetz.dev](https://ofriperetz.dev/articles/eslint-security-fn-fp-benchmark) — biased source |
| SpotBugs / FindSecBugs | Precision 0.877 / 0.689 | Precision | Non-standard "OWASP Top Ten Benchmark" (209 bad / 439 good functions) | Benchmark labels | [ResearchGate](https://www.researchgate.net/publication/342597384_Benchmarking_Approach_to_Compare_Web_Applications_Static_Analysis_Tools_Detecting_OWASP_Top_Ten_Security_Vulnerabilities) |
| All 7 Java SAST tools together (independent) | 12.7% of real CVEs detected | Recall | Java CVE benchmark | CVE ground truth | Li et al., [ESEC/FSE 2023](https://dl.acm.org/doi/10.1145/3611643.3616262) |
| **AI reviewers** (Greptile, CodeRabbit, Copilot code review, Claude) | Precision roughly 65–81%, recall roughly 47–60%, depending on snapshot | Share of review comments matched by later developer changes | Thousands of real PRs | **LLM-judge matching**, open-sourced | [Martian Code Review Bench](https://codereview.withmartian.com/) — figures via search summaries; **page not loaded, snapshots disagree** |
| Amazon CodeGuru | "High degree of precision" (no number); 0 TP / 18 FP in one study | — / precision | Null deref and use-after-free only | Vendor qualitative; independent small study | [AWS blog](https://aws.amazon.com/blogs/devops/detect-python-and-java-code-security-vulnerabilities-with-codeguru-reviewer/); [RepoAudit, arXiv 2501.18160](https://arxiv.org/pdf/2501.18160) |
| **Arbiter** (for comparison) | Verified tier: 690/690, lower bound 0.9945 (one rule). OWASP Python precision 0.883, recall 0.487. GHSA catch rate 8.1%. RealVuln multi-CWE Python recall 18.2%, precision 89.9% | Precision (lower bound) / recall | Held-out repos; benchmarks | Model labels (two labellers plus adjudicator), no human audit; benchmark truth | [precision.md](../precision.md), [accuracy-baseline.md](../accuracy-baseline.md) |

## Does anyone claim about 99%?

Not for security findings as a whole, and nowhere with published evidence.

- **Veracode "< 1.1% FP"** is the only headline at that level. Veracode
  publishes no dataset, definition or method, and third-party comparisons
  label it a vendor claim
  ([Konvu](https://konvu.com/compare/sca-vs-sast),
  [UnderDefense](https://underdefense.com/industry-pricings/veracode-pricing-2026-ultimate-guide-for-security-products/)).
- **Zero-false-positive targets do exist, but only for build-breaking or
  mechanical checks:** Google's compiler checks (none), Sonar's bug and
  code-smell rules (zero expected), and Fortify's IDE assistant ("only high
  confidence ... very low false positive rates", no number). This is the
  same design Arbiter uses: a small strict tier that can block, and
  everything else shown as advice.
- **"Perfect" OWASP Benchmark scores** exist, for example Fluid Attacks'
  claimed TPR 100% / FPR 0%
  ([docs](https://docs.fluidattacks.com/find-fix/use-cli/overview/scanner-results-owasp-benchmark)).
  The benchmark is public, so such scores show that a tool fits the
  benchmark, not that it is precise on real code. NIST itself warns
  against reading SATE results as tool rankings
  ([SP 500-326](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-326.pdf)).
- **Triage-AI figures in the 95–98% range** (Semgrep Assistant, Fortify
  Audit Assistant) are often read as precision, but they are not. Semgrep's
  96% is agreement on true positives only; on false positives its agreement
  was 41%.

## What users actually tolerate

- **Christakis & Bird (Microsoft, ASE 2016, 375 survey responses):** 90% of
  developers accept up to a 5% false-positive share, 47% accept up to 15%,
  and only 24% accept 20%. The authors recommend aiming "no higher than
  15–20%". Developers were split almost evenly on the trade-off: 49.3%
  would rather have fewer false positives even if real issues are missed,
  and 50.7% would rather find more real issues.
  ([PDF](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/What-Developers-Want-and-Need-from-Program-Analysis-An-Empirical-Study.pdf))
- **Johnson et al. (ICSE 2013, 20 interviews):** false positives and *how
  warnings are presented* are the main barriers to use. Some participants
  said volume would matter less with better presentation.
  ([PDF](https://cs.gmu.edu/~johnsonb/docs/icse2013.pdf))
- **Google (Sadowski et al. 2018):** under 10% for advisory checks in code
  review; zero for checks that break the build.
- **Meta Infer (O'Hearn et al. 2019):** with the same analysis and the same
  sub-20% false-positive rate, developers fixed almost nothing when reports
  arrived in batch, and over 70% when the same reports appeared in code
  review. Where and how a finding reaches the developer mattered more than
  a few points of precision.

Taken together: for advice, users accept 80–95% precision. For anything
that blocks their work, they expect close to 100%. They also care about
catching real bugs as much as about avoiding noise.

## Evaluation of Arbiter's bar

### Strictness

| Aspect | Arbiter | Market | Judgement |
|---|---|---|---|
| Precision target, gating tier | Lower bound ≥ 0.99 | Google: none; Sonar: zero for bugs (target only) | Comparable to the strictest practice. Appropriate. |
| Precision target, advisory findings | None (shown, cannot block) | 80–90% (Sonar vulnerabilities, Google review checks) | Arbiter has no stated bar here. This is a gap. |
| Statistic | 95% Wilson **lower bound** | Point estimates or "up to" | Stricter. A 99% point estimate on 100 findings has a lower bound of about 0.95. |
| Per category | Each dimension and CWE on its own | Usually one overall number | Stricter. |
| Held-out data | Yes, split by repository | Rarely stated | Stricter. |
| Recall target | Lower bound ≥ 0.99 (roadmap) | None claimed; measured real-world recall roughly 8–55% | Unrealistic. No tool comes close. |

### Strength of the evidence

**Stronger than the market:**
- It publishes counts, intervals and the held-out split.
- It refuses to borrow a claim from a better category.
- It states openly that the labels are model-made.

**Weaker than the market:**
- **Model labels with no human audit.** Independent studies (Elder et al.,
  Bandit, CodeQL embedded) use human reviewers. Vendor triage figures at
  least use their researchers or users. Arbiter's labeller is calibrated to
  a 0.99 lower bound only on injection, weak random/hash and deserialisation
  in benchmark code (382/382, lower bound 0.99004, which only just clears
  the bar). The verified rule is in the supply-chain category. There the
  labeller calibration is 18/18, lower bound 0.824. The 0.9945 figure
  therefore inherits an uncertainty its interval does not show.
- **No allowance for findings clustering in the same repository yet.** The
  roadmap says repository-clustered intervals are needed, and the baseline
  says the current ledger does not apply them. 690 findings from 50 repos
  are fewer independent samples than 690.
- **The two docs conflict.** `precision.md` allows a claim worded "by
  independent model labels and external ground truth". Evidence rule 2 in
  `accuracy-roadmap.md` says model labels "cannot independently certify a
  claim". Until that is settled, there is no internally agreed basis for any
  public 99% statement.

### Where the bar is misaligned with what users value

1. **The scope is too small to mean what "99%" sounds like.** One verified
   rule out of 263 shipped. Users judge the whole report. Arbiter's own
   ARB-100 incident showed this: the verified-only view hid 404 of 404
   planted defects.
2. **The recall half is not realistic.** 99% recall with a lower bound
   cannot be demonstrated on real code. It would take thousands of
   independently audited defects per segment, and no tool's measured recall
   is within an order of magnitude of it. Arbiter's own figures (8.1% GHSA,
   18.2% RealVuln, 4% AI held-out) show recall is the bigger gap. Users
   split 50/50 on preferring recall, so it should have a bar of its own that
   is realistic and benchmark-specific.
3. **A single 0.99 for every category ignores how different the categories
   are.** For exact-signature rules (pinned actions, key headers), 0.99 is
   easy and reasonable. For taint-style injection, no tool reaches it on
   independent benchmarks: the best measured Java OWASP precision is
   60% (CodeQL), and Arbiter's Python OWASP precision is 0.883. Holding
   injection to 0.99 means those findings will stay advisory for good. That
   is defensible for blocking, but it should not be the only number users
   see.
4. **No bar at all for advisory findings.** Advisory findings are most of
   what users read. The market norm (Google < 10% ignored; Sonar > 80%
   true; Christakis 80–85%) gives a sensible second bar.

## Recommendations

1. **Keep 0.99 (lower bound) as the bar for blocking the gate.** It matches
   Google's and Sonar's rule for build-breaking checks and is a real
   differentiator. Do not lower it.
2. **Add a second, published bar for advisory findings:** a lower bound
   ≥ 0.80 per rule, or ≥ 0.85 to match the Christakis and Bird majority.
   Rules below it should be off by default, not just labelled advisory.
3. **Replace the 99% recall target** with per-benchmark recall reported
   with intervals: GHSA fix pairs, RealVuln, OWASP, AI held-out. Set
   improvement targets per weakness family. Make no generic recall claim.
4. **Report coverage next to precision every time,** for example: "verified
   tier: 1 of 263 rules; 2 of 73 findings in this report". A precision
   figure without its coverage misleads.
5. **Settle the labelling rule before any public number.** Either align
   `precision.md` with roadmap rule 2 (model labels give "model-labelled
   conformance" only), or set out what human spot check upgrades a claim.
   `precision.md` already proposes a 50-finding human spot check. Doing it
   for `supply.unpinned-action` is cheap and would make Arbiter the only
   tool in this comparison with a human-checked, interval-bounded,
   held-out precision figure.
6. **Only claim a category where the labeller is calibrated for it.** A
   rule's lower bound should not be read as 0.99 unless the labeller's
   lower bound in that category is also ≥ 0.99. Apply repository-clustered
   intervals before publishing.
7. **Present results the way the evidence shows users respond to.** Post
   findings in code review, not in batch reports (the Infer result). Report
   like Google: per-check rates of findings users acted on, collected from
   real use, alongside the labelled lab figures.
8. **Public wording:** "Verified findings — the ones that can fail your
   build — are measured at ≥ 99% precision (95% lower bound) on held-out
   repositories, per rule, by independent model labellers; X of N rules
   currently qualify." Never "99% accurate".

## Could not verify

- **Coverity's per-language ~20% FP table.** The Black Duck knowledge-base
  page did not load. The ~20% is supported by Christakis & Bird (citing
  Coverity's designers) and the CMU study, not by the vendor page.
- **Martian Code Review Bench.** The page did not load. The precision and
  recall ranges above come from search summaries, and the snapshots
  disagree.
- **RealVuln per-tool precision and recall** (Snyk 0.282 / 0.167). The
  abstract page did not list them; the figures come from a search summary.
- **Checkmarx 36.3% FPR.** Second-hand via Mobb; the OWASP Benchmark
  attribution is uncertain.
- **Veracode < 1.1%, Snyk 0.72 OWASP score, Fortify 97–98%.** These are
  vendor claims with no published method.
- **Official OWASP Benchmark scorecards for FindSecBugs, CodeQL and
  commercial tools.** Not found.
- **gosec, Brakeman, Copilot code review (standalone), Amazon Q.** No usable
  quantitative precision data found.
- **NIST SATE V per-tool false-positive rates.** Not retrieved. The often
  quoted "30–70%" comes second-hand via a vendor blog
  ([Cycode](https://cycode.com/blog/ai-sast/)).
- The Johnson et al. 2013 figures are from the abstract and secondary
  summaries. The Christakis & Bird figures were checked against the paper's
  text.
