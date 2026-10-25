# External Accuracy Measurement Expansion

This records the source-vetting design and completed additive measurement
executions. It is not a 99% claim. The immediate work is
split into (1) real-repository finding precision, using Semgrep and CodeQL as
differential signals with blinded model labels for now; (2) external
AI-generated-code conformance; and (3) expanding the existing RealVuln
measurement beyond Python CWE-89.

## Status and guardrails

- ARB-105 was a design-only milestone. ARB-106 later reacquired and scanned
  only the 11 previously approved pinned MIT/Unlicense Python repositories;
  the sources and per-repository reports were kept in temporary storage.
- ARB-107 completed a pinned Arbiter/Semgrep/CodeQL differential on those same
  11 snapshots. It reports analyzer coverage and location overlap only; it is
  not the ordinary-repository precision study.
- ARB-108 froze an 11-repository ordinary Python feasibility cohort before
  scanning. Exact pins and MIT license-file digests are recorded in the
  benchmark manifest; no project source snapshots have been acquired and the
  cohort has not been scanned.
- No benchmark target code was executed. The committed output contains
  aggregate labels and differential counts only.
- Semgrep 1.177.0 and its locked rules were used. CodeQL 2.27.3 and the pinned
  `codeql/python-queries@1.8.13` pack were provisioned for the rehearsal.
- Semgrep/CodeQL agreement is **not ground truth**. Each tool has its own
  coverage, rule semantics, false positives, and false negatives.
- Until human review is available, sampled labels produced by a model must be
  reported as **model-labelled conformance**. They are not independent
  adjudication, audited truth, or a basis for certified 99% precision or
  recall.
- Only public source snapshots with documented permissions may be sent to a
  hosted model. Do not submit private code, secrets, or sealed benchmark
  material. Do not execute benchmark source code.
- Keep the existing RealVuln pilot's matcher unchanged: exact
  repository-relative file path, intersecting accepted CWE, and line-span
  overlap with the benchmark's +/-10-line tolerance. An unmatched
  CWE-89 finding remains unassessed, not a false positive.

## Source review

| Source | What it can contribute | Readiness and limitations |
|---|---|---|
| [RealVuln, pinned at `7a710251`](https://github.com/kolega-ai/Real-Vuln-Benchmark/tree/7a710251f55c17d32d3adcb13d37468e2e3b9e4a) | The pinned manifest reports 140 repositories, 4,138 vulnerable findings, 280 Python false-positive traps, 176 non-scoring entries, and 92 primary CWEs across Python, JavaScript, and TypeScript. It identifies 90 end-to-end LLM-generated applications (40 Python and 50 TypeScript/JavaScript) and records authorship model by repository. This is the strongest immediate source for extending the current real-code study and measuring AI-generated applications. | The benchmark project reports Apache-2.0, but that does not establish the license of every linked source repository or authorize redistribution of its source. The existing pilot cleared only its 11 MIT/Unlicense Python repositories. The full generated corpus is **not yet cleared**: verify each repository's pinned license and data terms before acquisition. All targets are intentionally vulnerable applications, so this is benchmark conformance, not a representative production-repository sample. The published benchmark and embedded ground-truth versions are separate (`3.1.0` and `3.0.0`) and must remain so. Java is not in this release. |
| [SecurityEval repository](https://github.com/s2e-lab/SecurityEval) and [dataset card](https://huggingface.co/datasets/s2e-lab/SecurityEval) | Version 2.1 describes 121 Python code-generation prompts spanning 69 CWEs. The repository also describes older Copilot and InCoder outputs and manual-analysis result files. | GitHub repository and dataset card do not declare a license. The artifact is prompt/snippet-level and its existing model outputs are historical; it is not a repository-level production sample. **Do not download, redistribute, or score until the dataset and code-example rights and the exact label provenance are confirmed.** |
| [RealSec-Bench](https://github.com/DeepSoftwareAnalytics/Realsec-code-Bench) | Describes evaluating LLM-generated code for real-world repository tasks with CodeQL and a multi-LLM voting mechanism. It may inform an external AI-code comparison. | GitHub reports no repository license. Its documented evaluation pipeline includes executing generated code; that behavior is outside this study's no-target-execution boundary. **Do not run it.** Reconsider only after licensing is resolved and a static-only, non-executing path is independently verified. |
| [MT-Sec](https://github.com/santaboi/Multiturn-secure-code-generation-benchmark) | Potential source of multi-turn secure-code generation tasks. | No repository license is declared, and the reviewed README provides insufficient information about a fixed corpus, ground-truth labels, and scanner-compatible source snapshots. **Not ready for measurement.** |

The multi-CWE label inventory and the first cross-analyzer differential are
complete for the cleared 11-repository RealVuln Python subset. This preserves
the approved source scope while extending weakness coverage and measuring
tool disagreement; it does not estimate production precision. Expand to
another language or AI-authorship stratum only after repository-level license
and permission checks. Do not mix non-scoring entries into either side of the
label-conformance metric.

## Real-repository precision: differential plus blinded labels

### Comparison design

Use an approved, predeclared cohort of ordinary public repositories for the
real-repository precision estimate. Do not treat intentionally vulnerable
training applications such as RealVuln as a representative production sample;
use them for labeled benchmark conformance only.

1. Freeze a documented repository sampling frame and select repository
   snapshots before scanning. Separate development repositories from the
   evaluation sample by repository or family.
2. Run Arbiter, Semgrep, and CodeQL on the exact same checked-out snapshots.
   Pin Arbiter commit/configuration, Semgrep binary and rules revision,
   CodeQL CLI and query-pack versions, OS/architecture, and scan settings.
   Record unavailable tools and unsupported language features as not assessed.
3. Build a finding comparison table using repository-relative path, CWE
   (where each analyzer supplies a defensible mapping), and overlapping source
   spans. Keep raw analyzer IDs and source-specific severity separately;
   do not imply that similarly named rules or severities are equivalent.
4. Report overlap and tool-unique findings by language and weakness as
   **differential coverage**, not accuracy. A finding emitted by two tools is
   not thereby a true positive; a finding emitted by one tool is not thereby
   false.
5. Estimate Arbiter precision from a predeclared, stratified sample of Arbiter
   findings, including both findings that agree and disagree with the other
   tools. Preserve inclusion probabilities and weight to the declared target
   population. Use repository-cluster-aware uncertainty.

### Interim model-labelled mode

For the current owner-approved interim, a model may label blind packets from
the precision sample. Remove analyzer identity, rule identifiers, tool
rationale, severity, confidence, and agreement status before sending a packet
to the labeler. Apply one frozen rubric and the same packet shape to every
tool's findings; allow `real_issue`, `false_positive`, `out_of_scope`, and
`unresolved`. Do not expose expected benchmark labels or prior model answers.

Record, at minimum, labeler provider and exact model/version, timestamp,
prompt/rubric version and digest, inference settings, packet digest, output
schema/version, raw-response retention policy, and all unresolved or failed
labels. If multiple models are used, preserve each model's independent output
before any reconciliation and report their disagreement. Model agreement is
not independent human verification. Label results and all metrics that depend
on them **model-labelled conformance**; do not call them audited truth or
certified precision. Human reviewers remain necessary for a human-grounded
accuracy claim.

Model-labelled finding review alone cannot establish recall. Recall needs
independently established defects from eligible benchmark labels or a
predeclared repository miss audit, with any model-generated labels reported
separately and without a human-truth claim.

### Safe CodeQL extraction

ARB-107 provisioned CodeQL CLI 2.27.3 and the locked Python query pack
`codeql/python-queries@1.8.13` with its dependency lock. The Python database
used `--build-mode none`; all 11 invocations succeeded and extracted 459/459
Python files without running a project build or target command. This verifies
only the selected Python snapshots. Do not invoke autobuild/manual builds or
benchmark evaluation scripts that run target code. If static extraction
cannot be completed without building or executing untrusted code, mark that
language/repository not assessed and state why.

## ARB-106: first multi-CWE baseline

All 502 pinned label entries validated across the 11 approved repositories:
65 distinct primary CWEs and no explicit `non_scoring` entries. The scored
population is limited to 408 entries with `evidence.source=manual_review`,
covering 53 primary CWEs. The other 94 labels are reported by provenance and
excluded from the score: 75 `our-scanner`, 13
`gt_expansion_verification_2026_04_29`, five `snyk`, and one `walkthrough`.
Within the included 408, 66 entries explicitly set
`manually_verified=true`. These are benchmark-maintainer labels, not
independent multi-reviewer adjudication.

The offline `lang_python` probe ran on all 11 pinned source snapshots; all 11
overall scorecards were withheld because other probes were not assessed. On
the manual-review cases, the result was TP 62, FN 279, FP 7, TN 60: labelled-
case precision 62/69 (89.9%), recall 62/341 (18.2%), and safe-trap false-
positive rate 7/67 (10.4%). The descriptive 95% repository-cluster bootstrap
intervals were 84.5%–94.7% for precision and 13.0%–23.8% for recall. Twenty-
five findings did not match included labels and remain unassessed.

The largest miss buckets were CWE-79 (0/37 positive cases detected), CWE-798
(1/22), CWE-918 (0/18), CWE-400 (1/18), CWE-22 (0/17), and CWE-639 (0/13).
These are aggregate prioritization signals only; no case-level examples were
inspected and no rules were tuned on this benchmark. The multi-CWE evaluator
reproduces the historical CWE-89 counts exactly, and neither its matcher nor
the prior CWE-89 run record was changed. This is curated benchmark
conformance—not finding-level precision, independent truth, production
accuracy, or a 99% claim.

Full aggregate results and environment, source, label, and report digests are
in [accuracy-realvuln-multicwe-run.json](accuracy-realvuln-multicwe-run.json);
the benchmark manifest references its digest.

## Run-record and matcher compatibility

Keep `docs/accuracy-benchmark-manifest.json`'s generic `run_record_template`
stable and use its fields for each study: Arbiter commit and worktree state,
benchmark pin/digest, evaluator commit, configuration digest, analyzer/rule
versions, database snapshot, OS image, architecture, Python version, profile,
cache policy, timestamps, counts, and metrics.

The existing `evaluation_run` instance for the RealVuln CWE-89 pilot is
intentionally narrower: it fixes `probe` to `lang_python` and names
Python/CWE-89-specific counts. Do not rewrite that historical record to fit a
new language or CWE. New studies must be recorded as separate versioned run
records; if the shared schema must be generalized, coordinate the additive
schema change before changing the established template or the matching rules.
The current evaluator's case-matching behavior remains unchanged.

## Execution gates

1. Completed for the previously cleared 11 Python pins: exact metadata,
   source commits, labels, and source permissions were validated; no other
   repositories were acquired.
2. Completed: an additive aggregate-only multi-CWE evaluator was implemented
   and tested. It scores only `manual_review` labels, records exclusions and
   unmatched findings, and preserves the existing matcher and historical
   CWE-89 record.
3. **Completed for the selected Python snapshots:** verified the CodeQL CLI
   checksum, locked query pack, no-build extraction, and Semgrep version/rules
   pin. Other language extractors remain untested.
4. **Completed for this differential:** the repository pins and tool settings
   were frozen before scans; no rules were tuned on the evaluation data.
5. **Completed for this differential:** published only aggregate counts,
   provenance, file coverage, and matching limits; case-level results remain
   temporary.

The ordinary public-repository precision sample, blinded labels, independent
human audit, other-language CodeQL extraction, and cleared external
AI-authorship expansion remain future work. The RealVuln differential does not
substitute for any of them.

## ARB-108: frozen ordinary-repository precision cohort

The pre-scan cohort is recorded in
`docs/accuracy-benchmark-manifest.json` under
`ordinary_repository_precision_pilot`. It was drawn from 100 GitHub search
results filtered to Python, MIT metadata, 100–10,000 stars, pushed after
2025-01-01, non-forks, and non-archived repositories, sorted by descending
stars. Repository names and public descriptions were screened for ordinary
Python libraries, frameworks, packages, clients, servers, applications, and
developer tools; benchmark/dataset, tutorial/course, security-focused,
AI/LLM, research, bot, and social/consumer automation projects were excluded.

The 17 eligible repository identifiers and their frozen popularity order,
sample size (11), and `random.Random(108).sample` seed are in the manifest.
All selected snapshots have full commit pins and MIT license evidence queried
at each exact commit, including the license path, Git blob SHA, and SHA-256 of
the license bytes. Identifier-only overlap checks found no selected repository
in Arbiter's 24-repository gold set or the 11-repository RealVuln subset; no
finding labels or target source were accessed during this screening.

This is a popularity-biased feasibility sample, not a probability sample or
representative production-repository population. It is not accuracy evidence.
The cohort is frozen but unscanned; acquire and scan only these exact snapshots
in the next measurement stage. A separate independent coordinator/reviewer is
still required before blinded human labels or a human-grounded accuracy claim.
