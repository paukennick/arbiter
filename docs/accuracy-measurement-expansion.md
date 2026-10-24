# External Accuracy Measurement Expansion

This is a source-vetting and study-design record for the next accuracy
measurements. It is not a scan result or a 99% claim. The immediate work is
split into (1) real-repository finding precision, using Semgrep and CodeQL as
differential signals with blinded model labels for now; (2) external
AI-generated-code conformance; and (3) expanding the existing RealVuln
measurement beyond Python CWE-89.

## Status and guardrails

- No new benchmark source or repository snapshot was downloaded or scanned
  for this design.
- `semgrep` 1.177.0 and its locked rules are available locally. CodeQL is not
  installed or provisioned in the current environment.
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

The current priority is the cleared 11-repository RealVuln Python subset:
first inventory the pinned ground truth and, if all eligible labels and
non-scoring exclusions validate, assess its eligible CWE cases at those
commits. Then expand to another language or AI-authorship stratum only after
repository-level license and permission checks. This preserves the previous
source scope while increasing weakness coverage. Do not mix non-scoring
entries into either side of the metric.

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

The current environment has Semgrep but not CodeQL. Before installing a pinned
CodeQL CLI and query pack, record their versions in the study manifest. Use
CodeQL's `--build-mode none` where supported; the current CLI documentation
lists C#, Java, JavaScript/TypeScript, Python, and Ruby. Do not invoke
autobuild/manual builds or benchmark evaluation scripts that run target code.
If static extraction cannot be completed without building or executing
untrusted code, mark that language/repository not assessed and state why.

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

1. Confirm exact RealVuln pinned metadata, repository-level source rights,
   and eligible scoring labels; do not fetch source code until the selected
   subset is approved.
2. Implement and test an aggregate-only multi-CWE evaluator over the
   already-cleared repository subset, preserving the existing matcher and
   historical pilot record. Treat non-scoring and unmatched findings
   explicitly.
3. Confirm CodeQL CLI/query-pack installation and no-build extraction for
   each selected language. Revalidate Semgrep version and rules lock.
4. Freeze the repository split, model labeler/rubric, run record, and analysis
   before running the differential. Do not tune rules on the evaluation data.
5. Publish only aggregates, provenance, denominators, coverage, and
   model-label limitations. Keep case-level results private unless their
   source license explicitly permits release.

No expanded evaluator, CodeQL scan, model-label run, or new RealVuln accuracy
result has been produced by this design. The first bounded experiment should
inventory then, if eligible-label validation passes, run an aggregate
evaluation over the already-cleared 11 RealVuln Python repository pins;
cross-language and AI-authorship expansion follows source-rights verification.
