# Blinded Accuracy Review Protocol

This protocol defines how to obtain independent labels for Arbiter finding
precision and missed-defect recall. It is a procedure, not a completed review
or an accuracy result. The current RealVuln CWE-89 pilot remains benchmark
conformance against maintainer-authored labels; this protocol does not upgrade
those labels or certify the 99% target.

## Non-negotiable safeguards

1. **Freeze the claim and population first.** Name the weakness, languages,
   frameworks, repository population, operating systems, architectures, and
   toolchain versions to which the planned result could apply. Mark untested
   strata as unproven. Do not generalize from a convenience sample.
2. **Use separate development and evaluation data.** Split by repository or
   repository family before tuning. Keep the final evaluation labels and
   sampled cases sealed from rule authors. The already-run RealVuln subset is
   exploratory evidence, not a fresh sealed holdout; re-reviewing it cannot
   make it untouched.
3. **Freeze Arbiter before evaluation.** Record the commit, clean/dirty state,
   configuration, enabled probes, analyzer and database versions, runtime,
   host OS/architecture, evaluator version, and input snapshot digests. Do not
   tune rules, thresholds, or matching logic on evaluation labels or findings.
   Any such change invalidates that evaluation as a final holdout.
4. **Keep the reviewer blind.** An independent coordinator controls case
   selection and label access. Reviewers must not see Arbiter findings,
   detector/rule names, rule rationale, expected labels, or another reviewer's
   decisions before submitting their own assessment.
5. **Obtain two independent assessments.** Each sampled item is assessed
   independently by two qualified reviewers. A third qualified adjudicator,
   not involved in rule development, resolves disagreements. Preserve both
   original assessments and the resolution; do not overwrite disagreement.
6. **Do not force certainty.** Permit `unresolved`, `insufficient evidence`,
   and `out of scope` outcomes. Report these counts and their effect on
   denominators. They are not silently treated as correct detections or safe
   code.
7. **Protect data and licensing.** Before acquisition or sharing, verify
   source licenses, terms, and permissions for the planned review and
   publication. Restrict source and label access to authorized reviewers;
   publish aggregates only unless redistribution is explicitly permitted.
   Do not open Arbiter's sealed AI or gold corpora as part of this protocol.

## Roles and independence

- **Study owner:** pre-registers the population, sampling plan, matching
  criteria, and analysis; does not expose sealed labels to rule authors.
- **Independent coordinator:** has access to scan outputs and ground truth,
  draws the sample, creates blind packets, and keeps the mapping private.
  The coordinator must not have authored or tuned the rules being evaluated.
- **Reviewers A and B:** have relevant secure-code-review expertise and no
  role in developing the evaluated rules. They review independently and
  record evidence before seeing the other review.
- **Adjudicator:** resolves disagreements using the pre-registered criteria
  and records a reason. The adjudicator must not be a rule author.

Record each reviewer's relevant expertise, conflict-of-interest declaration,
and training completed. Use a separate training set to align on the rubric;
do not use evaluation cases to train reviewers.

## Evaluation preparation

Before the scan or review begins, create a dated, access-controlled study
record containing:

- the claim and applicability matrix, including unsupported and unassessed
  strata;
- the repository sampling frame, repository-family grouping, inclusion and
  exclusion rules, and target population;
- separate sampling frames for reported findings and independent miss audits;
- the randomization method and seed custodian, inclusion probabilities, planned
  sample sizes, and handling of non-response or inaccessible code;
- the frozen scanner, evaluator, source snapshot, configuration, environment,
  and tool/database provenance;
- the pre-registered weakness/location matching rubric, outcome categories,
  estimators, confidence interval method, and stopping rule;
- license and data-handling approvals, reviewer assignments, and retention
  limits.

Choose sample sizes from the intended confidence-bound claim and expected
repository clustering, not from a desired pass result. A simple independent
sample with no errors needs about 381 observations for a two-sided 95% Wilson
lower bound to reach 99%; this is only an intuition, not a sufficient sample
size for clustered repositories or weighted strata.

## Track A: reported-finding precision

1. Run the frozen scanner on the sampled repositories. The coordinator draws
   findings using the pre-registered strata and probabilities, including
   unreviewed findings. Keep a private mapping from blind case IDs to findings.
2. Prepare a packet with the minimum code and configuration context needed to
   decide whether a real, in-scope weakness exists at the reported location.
   Remove Arbiter identity, rule/detector identifiers, rationale, confidence,
   tier, and prior verdict. Do not add context that discloses the expected
   answer.
3. Each reviewer independently records one outcome: `real_issue`,
   `false_positive`, `out_of_scope`, or `unresolved`; the relevant weakness
   and location; impact and evidence; and a concise rationale. Reviewers must
   cite the code/configuration evidence they examined.
4. The coordinator matches the two assessments. The adjudicator resolves
   disagreements under the frozen rubric and records the reason and evidence.
   Preserve all initial and final labels.
5. Estimate precision using the pre-declared sampling weights and denominator.
   Report unresolved, excluded, and out-of-scope counts separately. Do not
   count an unassessed finding as a confirmed true positive.

## Track B: repository-level missed-defect recall

1. Draw repositories independently of Arbiter's findings from the declared
   repository frame. Within repositories, draw files, components, or other
   auditable units independently of known vulnerable labels and reported
   findings, using recorded inclusion probabilities.
2. Reviewers receive the selected code/configuration scope and the weakness
   rubric, but not Arbiter findings, ground-truth labels, or known vulnerable
   locations. They inspect the scope for in-scope defects and record the
   files, paths, and review coverage, including areas they could not inspect.
3. Each candidate defect is independently assessed by both reviewers. The
   adjudicator resolves disagreements. The coordinator then compares
   independently confirmed defects with frozen Arbiter output using the
   pre-registered weakness and location-matching criteria.
4. Record confirmed misses, confirmed detections, unresolved candidates,
   inaccessible scope, and audit coverage. A repository with no reported
   findings is not automatically a true negative; only documented,
   independently audited scope contributes evidence.
5. Estimate recall only over the independently established in-scope defects
   and the declared sampled population. Weight for the sampling design and
   report limitations from incomplete review coverage.

Finding precision and repository miss-audit recall are separate tracks with
separate denominators. Do not substitute a benchmark's known labels for the
independent miss audit.

## Analysis and publication

- Report precision, recall, assessed coverage, exclusions, unresolved labels,
  and reviewer agreement for every pre-declared applicable stratum.
- Respect repository clustering and unequal inclusion probabilities with a
  validated design-based estimator, repository-cluster bootstrap, or
  pre-validated hierarchical method. State the method, seeds, assumptions, and
  effective sample sizes. Do not treat findings from one repository as
  independent observations.
- Publish numerators, denominators, weights, confidence intervals, sampling
  coverage, tool provenance, label provenance, and deviations from protocol.
  Publish aggregates only when license or confidentiality terms prohibit
  case-level disclosure.
- A 99% claim requires the pre-declared 95% lower confidence bound to be at
  least 99% for both precision and recall in each claimed, adequately sampled
  segment. Insufficient sample size, incomplete audit coverage, weak labels,
  or a failed bound means no claim for that segment.
- Any protocol deviation, unblinding, tuning on evaluation data, or material
  mismatch between the frozen run and analyzed output must be disclosed; the
  affected result cannot support a sealed-holdout claim.

## Current readiness

ARB-104 documents this process only. No independent reviewers have been
engaged, no review packets have been produced, no new benchmark has been
approved, and no independent labels or miss audits have been collected. The
next execution gate is to secure reviewer and coordinator availability,
approve the source/license and sampling plan, and freeze the study record
before sharing any cases.
