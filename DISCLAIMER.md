# Disclaimer

This page says in plain language what Arbiter's results do and do not mean.
It explains the [licence](LICENSE); it does not replace or narrow it. Where
the two differ, the licence governs.

## Provided as is

Arbiter is provided "as is", without warranties or conditions of any kind,
and its contributors are not liable for damages arising from its use. Those
terms are sections 7 (Disclaimer of Warranty) and 8 (Limitation of Liability)
of the Apache License, Version 2.0, in [LICENSE](LICENSE). Read them there.

## Findings are not a security guarantee

- A finding means a check matched something. It may be wrong: every rule has
  false positives, and most rules have not yet been measured well enough to
  say how often.
- **No findings does not mean secure.** It means the checks that ran found
  nothing. Arbiter catches a minority of real defects: on the AI-written test
  services it is measured against, its native probes detect well under half of
  the labelled code defects ([docs/testing-harness.md](docs/testing-harness.md#what-the-numbers-say)).
  Whole classes of problem (business logic, authorisation design, anything that
  needs the code to run) are out of its reach.
- Every report lists what was **not assessed** and why. A check that did not
  run is not a check that passed.

## Precision figures and tiers are estimates

Precision figures, confidence intervals and the `verified`, `advisory` and
`inferred` tiers are **measured estimates on stated corpora**, not guarantees
about your code. They come from labelled samples of specific public
repositories, benchmarks and generated test services, at a recorded date and
labeller version, and they carry statistical uncertainty. A rule that is
precise on those corpora can be wrong on yours. How the figures are produced,
and their current values, are in [docs/precision.md](docs/precision.md).

A `verified` tier is a statement about a rule's measured track record and,
where a model was asked, one model's verdict on one excerpt. It is not a
statement that a human reviewed the finding or that the code is defective.

## Control mappings are not certification or compliance advice

Arbiter ships control packs that map its checks to frameworks, including the
2024 CWE Top 25, NIST SP 800-53, 800-171 and 800-218, FedRAMP Moderate,
CMMC Level 2, CIS Controls, PCI DSS, SOC 2 Trust Services Criteria and the
HIPAA Security Rule ([docs/compliance.md](docs/compliance.md),
[docs/cwe-top25.md](docs/cwe-top25.md)).

- A mapping says which checks bear on a control. It does **not** certify,
  attest to or audit compliance with any framework, and a clean scan is not
  evidence that a control is met.
- A control shown as `satisfied` means only that a check mapped to it ran and
  found nothing. It is not a determination that the control is met.
- Most controls are about processes, people and operations that no scan of a
  repository can see; the coverage report marks those `not_automatable` or
  `no_coverage`.
- Nothing Arbiter produces is legal, regulatory or compliance advice. The
  framework owners, your auditors and your own advisers decide what
  compliance means for you. Arbiter is not affiliated with or endorsed by
  MITRE, NIST, the PCI Security Standards Council, the AICPA, CIS, the US
  Department of Health and Human Services or any other framework owner.

## You make the decisions

You are responsible for what you do with Arbiter's output, including:

- whether a finding is real and whether to act on it;
- any change you make in response, whether it follows a rule's remediation
  text, a model's verdict or reason, or an AI assistant acting on a report;
- **inferred** findings, which come from a model's reading of your code,
  can be wrong in ways a deterministic rule cannot, and do not gate a build
  unless you configure them to;
- model verdicts from the verification pass, which are one model's opinion
  on a bounded excerpt;
- whether to send code to a model provider at all
  ([PRIVACY.md](PRIVACY.md)).

## No professional relationship

Using Arbiter, reading its documentation or filing an issue does not create
a consulting, advisory, auditing, legal or any other professional
relationship with the copyright holder or contributors.

## Export control and sanctions

Arbiter is open-source software published without restriction on a public
repository. Its maintainers make no export classification claim for it (no
ECCN or other designation is asserted). You are responsible for complying
with the export-control and sanctions laws that apply to you, including when
you download, use, redistribute or provide access to Arbiter, or a service
built on it, in or to another country, or for a restricted person or end use.
