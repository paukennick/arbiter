# Command Reference

Twelve subcommands. Every command reads and writes files; none executes the
target repository.

## Contents

- [Analysis](#analysis)
- [Baselines and comparison](#baselines-and-comparison)
- [Adjudication and calibration](#adjudication-and-calibration)
- [Integrity and compliance](#integrity-and-compliance)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)

---

## Analysis

```bash
arbiter scan ./repo                             # analyze and report
arbiter scan --system arbiter-system.yaml       # several repos, one verdict
arbiter scan . --tfplan tfplan.json             # read a Terraform plan
arbiter scan . --profile connected              # override the configured profile
arbiter scan . --pin-knowledge k:4cf3d3fa2f02   # freeze calibration for a release gate
arbiter gate ./repo --baseline .arbiter/baseline.json   # exit 1 on policy failure
arbiter probes ./repo                           # what can run here, and why not
arbiter explain f:8c41d2ae9b07                  # one finding in full
```

`scan` reports. `gate` reports and enforces — it is the form to use in CI, where
the exit code is the product. See [configuration.md](configuration.md#gating)
for the thresholds it reads.

## Baselines and comparison

```bash
arbiter baseline arbiter-out/report.json        # snapshot current state
arbiter diff before.json after.json             # new / fixed / unchanged
arbiter ab --spec examples/ab-native-vs-checkov.yaml --out ab-out
```

`diff` accepts `--format console,json,markdown,pr-comment`.

A baseline is what makes "fail on new findings only" usable: findings are
matched by fingerprint, which deliberately excludes the line number, so
reformatting a file does not invalidate it. See
[architecture.md](architecture.md#fingerprinting).

The A/B harness is documented in [ab-testing.md](ab-testing.md).

## Adjudication and calibration

```bash
arbiter review arbiter-out/report.json          # adjudicate a batch in one pass
arbiter review report.json --html               # ...as a page you can tap through
arbiter review report.json --interactive        # ...or one keypress each, in the terminal
arbiter review --apply arbiter-out/review.md    # record the verdicts
arbiter feedback f:8c41 --false-positive        # adjudicate a single finding
arbiter learn                                   # what has been learned, and what it supports
```

Why this ledger is the only input to calibration, and how the batch is chosen,
is covered in [calibration.md](calibration.md).

## Integrity and compliance

```bash
arbiter verify arbiter-out/report.json          # does any claim outrun its basis?
arbiter verify arbiter-out/report.json --show-claims
arbiter controls arbiter-out/report.json        # control coverage, including the gaps
arbiter controls arbiter-out/report.json --framework FedRAMP-Moderate-r5
```

See [evidence.md](evidence.md#claim-integrity) and
[compliance.md](compliance.md).

---

## Output formats

```bash
arbiter scan . --format json,sarif,html,markdown,console
```

JSON is canonical and is written first; every other format is a rendering of it.
Anything a renderer shows can be recomputed from the JSON, and no format carries
a fact the JSON does not.

| Format | Use |
|---|---|
| `json` | canonical record; input to `baseline`, `diff`, `verify`, `controls`, `review` |
| `sarif` | inline annotations on a pull request |
| `html` | a self-contained page, no server and no network |
| `markdown` | PR comments and reports for people |
| `console` | terminal output, the default alongside `json` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | pass |
| `1` | gate failure |
| `2` | error |

A gate failure is a policy decision and is reported as such. An error means
Arbiter could not complete the run — it never degrades into a pass.
