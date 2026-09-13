# Control Coverage

Five government framework packs ship with Arbiter:

| Pack | Framework |
|---|---|
| `nist-800-53r5` | NIST SP 800-53 Rev. 5 |
| `nist-800-171r2` | NIST SP 800-171 Rev. 2 |
| `nist-800-218-ssdf` | NIST SSDF (SP 800-218) |
| `fedramp-moderate-r5` | FedRAMP Moderate Rev. 5 |
| `cmmc-l2` | CMMC Level 2 |

Each is an **independent** pack — controls map straight to checks, never routed
through a hub framework, because chaining two approximate crosswalks produces a
compliance claim two translations removed from anything that ran.

Packs are data files in `src/arbiter/packs/controls/`, not code.

## The five states

Every control resolves to one of five states, and the split between the last
three is the entire point:

| State | Meaning |
|---|---|
| `satisfied` | A covering check ran, applied, and found nothing. |
| `violated` | A covering check fired. |
| `not_assessed` | A check covers this on paper but did not run here — tool absent, value unknown until apply. **Not a pass.** |
| `no_coverage` | Assessable in principle; Arbiter has no check for it. |
| `not_automatable` | No static analyzer can ever assess this — personnel screening, physical access, incident-response exercises. A person must. |

Plus `not_enumerated`: controls the pack does not list at all, counted against
the framework's real published size so a pack covering twenty controls cannot
report full coverage.

## Reading a coverage report

```console
$ arbiter controls arbiter-out/report.json --framework FedRAMP-Moderate-r5

       8  violated         a check fired
       0  not_assessed     a check covers this but did not run — not a pass
       0  no_coverage      assessable in principle; Arbiter has no check for it
       5  satisfied        a check ran, applied, and found nothing
       5  not_automatable  no static analyzer can assess this; a person must
     305  not_enumerated   not in this pack; assess by other means
     323  controls in this baseline

    4.0% of the baseline carries evidence from this scan (13 of 323).
```

Four percent. No compliance product would print that number, which is why it is
the right one: the other 96% is unevidenced by this scan, and a reader of an
accreditation package needs to know which 96%.

## Residual notes

Every automatable control also carries a `residual` note saying what a person
must still check even when the automated part passes — because encryption being
switched on says nothing about who holds the key, and FedRAMP AU-11 fixes a
retention period that a check confirming "some period is set" cannot see.

## Mapping a rule to a control

Rules declare the controls they support:

```yaml
- id: unencrypted-database
  match_kinds: [database]
  assert: property_truthy
  any_of: [storage_encrypted, StorageEncrypted, encrypted, KmsKeyId]
  severity: high
  controls: [NIST-800-53r5:SC-28]
```

## Commercial packs

PCI-DSS, HIPAA, SOC 2 and CIS are each a data file in the format the five
government packs already use. The interfaces exist; those packs do not ship. See
the roadmap in the [README](../README.md#project-status).
