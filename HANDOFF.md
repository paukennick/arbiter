# Arbiter handoff

This file no longer duplicates Arbiter's history or carries one-time landing
instructions. The previous handoff still told a session to import an already
landed git bundle, quoted obsolete test and corpus counts, and described
adjudication as the only open work.

Use the maintained context in this order:

1. `.ai/context-brief.md`
2. `.ai/project-context.md`
3. `.ai/project-configuration.md`
4. `.ai/project-map.md`
5. `.ai/requirements/requirements.json`

`README.md` explains the product. The active requirements registry is the
authority for unfinished work; `CHANGELOG.md` and `.ai/project-context.md`
record completed decisions and their reasons.

## Current completion order

The `req-018-hosted-api` branch contains three related deliverables:

1. **REQ-018** — the shared service layer and hosted HTTPS API. This is the
   dependency root.
2. **REQ-019** — the remote CLI that calls the hosted API.
3. **REQ-010** — stdio and authenticated HTTPS MCP transports over the same
   service, identity, limit and audit model.

REQ-019 and REQ-010 both depend on REQ-018; neither depends on the other. Close
them only after the rebased branch passes the requirement-specific tests and
the full Linux completion gate. REQ-005 remains separate and requires counsel;
do not represent engineering work as resolving its licensing questions.

## Validation

The configured completion command is:

```bash
PYTHONPATH=src python -m pytest -q
```

Use `python tools/corpus.py --counts` for corpus totals instead of copying a
number into this file. Adjudication remains necessary before calibration can
promote rules, but it is an operational evidence track rather than the only
blocker to product work.

The product invariants, hosted custody decisions, MCP transport boundaries and
known gaps are maintained in `.ai/project-context.md`; they are deliberately
not repeated here.
