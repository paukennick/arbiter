# Running the pilot

> **Status: not yet deployed.** This is the arrangement to stand up for a pilot
> with a handful of named testers, in the order the steps have to happen. It
> assumes the decisions already recorded in [hosted-api.md](hosted-api.md):
> uploads only, nothing retained, TLS only, one key per user.

## Contents

- [Before anybody uploads](#before-anybody-uploads)
- [The machine](#the-machine)
- [Standing it up](#standing-it-up)
- [Issuing keys](#issuing-keys)
- [What to send each tester](#what-to-send-each-tester)
- [While it runs](#while-it-runs)
- [Shutting it down](#shutting-it-down)

---

## Before anybody uploads

One thing has to exist that is not code: a written statement of what happens to
a tester's source. [pilot-terms.md](pilot-terms.md) is a draft of it. Send it
with the key, and get a reply saying they have read it — an email is enough for
a pilot. Testers are uploading their employer's code, and most of them need
something to point at when somebody asks why that was allowed.

Nothing else on this page matters until that is done.

## The machine

Run the server as an unprivileged user in a container, with a memory limit. The
scanned repository is never executed — no build, no test, no hook, no entry
point from the upload runs at any stage — but the analyzers still parse
attacker-chosen files in a subprocess with a 900-second timeout and no memory
limit of their own. A parser bug on a pathological file is the plausible way to
lose the box, and a container with a cap turns that into one failed request.

Sizing for the defaults: four concurrent scans, each unpacking an archive of up
to 100 MB and running several analyzers. Two cores and 4 GB is enough for a
pilot; disk needs room for four extracted trees at once, which is far more than
the archives themselves.

## Standing it up

Put a TLS-terminating proxy in front and keep Arbiter on loopback. That gets a
real certificate without any certificate handling in this process, and gives you
somewhere to set a request body limit and connection limits — which matters
because an unauthenticated caller's upload is read before the key is checked, so
the `401` costs bandwidth and memory unless something upstream stops it first.

Caddy, as a whole config:

```
arbiter.example.com {
    reverse_proxy 127.0.0.1:8443
    request_body {
        max_size 100MB
    }
}
```

Then:

```
arbiter api serve --behind-proxy
```

`--behind-proxy` binds to loopback only and refuses any request that did not
reach the proxy over HTTPS. Without the flag, `X-Forwarded-Proto` is ignored
entirely. There is no plaintext mode in either arrangement. If the machine has
no public address, a tunnel (`cloudflared`, Tailscale Funnel) terminates TLS at
the provider's edge and forwards to loopback the same way — but the provider
then sees the traffic, which is a custody question and belongs in what you send
testers.

Do not hand a self-signed certificate to a tester. It works, but the first trust
error teaches them `curl -k`, and at that point anything on the path can
impersonate the service and collect their key.

## Issuing keys

One key per person, named for the person:

```
arbiter api key add --user "dana@acme.example"
arbiter api key list
```

The key is printed once. Send it over something that expires — a password
manager share, or a message that self-deletes — not a ticket or a mailing list.
Only its SHA-256 hash is stored, so losing the key file means reissuing rather
than a breach.

Minting a second key for somebody who already holds a live one is refused. To
rotate, `--replace` issues the new key and revokes the old one in the same
command. If a key might have leaked, revoke first and ask questions after:

```
arbiter api key revoke 4a0df464a689
```

Revocation takes effect on the next request. Anything already running finishes.

## What to send each tester

- The URL, and that every call needs `X-API-Key`.
- Their key, over a channel that expires.
- [pilot-terms.md](pilot-terms.md).
- The limits, so a `429` is not a support ticket: 30 requests an hour, two scans
  at once, uploads up to 100 MB, keys expire in 90 days.
- That the report they get back names the file each credential sits in and what
  kind it is. The value is never reprinted, but the report is still a map of
  where to look, and where they store it is now their decision.
- That there is no history: the report comes back in the response and nowhere
  else, so they should keep the one they want.

## While it runs

`~/.arbiter/audit.log` gets one line per request — key, user, operation,
outcome, bytes, milliseconds, and nothing about their code. It is created
owner-read-only on Linux; on Windows that call only sets the read-only
attribute, so restrict the directory instead. Read the log for the things that
are invisible otherwise:

- `auth_failed` lines in any volume mean a key leaked or somebody is probing.
- Repeated `429`s mean the limits are wrong for real use, not that a tester is
  misbehaving. Change them deliberately rather than raising them per complaint.
- `status` 500 is an Arbiter bug, and the line gives you the key and the time to
  ask its owner what they were scanning.

Restarting the server resets the rate-limit counters, since they live in memory.
Running two instances behind one address doubles every per-key limit, so do not,
until the counts move to shared storage.

## Shutting it down

Revoke every key (`arbiter api key list`, then `revoke` each id), then stop the
process. Keys outlive the deployment otherwise, and a key that still verifies
against a service nobody is watching is the worst of both.

Keep the audit log after shutdown — it is the only record that the pilot
happened and the only thing that can answer a later question about it. It holds
nothing of anybody's source.
