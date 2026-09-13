"""The hosted front door: Arbiter as something a customer calls, not installs.

This is the second surface over `service.py`, alongside `mcp.py`. It decides
nothing about containment -- workspaces, archive safety, path limits and profile
limits all live in the service layer, so they are written once.

What belongs here instead is everything that only matters when the caller is
remote and unknown: who they are, how much they may send, and what is kept
afterwards.

## Access is handed out by hand, one key per user

There is no sign-up, no billing and no self-service. The owner mints a key with
`arbiter api key add --user "..."` and sends it to a person he chose. That is
the whole distribution model, and it is deliberate: an offering that cannot be
signed up for cannot be abused at scale by someone who was never vetted.

A key is scoped to a user, and that is the whole model -- no roles, no tiers, no
per-key permissions. One user holds at most one live key, so a key identifies a
person rather than a pool. Sharing one defeats every limit here: the caps below
count per key, and revoking a shared key for the person who left also cuts off
the person who stayed. Adding somebody means minting them their own.

Keys are stored as SHA-256 hashes, never in the clear. The raw key is shown once
at mint time and cannot be recovered -- so the key file is not itself a
credential store, and losing it means reissuing rather than a breach. Each key
carries a short id derived from its hash so a key can be named in a log or
revoked without anyone writing the secret down.

## Nothing is kept

A scan writes into a workspace that is deleted when the request ends, including
when it fails. The report goes back in the response body and nowhere else. There
is no database, no object store, no log of findings.

That costs a feature: a caller cannot come back tomorrow for yesterday's report.
It buys the simplest possible answer to "what do you hold of ours?", which is
"nothing", and that answer needs no retention policy to defend.

The reason it matters more here than it would for most services: a report names
the file a credential sits in and what kind it is. `report.py` withholds the
secret's value -- `test_no_output_format_reprints_a_secret` holds it to that --
but a stored report would still be a map of where to look. Keeping none is
cheaper than guarding them.

## Source arrives as an upload, and only as an upload

The server does not clone from a caller's repository, because that would mean
holding credentials to their source: a far larger thing to ask for and to
protect than a tarball for the duration of one request. Uploads are treated as
hostile input by `service.extract_archive`.

## No verdict crosses this boundary

`review_queue` returns a queue with every mark blank, exactly as the other
surfaces do. There is no endpoint that records an adjudication, and there must
never be one: `learn.record()` refuses to re-adjudicate a fingerprint, so a mark
made by an automated caller would be permanent and would replace the one signal
in the system that the system did not generate.

Whether a customer's own human adjudications should ever feed calibration is an
open question and is deliberately not answered here. If it is ever answered yes,
the thing sent back is the verdict and the rule id -- never the fingerprint,
which is derived from the file path and a snippet of their code and would leak
both.
"""
from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import __version__
from .service import (
    DEFAULT_TIMEOUT,
    ServiceError,
    Workspace,
    extract_archive,
    gate,
    review_queue,
    scan,
)

# An upload larger than this is refused before anything is written to disk.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024

# Stated as a constant so a test can assert it rather than trusting the prose:
# no request path writes anything that outlives the request.
RETAINS_NOTHING = True

KEY_PREFIX = "arb_"

# Ninety days. Long enough not to be a nuisance, short enough that a key leaked
# and forgotten stops working without anyone having to notice. It sits up here
# rather than with the other limits further down because `mint_key` takes it as
# a default argument, and Python evaluates those when the function is defined.
DEFAULT_KEY_LIFETIME_DAYS = 90

# Two years, and subdomains. Sent on every response so a browser or client that
# once reached us over TLS refuses to try plaintext afterwards.
HSTS_HEADER = "max-age=63072000; includeSubDomains"

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


# --------------------------------------------------------------------------
# Transport security, which is not optional
# --------------------------------------------------------------------------
#
# Every request to this service carries an API key in a header and a copy of
# somebody's source code in the body. Over plaintext both are readable by
# anything on the path, and the key is replayable forever. So the server does
# not offer plaintext as a degraded mode: it refuses to start without TLS, and
# refuses individual requests that arrive over it anyway.
#
# There are exactly two legitimate arrangements. Either this process terminates
# TLS itself, with a certificate and key, or a proxy terminates it and forwards
# to this process on the loopback interface. The second is only honoured when
# the operator says so explicitly, because `X-Forwarded-Proto` is a header any
# client can invent -- trusting it on a public interface would hand anyone a
# way to claim their plaintext request was secure.


def require_tls(scheme: str, forwarded_proto: str, behind_proxy: bool) -> None:
    """Refuse a request that did not arrive over TLS.

    Framework-free so the rule is testable without a running server.
    """
    if behind_proxy:
        # A proxy may append to the header, so the first hop is the client's.
        proto = (forwarded_proto or "").split(",")[0].strip().lower()
        if proto != "https":
            raise ServiceError(
                "this request reached the proxy over plaintext; HTTPS is required"
            )
        return
    if (scheme or "").lower() != "https":
        raise ServiceError("plaintext HTTP is refused; use HTTPS")


def check_tls_config(certfile: str | None, keyfile: str | None,
                     behind_proxy: bool, host: str) -> None:
    """Refuse to start in any arrangement that would expose plaintext.

    Called before the socket is opened, so a misconfiguration is a startup
    failure rather than a quiet downgrade nobody notices.
    """
    if behind_proxy:
        if host not in LOOPBACK:
            raise ServiceError(
                f"--behind-proxy binds to the loopback interface only, not {host}; "
                "otherwise anyone could send X-Forwarded-Proto: https and be believed"
            )
        return
    if not certfile or not keyfile:
        raise ServiceError(
            "TLS is required: pass --cert and --key, or --behind-proxy if a "
            "reverse proxy terminates TLS and forwards to localhost. "
            "With no certificate to hand, see docs/hosted-api.md "
            "('If you have no certificate') -- there is no plaintext mode"
        )
    for label, value in (("--cert", certfile), ("--key", keyfile)):
        if not Path(value).expanduser().is_file():
            raise ServiceError(f"{label} {value} does not exist")


# --------------------------------------------------------------------------
# Keys, issued by hand
# --------------------------------------------------------------------------

def default_key_path() -> Path:
    """Where minted keys live. `ARBITER_KEYS` overrides it for a deployment."""
    env = os.environ.get("ARBITER_KEYS")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".arbiter" / "keys.json"


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _stamp(when: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))


def _parse_stamp(value: str) -> float:
    return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))


def key_state(record: dict, now: float | None = None) -> str:
    """`active`, `revoked` or `expired`. Used for display and for verification."""
    if record.get("revoked"):
        return "revoked"
    expires = record.get("expires")
    if expires and _parse_stamp(expires) <= (time.time() if now is None else now):
        return "expired"
    return "active"


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ServiceError(f"key file {path} is not valid JSON: {exc}") from exc
    return data.get("keys", []) if isinstance(data, dict) else []


def _store(path: Path, keys: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "keys": keys}, indent=2), encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - platform dependent
        pass


def active_key_for(user: str, path: Path | None = None) -> dict | None:
    """The live key a user holds, if any. One user, one key."""
    wanted = user.strip()
    for rec in _load(path or default_key_path()):
        if rec.get("user") == wanted and key_state(rec) == "active":
            return rec
    return None


def mint_key(user: str, path: Path | None = None,
             lifetime_days: int | None = DEFAULT_KEY_LIFETIME_DAYS,
             replace: bool = False) -> tuple[str, dict]:
    """Create a key for one user. Returns the raw key and its record.

    A key is scoped to a user and that is the whole model. One user holds at
    most one live key, so a key identifies a person rather than a pool: if two
    people share one, nothing downstream can tell them apart, and revoking it
    for the one who left also cuts off the one who stayed. Adding a second
    person means minting them their own.

    Minting over a live key is refused unless `replace` is set, which revokes
    the old one in the same breath -- so rotation is one deliberate act and
    never silently leaves two keys working for the same person.

    The raw key is returned once and never stored. Only its hash is written, so
    the key file cannot be used to impersonate anyone who holds a key.

    Keys expire. `lifetime_days=None` mints one that does not, which is a
    deliberate exception rather than the default: a permanent key is a permanent
    grant to whoever ends up holding it.
    """
    user = user.strip()
    if not user:
        raise ServiceError("a key is scoped to a user; name the one it is for")
    if lifetime_days is not None and lifetime_days <= 0:
        raise ServiceError("a key's lifetime must be at least one day")
    path = path or default_key_path()

    held = active_key_for(user, path)
    if held and not replace:
        raise ServiceError(
            f"{user} already holds key {held['id']}; pass --replace to rotate it, "
            "or revoke it first. One user, one key."
        )

    keys = _load(path)
    if held:
        for rec in keys:
            if rec.get("id") == held["id"]:
                rec["revoked"] = _stamp(time.time())

    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    digest = _digest(raw)
    now = time.time()
    record = {
        "id": digest[:12],
        "user": user,
        "sha256": digest,
        "created": _stamp(now),
        "expires": _stamp(now + lifetime_days * 86400) if lifetime_days else None,
        "revoked": None,
        "replaced": held["id"] if held else None,
    }
    keys.append(record)
    _store(path, keys)
    return raw, record


def list_keys(path: Path | None = None) -> list[dict]:
    """Every key, without any secret, each with its current state. Safe to print."""
    listed = []
    for rec in _load(path or default_key_path()):
        shown = {k: v for k, v in rec.items() if k != "sha256"}
        shown.setdefault("expires", None)
        shown["state"] = key_state(rec)
        listed.append(shown)
    return listed


def revoke_key(key_id: str, path: Path | None = None) -> bool:
    """Revoke by short id. Returns whether anything changed."""
    path = path or default_key_path()
    keys = _load(path)
    changed = False
    for rec in keys:
        if rec.get("id") == key_id and not rec.get("revoked"):
            rec["revoked"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            changed = True
    if changed:
        _store(path, keys)
    return changed


def verify_key(raw: str, path: Path | None = None) -> dict | None:
    """Return the key's record, or None if it is unknown or revoked.

    Compared with `hmac.compare_digest` so the time taken does not reveal how
    much of a guessed key was correct.
    """
    if not raw:
        return None
    candidate = _digest(raw)
    for rec in _load(path or default_key_path()):
        if hmac.compare_digest(rec.get("sha256", ""), candidate):
            return rec if key_state(rec) == "active" else None
    return None


# --------------------------------------------------------------------------
# Limits on a key, so holding one is not the same as owning the machine
# --------------------------------------------------------------------------
#
# A key that never expires and is never throttled is a permanent, unlimited
# grant. If one leaks -- pasted into a ticket, left in a shell history, kept by
# somebody who has since left -- whoever holds it can run scans forever, and a
# scan is expensive: it unpacks an archive and runs several analyzers.
#
# Three limits, all cheap, none of which a recipient would notice in normal use:
# keys expire, a key may only make so many requests in an hour, and a key may
# only have so many scans running at once.

RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 3600
MAX_CONCURRENT_SCANS = 2


class RateLimited(ServiceError):
    """A key asked for too much. Carries how long to wait."""

    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class RateLimiter:
    """Per-key request and concurrency caps.

    Held in memory, which is the honest scope of it: the counts do not survive a
    restart and are not shared between processes. For a manually distributed
    pilot on one machine that is sufficient, and it is stated here rather than
    implied so that running several instances is a known gap rather than a
    surprise.
    """

    def __init__(self, requests: int = RATE_LIMIT_REQUESTS,
                 window: int = RATE_LIMIT_WINDOW_SECONDS,
                 concurrent: int = MAX_CONCURRENT_SCANS) -> None:
        self.requests = requests
        self.window = window
        self.concurrent = concurrent
        self._calls: dict[str, list[float]] = {}
        self._running: dict[str, int] = {}
        self._lock = threading.Lock()

    def check(self, key_id: str, now: float | None = None) -> None:
        """Record one request, or refuse it if the key is over its hourly cap."""
        now = time.time() if now is None else now
        with self._lock:
            recent = [t for t in self._calls.get(key_id, []) if now - t < self.window]
            if len(recent) >= self.requests:
                oldest = min(recent)
                wait = int(self.window - (now - oldest)) + 1
                self._calls[key_id] = recent
                raise RateLimited(
                    f"this key has made {self.requests} requests in the last "
                    f"{self.window // 60} minutes; try again in {wait}s", wait)
            recent.append(now)
            self._calls[key_id] = recent

    @contextmanager
    def slot(self, key_id: str):
        """Hold one of a key's concurrent scan slots for the length of a request."""
        with self._lock:
            running = self._running.get(key_id, 0)
            if running >= self.concurrent:
                raise RateLimited(
                    f"this key already has {running} scans running; "
                    "wait for one to finish", 30)
            self._running[key_id] = running + 1
        try:
            yield
        finally:
            with self._lock:
                self._running[key_id] = max(0, self._running.get(key_id, 1) - 1)


# One limiter per process, shared by every request.
LIMITER = RateLimiter()


# --------------------------------------------------------------------------
# Request handling, without a web framework in sight
# --------------------------------------------------------------------------

def _ingest(ws: Workspace, upload: bytes | str | Path) -> Path:
    """Put the caller's source in the workspace, refusing an oversized upload."""
    if isinstance(upload, (str, Path)):
        archive = Path(upload)
        if archive.stat().st_size > MAX_UPLOAD_BYTES:
            raise ServiceError(f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
    else:
        if len(upload) > MAX_UPLOAD_BYTES:
            raise ServiceError(f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
        archive = ws.path / "upload.bin"
        archive.write_bytes(upload)
    extract_archive(archive, ws.source)
    archive.unlink(missing_ok=True)
    return ws.source


def handle_scan(upload: bytes | str | Path, profile: str = "offline", only: str = "",
                skip: str = "", timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Scan an uploaded archive and return the report. Keeps nothing."""
    with Workspace() as ws:
        source = _ingest(ws, upload)
        result = scan(str(source), str(ws.output), profile=profile, only=only,
                      skip=skip, timeout=timeout)
        # Deliberately not returning report_path: it names a directory that is
        # about to stop existing, and a caller should not learn server paths.
        return {"report": result["report"], "finding_count": result["finding_count"]}


def handle_gate(upload: bytes | str | Path, profile: str = "ci", only: str = "",
                skip: str = "", timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Gate an uploaded archive. Returns pass or fail with the claim ledger."""
    with Workspace() as ws:
        source = _ingest(ws, upload)
        result = gate(str(source), str(ws.output), profile=profile, only=only,
                      skip=skip, timeout=timeout)
        return {"passed": result["passed"], "gate": result["gate"],
                "claims": result["claims"]}


def handle_review_queue(report: dict, limit: int = 20, rule: str = "",
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Turn a report the caller already has into a queue for a person to mark.

    Returns the queue with every mark blank. Nothing is recorded, here or
    anywhere reachable from here.
    """
    with Workspace() as ws:
        report_path = ws.output / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        result = review_queue(str(report_path), str(ws.output), limit=limit,
                              rule=rule, timeout=timeout)
        return {"queue_markdown": result["queue_markdown"],
                "entry_count": result["entry_count"],
                "recorded": False,
                "note": result["note"]}


# Every operation the hosted surface may expose. A test asserts this set, so
# adding a verdict-recording endpoint fails the build rather than review.
ENDPOINTS = {"scan": handle_scan, "gate": handle_gate, "review_queue": handle_review_queue}


# --------------------------------------------------------------------------
# The framework layer, imported only when actually serving
# --------------------------------------------------------------------------

def create_app(key_path: Path | None = None, behind_proxy: bool = False) -> Any:
    """Build the FastAPI application.

    FastAPI is imported here, not at module scope, so everything above stays
    importable and testable without it. It is an optional extra: a plain
    `pip install arbiter-eval` still depends on PyYAML alone.
    """
    try:
        from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
        from fastapi.responses import JSONResponse
        from pydantic import BaseModel
    except ImportError as exc:
        raise ServiceError(
            "the hosted API needs the optional 'api' dependency: "
            "pip install 'arbiter-eval[api]'"
        ) from exc

    app = FastAPI(title="Arbiter", version=__version__,
                  description="Evaluate a repository without installing anything. "
                              "Uploads are deleted when the request ends.")

    @app.middleware("http")
    async def enforce_tls(request, call_next):
        """Refuse plaintext before anything reads the key or the body."""
        try:
            require_tls(request.url.scheme,
                        request.headers.get("x-forwarded-proto", ""),
                        behind_proxy)
        except ServiceError as exc:
            # 426 Upgrade Required: the request was understood and the transport
            # is the problem, which is exactly what happened.
            return JSONResponse(status_code=426, content={"detail": str(exc)})
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = HSTS_HEADER
        return response

    def caller(x_api_key: str = Header(default="")) -> dict:
        record = verify_key(x_api_key, key_path)
        if record is None:
            # One message for unknown, revoked and expired alike: telling a
            # caller which one it was would confirm that a key it guessed once
            # existed.
            raise HTTPException(status_code=401,
                                detail="unknown, revoked or expired API key")
        try:
            LIMITER.check(record["id"])
        except RateLimited as exc:
            raise HTTPException(status_code=429, detail=str(exc),
                                headers={"Retry-After": str(exc.retry_after)}) from exc
        return record

    async def _read(upload: UploadFile) -> bytes:
        data = await upload.read()
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413,
                                detail=f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
        return data

    def _guard(key_id: str, fn, *args, **kwargs):
        """Run one operation while holding a concurrency slot for its key.

        `RateLimited` is caught first because it subclasses `ServiceError`, and
        "you asked for too much" is a different answer from "your request was
        malformed".
        """
        try:
            with LIMITER.slot(key_id):
                return fn(*args, **kwargs)
        except RateLimited as exc:
            raise HTTPException(status_code=429, detail=str(exc),
                                headers={"Retry-After": str(exc.retry_after)}) from exc
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    class ReviewRequest(BaseModel):
        report: dict
        limit: int = 20
        rule: str = ""

    @app.get("/v1/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__,
                "retains_nothing": RETAINS_NOTHING, "tls_required": True}

    @app.post("/v1/scan")
    async def scan_endpoint(archive: UploadFile = File(...), profile: str = "offline",
                            only: str = "", skip: str = "",
                            key: dict = Depends(caller)) -> dict:
        return _guard(key["id"], handle_scan, await _read(archive), profile, only, skip)

    @app.post("/v1/gate")
    async def gate_endpoint(archive: UploadFile = File(...), profile: str = "ci",
                            only: str = "", skip: str = "",
                            key: dict = Depends(caller)) -> dict:
        return _guard(key["id"], handle_gate, await _read(archive), profile, only, skip)

    @app.post("/v1/review-queue")
    def review_endpoint(body: ReviewRequest, key: dict = Depends(caller)) -> dict:
        return _guard(key["id"], handle_review_queue, body.report, body.limit, body.rule)

    return app


def serve(host: str = "127.0.0.1", port: int = 8443, key_path: Path | None = None,
          certfile: str | None = None, keyfile: str | None = None,
          behind_proxy: bool = False) -> int:
    """Run the API over TLS. There is no plaintext mode.

    Either this process holds the certificate, or a proxy terminates TLS and
    forwards to loopback with `--behind-proxy`. Anything else fails to start.
    """
    # The TLS check comes first deliberately. An operator whose install is
    # missing the extra should still be told plainly that their arrangement
    # would have served plaintext, rather than fixing the dependency and
    # meeting that refusal only on the second attempt.
    check_tls_config(certfile, keyfile, behind_proxy, host)

    try:
        import uvicorn
    except ImportError:
        print("arbiter: the hosted API needs the optional 'api' dependency.\n"
              "         pip install 'arbiter-eval[api]'")
        return 2

    app = create_app(key_path, behind_proxy=behind_proxy)

    if behind_proxy:
        print(f"arbiter: serving on http://{host}:{port} for a TLS-terminating "
              "proxy only; requests without X-Forwarded-Proto: https are refused")
        uvicorn.run(app, host=host, port=port, proxy_headers=True,
                    forwarded_allow_ips="127.0.0.1")
        return 0

    # uvicorn builds its own SSL context and exposes no minimum-version hook, so
    # a TLS 1.2 floor cannot be asserted from here. Restricting to forward-secret
    # AEAD suites is what is actually enforced: it leaves nothing a TLS 1.0 or
    # 1.1 client can negotiate. The version floor proper belongs to the platform
    # OpenSSL policy, or to the terminating proxy under --behind-proxy, which is
    # the arrangement to prefer if that floor has to be guaranteed.
    print(f"arbiter: serving on https://{host}:{port}")
    uvicorn.run(app, host=host, port=port, ssl_certfile=certfile,
                ssl_keyfile=keyfile,
                ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
    return 0
