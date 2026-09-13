# Arbiter as a hosted service.
#
# One unprivileged process, the analyzers baked in so a scan never fetches
# anything at request time, and no build tooling left in the final image.
#
# Keep this image private. Running semgrep server-side conveys no copy of it and
# so triggers none of LGPL-2.1's redistribution obligations -- that is the whole
# reason hosting is less encumbered than the air-gapped bundle (see
# docs/licensing.md, L-6). Pushing this image to a public registry would convey
# copies and put those obligations straight back.

FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# A virtualenv rather than the system site-packages, so the whole install is one
# directory to copy into a clean image and nothing from the build stage follows.
RUN python -m venv /opt/arbiter \
 && /opt/arbiter/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/arbiter/bin/pip install --no-cache-dir '.[api,tools]'


FROM python:3.12-slim

COPY --from=build /opt/arbiter /opt/arbiter

# 10001 is arbitrary and deliberately outside the host's usual range. The named
# volumes inherit this ownership when Docker first creates them, which is what
# lets the container run non-root against a read-only root filesystem.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin arbiter \
 && mkdir -p /data /work \
 && chown 10001:10001 /data /work

ENV PATH="/opt/arbiter/bin:${PATH}" \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARBITER_KEYS=/data/keys.json \
    ARBITER_AUDIT=/data/audit.log \
    # Workspaces land here rather than in /tmp, so the disk they use is an
    # explicit volume that can be sized and watched.
    TMPDIR=/work \
    # The analyzers write caches under $HOME. Pointing it at the same volume is
    # what allows the root filesystem to stay read-only.
    HOME=/work

USER 10001
WORKDIR /work
EXPOSE 8443

# The service refuses any request that did not reach the proxy over HTTPS, so
# the health check has to say so. It only reaches this port from inside the
# network namespace it shares with Caddy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request as r; \
req = r.Request('http://127.0.0.1:8443/v1/health', \
headers={'X-Forwarded-Proto': 'https'}); \
exit(0 if r.urlopen(req, timeout=4).status == 200 else 1)"

ENTRYPOINT ["arbiter"]
CMD ["api", "serve", "--behind-proxy", "--port", "8443"]
