# ADR-0010 — Gateway and S1 sidecar ship as containers, sharing a unix socket

**Status:** Accepted · **Date:** 2026-10-07

## Context

Every benchmark so far started the S1 sidecar by hand. ADR-0007 chose a
sidecar precisely so S1 could be a deployable unit; until it built
reproducibly it was not one, and "nothing container-verified" was a standing
gap (the Docker daemon was unavailable earlier in the project).

## Decision

Two images, built from the repository root, composed over a **unix socket on a
shared named volume**:

- `s1-sidecar/Dockerfile` — Go build → `gcr.io/distroless/static-debian12:nonroot`.
  CGO off, so Coraza v3 (pure Go) yields a static binary. **29.4 MB.**
- `backend/Dockerfile` — uv install → `python:3.14-slim`, non-root.
- `compose.yaml` — `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, and
  **no published port for S1**.

### Why a socket, not a port
S1 is an internal detail of the gateway, not a service. Nothing publishes it,
so there is no second network path into the rule engine and no port to forget
to firewall. The gateway's port is bound to `127.0.0.1` — this is not an edge
deployment yet.

### Why the rule set is baked in but exclusions are mounted
The CRS checkout is `COPY`d into the image: a WAF whose rules come from a
writable host path is a WAF whose rules an attacker on the host can rewrite,
and baking them in makes the image's rules match the image's tag. Per-application
rule exclusions are *deployment configuration*, not part of the detector, so
they are mounted read-only. These are different things and are treated
differently on purpose.

### Why both containers run as uid 65532
The sidecar chmods its socket to `0600`. The gateway must therefore run as the
**same uid**, not merely a shared group — a group would widen who can reach the
rule engine, and the socket is the only path to it. The uid is pinned
numerically in both images because that is what the kernel compares.

## Verification

Not a smoke test. The containerised sidecar was compared against the host one
across **400 real corpus requests**, scoring both anomaly and blocking scores:
**0 mismatches** (9 requests with non-zero scores, so the comparison is not
vacuously over zeros).

The first such run showed **400/400 mismatches** — the host sidecar had the
CSIC exclusions loaded and the container did not. That is a configuration
difference behaving correctly, not a container bug, and it is recorded because
it is exactly what the equivalence check exists to catch.

End-to-end through the composed stack: SQLi, XSS, traversal and command
injection all blocked (shadow mode, `enforced: false`); benign allowed. With S1
disabled, all ten payloads from the Phase 6b coverage fixes are blocked by S2
**in the container**, and the benign controls — including `C:\new\report.docx`,
the Windows path that justified the escaped-line-break shape requirement — are
allowed.

## What containerising found

A clean install from `pyproject.toml` **could not import S2 at all**:

- **`sqlglot` was never declared.** S2's parser. It worked locally only because
  the development venv happened to have it.
- **`httptools` was never declared.** `csf/framing.py` imports it directly. It
  arrived transitively via `uvicorn[standard]`, so nothing broke — but framing
  documents measured strictness differences between httptools and h11 and
  reports which parser is live. That behaviour cannot rest on a server extra
  that may drop the package.
- **scikit-learn** is needed to *deserialise* the S3 artifact though no module
  imports it by name, so an AST scan of the source will not find it. Added as
  an optional `s3` extra, not a default: Phase 6 recorded S3 as a negative
  result and the gateway runs without it.

This is the argument for containerisation stated as a measurement: the project
was not installable from its own manifest, and only a build from a clean base
revealed it.

## Known limitations

- Base images are now **digest-pinned** (ADR-0018): golang, python, distroless
  and the uv stage all carry `@sha256:` digests, so a rebuild is the same build.
  Re-pin on an intentional base bump.
- `read_only: true` required a tmpfs at `/tmp`: Coraza probes for filesystem
  access at startup and aborts on a fully read-only root. Coraza suggests a
  `no_fs_access` build tag instead; that changes the binary, and this binary is
  the one whose scores were verified equal to the host's. Not re-opened.
- The S1 healthcheck runs `-version`, which proves the binary is executable,
  **not** that the socket is accepting connections. A real readiness probe
  needs a client that speaks to the unix socket.
- Only tested on macOS/arm64 under Docker Desktop. No CI, no multi-arch build,
  no image signing, no published registry.
