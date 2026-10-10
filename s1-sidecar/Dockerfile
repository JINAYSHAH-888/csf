# S1 sidecar: Coraza + OWASP CRS, served over a unix socket.
#
# Why this exists: the sidecar has been started by hand for every benchmark so
# far, which makes the measured numbers depend on one machine's Go toolchain
# and one person's shell history. ADR-0007 chose a sidecar precisely so S1
# could be a deployable unit; until it builds reproducibly it is not one.

# --- build -----------------------------------------------------------------
# Digest-pinned to go1.27.2 for reproducibility AND to patch the net/http,
# crypto/tls and net/textproto CVEs that go1.27.1 carried (GO-2026-66xx,
# caught by govulncheck in the final review). Re-pin on an intentional bump.
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

WORKDIR /src

# Dependencies first so a source edit does not re-download the module graph.
COPY s1-sidecar/go.mod s1-sidecar/go.sum ./
RUN go mod download

COPY s1-sidecar/main.go ./
# CGO off: Coraza v3 is pure Go, so the result is a static binary that runs on
# scratch. This is the reason libmodsecurity was rejected in ADR-0007 -- it
# needs a C toolchain and would not build on the dev machine at all.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags="-s -w" -o /out/s1-sidecar .

# Staged here only so the runtime stage can COPY it with an owner. Distroless
# has no shell and therefore no mkdir, and Docker seeds a fresh named volume
# from the image's directory -- including its ownership. Without this the
# socket directory arrives root-owned and a non-root sidecar cannot bind.
RUN mkdir -p /out/run-csf

# --- runtime ---------------------------------------------------------------
# Distroless static: no shell, no package manager, nothing to pivot to. The
# sidecar parses attacker-controlled bytes for a living (threat model T4), so
# the blast radius of a parser bug is worth minimising.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# Built from the REPO ROOT, not s1-sidecar/, so this can read vendor/crs --
# the same pinned checkout the host benchmarks use. Staging a copy into the
# sidecar directory would mean two rule sets that can drift apart.
#
# The rule set is COPIED IN, not mounted. A WAF whose rules come from a
# writable host path is a WAF whose rules an attacker who reaches the host can
# rewrite; baking them in makes the image's rules match the image's tag.
COPY --from=build /out/s1-sidecar /usr/local/bin/s1-sidecar
COPY --chown=nonroot:nonroot vendor/crs /opt/crs

USER nonroot:nonroot

# The socket lives on a shared volume so the Python gateway can reach it
# without opening a TCP port. Nothing listens on the network by default.
#
# The sidecar chmods its socket to 0600, so the gateway must run as the SAME
# uid -- see compose.yaml. That is deliberate: a shared group would also work
# and would widen who can reach the rule engine, and the socket is the only
# path to it.
COPY --from=build --chown=nonroot:nonroot /out/run-csf /run/csf
VOLUME ["/run/csf"]

ENTRYPOINT ["/usr/local/bin/s1-sidecar"]
CMD ["-socket", "/run/csf/s1.sock", "-crs", "/opt/crs"]
