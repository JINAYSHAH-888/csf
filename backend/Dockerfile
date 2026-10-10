# CSF gateway: S0 ingress + JWT, S1 client, S2 semantic, S3 learned.
#
# ADR-0006 chose a single-language backend so that training and serving share
# one definition of a model input. That argument only holds if the thing that
# serves is the thing that was tested, which is what this image is for.

FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS build

# uv resolves and installs from the lockfile; no network at runtime.
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /usr/local/bin/uv

WORKDIR /src
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Dependencies as their own layer, so editing source does not reinstall them.
COPY pyproject.toml ./
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install -r pyproject.toml

COPY csf ./csf
RUN VIRTUAL_ENV=/opt/venv uv pip install --no-deps .

# --- runtime ---------------------------------------------------------------
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

# A WAF that runs as root is a WAF whose parser bugs are root bugs
# (threat model T4). Nothing here needs privilege.
# uid 65532 is distroless's `nonroot`. The two images must agree on it: the
# sidecar's socket is mode 0600, so a differing uid means the gateway simply
# cannot connect. Pinned numerically because that is what the kernel compares.
RUN useradd --system --uid 65532 --create-home csf
COPY --from=build --chown=csf:csf /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

USER 65532:65532
EXPOSE 8080

# No HEALTHCHECK here: the gateway's readiness is a cascade property
# (_readiness_problems reports an unreachable S1 or a missing S3 artifact),
# and compose asks the endpoint rather than the image guessing at it.
ENTRYPOINT ["csf-gateway"]
CMD ["--config", "/etc/csf/gateway.json"]
