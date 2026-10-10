# Base images are pinned by digest, matching backend/Dockerfile (ADR-0010/0018).
# Console API image: the real csf gateway + demo shop + console endpoints.
# Build context is the repository root (see compose.yaml).
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS build
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a /uv /usr/local/bin/uv
WORKDIR /src
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY backend/pyproject.toml ./
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install -r pyproject.toml
COPY backend/csf ./csf
RUN VIRTUAL_ENV=/opt/venv uv pip install --no-deps .

FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
RUN useradd --system --uid 65532 --create-home csf
COPY --from=build --chown=csf:csf /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY --chown=csf:csf console-api/server.py ./console-api/server.py
RUN mkdir -p /app/console-api/.runtime && chown 65532:65532 /app/console-api/.runtime
USER 65532:65532
EXPOSE 8000
CMD ["python", "console-api/server.py"]
