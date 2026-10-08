# Console API image: the real csf gateway + demo shop + console endpoints.
# Build context is the repository root (see compose.yaml).
FROM python:3.14-slim AS build
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /src
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY backend/pyproject.toml ./
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install -r pyproject.toml
COPY backend/csf ./csf
RUN VIRTUAL_ENV=/opt/venv uv pip install --no-deps .

FROM python:3.14-slim
RUN useradd --system --uid 65532 --create-home csf
COPY --from=build --chown=csf:csf /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY --chown=csf:csf console-api/server.py ./console-api/server.py
RUN mkdir -p /app/console-api/.runtime && chown 65532:65532 /app/console-api/.runtime
USER 65532:65532
EXPOSE 8000
CMD ["python", "console-api/server.py"]
