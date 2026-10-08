# CSF backend — package contents

Complete CSF (Cascaded Semantic Firewall) **backend**: a clean export of the
tracked source plus the vendored OWASP CRS rule set needed to build the S1
sidecar. It builds and runs without anything else. Start at `README.md`.

## Included
- `backend/` — Python data plane + tests, scripts, `pyproject.toml`, `uv.lock`
- `s1-sidecar/` — Go Coraza + CRS sidecar
- `vendor/crs/` — OWASP CRS rule data (Apache-2.0), baked into the sidecar image
- `configs/`, `docs/` (17 ADRs, phase reports, threat model, benchmarks, SBOMs),
  `compose.yaml`, Dockerfiles, `.github/workflows/ci.yml`

## NOT included, and why
- **Evaluation corpora + frozen holdout** — licensed datasets, not
  redistributable. Sources + SHA-256 in `docs/datasets/dataset-card.md`.
- **S3 model artifact** — trained pickle; Phase 6 negative result, off by
  default. Regenerate with `backend/scripts/train_s3.py` given the corpora.
- `.venv/`, caches, git history (this is a clean source tree).

## Build & run
```bash
docker compose up -d --build
curl localhost:8080/statusz
```
Dev: `cd backend && uv sync --extra dev && uv run pytest -q`
