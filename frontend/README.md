# CSF Security Console (frontend)

React + Vite UI for the CSF gateway. Talks to `console-api/` (port 8000).

Quick start from the repo root: run `run-demo.bat` (starts the gateway + demo shop + console API, then this UI at http://localhost:5173).

Manual:
- `cd backend && uv sync --extra dev && uv run python ../console-api/server.py`
- `cd frontend && npm install && npm run dev`

Pages: Attack Lab, JWT Lab, Live Dashboard, Evidence.
S1 (Coraza/CRS) needs the Go sidecar via Docker and is shown as disabled in this local demo.
