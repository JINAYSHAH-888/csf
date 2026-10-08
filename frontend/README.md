# CSF Security Console

React + Vite console for the CSF gateway. Talks to `console-api/` on port 8000.

Run everything (Docker Desktop required for the S1 rules stage): `run-demo.bat` from the repo root.
It needs `vendor/crs` (OWASP CRS v4.21.0, gitignored): `git clone --depth 1 --branch v4.21.0 https://github.com/coreruleset/coreruleset vendor/crs`.

Manual, without S1:
- `cd backend && uv sync --extra dev && uv run python ../console-api/server.py`
- `cd frontend && npm install && npm run dev`

Pages: Dashboard, Live traffic, Scenario suite, Threat simulator, Token verification, Detection performance.
