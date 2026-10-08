@echo off
rem Starts the full CSF demo: S1 (Go/Coraza) sidecar + gateway + demo shop + console API in Docker,
rem then the frontend dev server. Docker Desktop must be running.
cd /d "%~dp0"
set "PATH=%PATH%;C:\Program Files\Docker\Docker\resources\bin"
docker compose -f console-api\compose.yaml up -d --build
if errorlevel 1 (
  echo Docker stack failed to start. Falling back to the native backend without S1.
  start "CSF backend" cmd /k "cd backend && uv run python ..\console-api\server.py"
)
start "CSF frontend" cmd /k "cd frontend && npm install && npm run dev -- --open"
