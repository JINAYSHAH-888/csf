@echo off
rem Starts the CSF console API (gateway + demo shop) and the frontend.
cd /d "%~dp0"
start "CSF backend" cmd /k "cd backend && uv run python ..\console-api\server.py"
start "CSF frontend" cmd /k "cd frontend && npm run dev -- --open"
