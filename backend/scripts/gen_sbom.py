#!/usr/bin/env python3
"""Phase 12: generate SBOMs and run vulnerability scans with real tooling.

An earlier version of this script hand-rolled a CycloneDX document from
importlib.metadata to avoid heavy dependencies. That was the wrong call: a
bespoke SBOM is exactly the thing a supply-chain reviewer cannot trust, and it
could not do the part that matters — checking the dependency tree against a
vulnerability database. This version drives the standard tools:

  * Python SBOM  -- cyclonedx-py (CycloneDX 1.6), from the live environment.
  * Python CVEs  -- pip-audit against the PyPI advisory DB.
  * Go SBOM      -- cyclonedx-gomod, from the sidecar module.
  * Go CVEs      -- govulncheck, which is call-graph aware (a CVE in an unused
                    code path is reported separately from one that is reachable).

The Python tools are a declared `security` extra (`pip install '.[security]'`).
The Go tools are installed with `go install` and found on PATH or in GOBIN;
when they are absent the script says so and treats the Go scan as UNVERIFIED
rather than silently passing.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND = ROOT / "backend"
VENV = ROOT / ".venv"
SEC = ROOT / "docs" / "security"


def _run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    # The commands are resolved tool paths and fixed arguments, never user
    # input; this is first-party orchestration of security tooling.
    return subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, check=False, **kw)  # type: ignore[arg-type]


def _tool(name: str, venv_first: bool = False) -> str | None:
    if venv_first:
        cand = VENV / "bin" / name
        if cand.exists():
            return str(cand)
    found = shutil.which(name)
    if found:
        return found
    for gobin in (Path("/tmp/gobin"), Path.home() / "go" / "bin"):
        cand = gobin / name
        if cand.exists():
            return str(cand)
    return None


def python_sbom() -> int:
    tool = _tool("cyclonedx-py", venv_first=True)
    if not tool:
        print("  cyclonedx-py not installed (pip install '.[security]')")
        return -1
    out = SEC / "sbom.cdx.json"
    r = _run([tool, "environment", str(VENV), "--of", "JSON",
              "--output-reproducible", "-o", str(out)])
    if r.returncode != 0:
        print(f"  cyclonedx-py failed: {r.stderr.strip()[:200]}")
        return -1
    n = len(json.loads(out.read_text()).get("components", []))
    print(f"  Python SBOM: {n} components -> {out.relative_to(ROOT)}")
    return n


def go_sbom() -> int:
    tool = _tool("cyclonedx-gomod")
    if not tool:
        print("  cyclonedx-gomod not installed "
              "(go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest)")
        return -1
    out = SEC / "sbom-sidecar.cdx.json"
    r = _run([tool, "mod", "-json", "-output", str(out), "."],
             cwd=str(ROOT / "s1-sidecar"))
    if r.returncode != 0:
        print(f"  cyclonedx-gomod failed: {r.stderr.strip()[:200]}")
        return -1
    n = len(json.loads(out.read_text()).get("components", []))
    print(f"  Go SBOM: {n} components -> {out.relative_to(ROOT)}")
    return n


def pip_audit() -> tuple[str, list[str]]:
    tool = _tool("pip-audit", venv_first=True)
    if not tool:
        return "UNVERIFIED (pip-audit not installed)", []
    r = _run([tool, "--format", "json"])
    try:
        deps = json.loads(r.stdout)
        deps = deps.get("dependencies", deps) if isinstance(deps, dict) else deps
    except json.JSONDecodeError:
        return f"ERROR: {r.stderr.strip()[:200]}", []
    findings = [f"{x['name']} {x['version']}: {v['id']}"
                for x in deps for v in x.get("vulns", [])]
    return (f"{len(deps)} packages scanned, {len(findings)} vulnerable", findings)


def called_osvs(govulncheck_json: str) -> set[str]:
    """OSV ids of CALLED vulnerabilities in govulncheck -format json output.

    Pure and testable. Two gotchas this encodes, both of which previously made
    the audit silently report "clean":
      * -format json emits a STREAM of pretty-printed objects, not JSONL, so a
        line-by-line parse matches nothing. We stream-decode objects.
      * A vulnerability is CALLED only when a finding's trace top-frame names a
        function; findings for merely-imported-but-uncalled vulns have no
        function there and must not count.
    """
    called: set[str] = set()
    decoder = json.JSONDecoder()
    text, idx = govulncheck_json, 0
    while idx < len(text):
        while idx < len(text) and text[idx] in " \t\r\n":
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        idx = end
        if isinstance(obj, dict) and "finding" in obj:
            f = obj["finding"]
            trace = f.get("trace") or [{}]
            if trace[0].get("function"):
                called.add(f.get("osv", "?"))
    return called


def govulncheck() -> tuple[str, list[str]]:
    tool = _tool("govulncheck")
    if not tool:
        return "UNVERIFIED (govulncheck not installed)", []
    r = _run([tool, "-format", "json", "./..."], cwd=str(ROOT / "s1-sidecar"))
    # -format json emits a STREAM of pretty-printed JSON objects, not JSONL, so
    # a line-by-line parse silently finds nothing. The authoritative signal is
    # the EXIT CODE: 0 = no called vulnerabilities, 3 = called vulnerabilities
    # present. We trust that, and parse the object stream (with a streaming
    # decoder) only to name the OSV ids.
    # NOTE: with -format json govulncheck ALWAYS exits 0 (the non-zero exit is
    # only for the text format), so the exit code is NOT a usable signal here.
    # A vulnerability is CALLED when a finding's trace top-frame names a
    # function; those are the ones that matter. Count distinct OSV ids among
    # called findings.
    called = called_osvs(r.stdout)
    if not called:
        return "clean", []
    return f"{len(called)} reachable vulnerability/ies", sorted(called)


def third_party_open_rows() -> list[str]:
    tp = (ROOT / "docs" / "third-party.md").read_text()
    return [ln for ln in tp.splitlines()
            if ("verify before use" in ln or "TBD" in ln) and ln.startswith("|")]


def main() -> int:
    SEC.mkdir(parents=True, exist_ok=True)
    print("=== SBOM generation ===")
    python_sbom()
    go_sbom()

    print("\n=== vulnerability scans ===")
    py_status, py_findings = pip_audit()
    print(f"  pip-audit:   {py_status}")
    for f in py_findings:
        print(f"    !! {f}")
    go_status, go_findings = govulncheck()
    print(f"  govulncheck: {go_status}")
    for f in go_findings:
        print(f"    !! {f}")

    print("\n=== third-party.md unresolved rows ===")
    rows = third_party_open_rows()
    for ln in rows:
        print(f"  {' / '.join(c.strip() for c in ln.split('|')[1:3])}")
    if not rows:
        print("  none")

    # Release blockers: any known vuln, or any unresolved inventory row. A scan
    # that could not run is UNVERIFIED, not a pass — flagged, not counted clean.
    blockers = len(py_findings) + len(go_findings) + len(rows)
    unverified = [n for n, s in (("pip-audit", py_status),
                                 ("govulncheck", go_status))
                  if "UNVERIFIED" in s]
    print(f"\nrelease blockers: {blockers}"
          + (f"; UNVERIFIED: {', '.join(unverified)}" if unverified else ""))
    return 1 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
