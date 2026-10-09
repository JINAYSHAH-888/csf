#!/usr/bin/env python3
"""Derive a safe operating point from a deployment's own shadow traffic.

The gap this closes (ADR-0011/0015): there is no cross-application SAFE DEFAULT
threshold, and there cannot be one derived from two corpora — the development
corpus is 100%-precise at every threshold, so it cannot tell a safe threshold
from a dangerous one. ADR-0011's prescription was "set the operating point
during shadow mode," i.e. from the target application's own traffic. This is
the tool that does it.

Input: a JSONL of requests the gateway saw in SHADOW mode on the target app
(real traffic, overwhelmingly benign; attacks are rare in production). Scored
through the real S1 sidecar and S2. The block rate on this traffic is, to a
close approximation, the FALSE-POSITIVE RATE the operator would get in enforce
mode — because almost none of it is actually an attack.

Output: the lowest (most sensitive, highest-recall) S1/S2 thresholds whose
block rate on this traffic stays within the operator's budget, plus a ready
config snippet. Lower thresholds mean more recall, so "lowest within budget" is
the best recall the operator can safely deploy on THIS application.

What it does NOT do: measure recall. Shadow traffic is unlabeled and mostly
benign, so it bounds FPR only; recall comes from the cross-corpus-validated
detectors (ADR-0015). Stated so no one reads a recall claim into it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from csf.data.corpus import Request  # noqa: E402
from csf.extraction import extract  # noqa: E402
from csf.semantic.detector import S2Config, analyze_extraction  # noqa: E402

S1_GRID = [8, 11, 15, 20, 25, 30, 40]
S2_GRID = [4.0, 5.0, 6.0, 7.0, 8.0]


def to_ex(r: Request):
    h = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
         for k, vs in r.headers.items() for v in vs]
    return extract(r.method, r.path, r.query.encode("latin-1", "replace"), h,
                   r.body.encode("latin-1", "replace"))


def recommend(scored: list[tuple[float, float]], budget_pct: float,
              s1_grid: list[int] | None = None,
              s2_grid: list[float] | None = None) -> tuple | None:
    """Lowest (highest-recall) thresholds whose block rate stays within budget.

    Pure and testable: given per-request (s1, s2) scores it is just arithmetic.
    Grids ascending, so the smallest feasible (t1, t2) is the most sensitive
    operating point the budget allows.
    """
    s1_grid = s1_grid or S1_GRID
    s2_grid = s2_grid or S2_GRID
    n = len(scored) or 1
    best: tuple | None = None
    for t1 in s1_grid:
        for t2 in s2_grid:
            rate = sum(1 for s1, s2 in scored if s1 >= t1 or s2 >= t2) / n * 100
            if rate <= budget_pct and (best is None or (t1, t2) < (best[0], best[1])):
                best = (t1, t2, rate)
    return best


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("traffic", help="JSONL of the app's own shadow-mode requests")
    ap.add_argument("--socket", default="/tmp/csf-s1.sock")
    ap.add_argument("--budget-pct", type=float, default=0.5,
                    help="max tolerable block rate (≈FPR) on this traffic")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = [Request.from_dict(json.loads(line))
            for line in Path(args.traffic).read_text().splitlines() if line]
    if args.limit:
        rows = rows[: args.limit]
    print(f"=== calibrating on {len(rows)} shadow requests, "
          f"budget {args.budget_pct}% ===\n")

    client = httpx.Client(transport=httpx.HTTPTransport(uds=args.socket),
                          base_url="http://s1", timeout=60.0)
    scored = []
    for r in rows:
        res = client.post("/eval", json={
            "id": "x", "method": r.method, "path": r.path, "query": r.query,
            "headers": r.headers, "body": r.body}).json()
        s1 = res.get("attack_score", res["anomaly_score"])
        s2 = analyze_extraction(to_ex(r), S2Config()).score
        scored.append((s1, s2))
    client.close()

    best = recommend(scored, args.budget_pct)
    n = len(scored)

    print(f"  {'S1 tau_high':>12} {'S2 tau_block':>13} {'block rate':>11}")
    for t1 in S1_GRID:
        for t2 in S2_GRID:
            rate = sum(1 for s1, s2 in scored if s1 >= t1 or s2 >= t2) / n * 100
            mark = "  <= budget" if rate <= args.budget_pct else ""
            print(f"  {t1:>12} {t2:>13.1f} {rate:>10.2f}%{mark}")

    print()
    if best is None:
        print("  NO operating point within budget on this traffic. Either the "
              "budget is too tight, or this traffic is not representative "
              "(it may contain real attacks). Inspect the high-scoring "
              "requests before loosening the budget.")
        return 2
    t1, t2, rate = best
    print(f"  RECOMMENDED: S1 tau_high={t1}, S2 tau_block={t2} "
          f"(block rate {rate:.2f}% on this traffic)\n")
    print("  config snippet:")
    print(json.dumps({"s1": {"tau_high": t1, "score_field": "attack"},
                      "s2": {"tau_block": t2}}, indent=2))
    print("\n  Note: this bounds FALSE POSITIVES on your traffic. Recall comes "
          "from the detectors' cross-corpus validation (ADR-0015); this tool "
          "does not and cannot measure it from unlabeled shadow traffic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
