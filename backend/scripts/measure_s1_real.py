#!/usr/bin/env python3
"""Re-derive S1 thresholds against the real frozen corpus.

Phase 3's thresholds came from 40 hand-built benign samples, which cannot
establish an FPR below roughly 7%. This runs the same sweep against CSIC 2010
plus curated payload lists.

Uses the VALIDATION split. The test split is the frozen holdout and deriving
thresholds on it would invalidate every later number.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from csf.data.corpus import Request  # noqa: E402

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "processed"
SOCKET = os.environ.get("CSF_S1_SOCKET", "/tmp/csf-s1.sock")  # noqa: S108


def load(split: str) -> list[Request]:
    return [Request.from_dict(json.loads(line))
            for line in (DATA / f"{split}.jsonl").read_text().splitlines() if line]


def main() -> int:
    split_name = sys.argv[1] if len(sys.argv) > 1 else "val"
    rows = load(split_name)
    print(f"evaluating S1 against the {split_name.upper()} split: {len(rows)} requests")
    if split_name == "test":
        print("  ⚠ this is the FROZEN HOLDOUT — report only, never tune on it")

    client = httpx.Client(transport=httpx.HTTPTransport(uds=SOCKET),
                          base_url="http://s1", timeout=30.0)
    client.get("/healthz").raise_for_status()

    results = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        payload = {"id": str(i), "method": r.method, "path": r.path,
                   "query": r.query, "headers": r.headers, "body": r.body}
        d = client.post("/eval", json=payload).json()
        results.append({"label": str(r.label), "source": r.source,
                        "detection": d["anomaly_score"],
                        "engine_us": d["elapsed_us"]})
        if (i + 1) % 500 == 0:
            print(f"    {i+1}/{len(rows)}…")
    wall = time.perf_counter() - t0
    print(f"  evaluated in {wall:.1f}s ({len(rows)/wall:.0f} req/s)")

    benign = [r["detection"] for r in results if r["label"] == "benign"]
    attacks = [r for r in results if r["label"] != "benign"]
    attack_scores = [r["detection"] for r in attacks]

    def describe(name, vals):
        if not vals:
            return
        v = sorted(vals)
        print(f"  {name:<10} n={len(v):<6} p50={v[len(v)//2]:<4} "
              f"p90={v[int(len(v)*.9)]:<4} p99={v[int(len(v)*.99)]:<4} max={v[-1]}")

    print("\n=== score distribution ===")
    describe("benign", benign)
    describe("attack", attack_scores)
    for cls in sorted({r["label"] for r in attacks}):
        describe(cls, [r["detection"] for r in attacks if r["label"] == cls])

    print("\n=== threshold sweep ===")
    print(f"  {'thresh':>7} {'detect%':>9} {'FPR%':>8} {'false+':>8}")
    sweep = []
    for t in [0, 1, 2, 3, 5, 8, 10, 15, 20, 25, 30, 40, 50]:
        tp = sum(1 for s in attack_scores if s >= t)
        fp = sum(1 for s in benign if s >= t)
        det = tp / len(attack_scores) * 100
        fpr = fp / len(benign) * 100
        sweep.append({"threshold": t, "detection_pct": det, "fpr_pct": fpr,
                      "false_positives": fp})
        print(f"  {t:>7} {det:>8.1f}% {fpr:>7.2f}% {fp:>8}")

    print("\n=== per-class recall at candidate thresholds ===")
    classes = sorted({r["label"] for r in attacks})
    print("  " + "thresh".rjust(7) + "".join(f"{c:>12}" for c in classes))
    for t in (5, 8, 10, 15, 20):
        cells = []
        for c in classes:
            vals = [r["detection"] for r in attacks if r["label"] == c]
            cells.append(f"{sum(1 for s in vals if s >= t)/len(vals)*100:>11.1f}%")
        print(f"  {t:>7}" + "".join(cells))

    eng = sorted(r["engine_us"] for r in results)
    print(f"\n=== latency ===\n  CRS engine p50={eng[len(eng)//2]}us "
          f"p95={eng[int(len(eng)*.95)]}us p99={eng[int(len(eng)*.99)]}us")

    out = DATA.parent.parent / "docs" / "benchmarks" / f"s1-real-{split_name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "split": split_name, "n": len(rows),
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "sweep": sweep,
        "benign_p99": sorted(benign)[int(len(benign)*.99)],
        "latency_us": {"engine_p50": eng[len(eng)//2],
                       "engine_p99": eng[int(len(eng)*.99)]},
    }, indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
