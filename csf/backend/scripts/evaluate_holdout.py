#!/usr/bin/env python3
"""Phase 14: the one-time frozen-holdout evaluation.

test.jsonl has been sealed since Phase 4. No threshold, no model, no analyser
change was ever derived from it — that was the whole point of recording its
hash. This script spends it, once, to produce the end-of-project number on data
used for nothing else.

What this measures, and what it does NOT:
  * IT DOES measure in-distribution generalisation: train/val/test are all
    CSIC-derived, split by template group so no row or endpoint leaks across
    them. This is "how does the deployed cascade do on held-out traffic from
    the same world it was built in."
  * IT DOES NOT measure cross-application transfer. That is ECML/PKDD, measured
    separately (Phase 5/6/8), and it is the harder, more honest number. This
    holdout cannot substitute for it and the report says so.

The operating point is the one the gateway actually ships: S1 blocks at the
CRS anomaly tau_high=8, S2 at tau_block=4.0, fused disjunctively. No tuning
happens here; the thresholds come from config, not from this data.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from csf.data.corpus import Request  # noqa: E402
from csf.extraction import extract  # noqa: E402
from csf.s1_rules import S1Config  # noqa: E402
from csf.semantic.detector import S2Config, analyze_extraction  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
TEST = ROOT / "data" / "processed" / "test.jsonl"
MANIFEST = ROOT / "data" / "processed" / "manifest.json"
CLAIMED = {"sqli", "xss", "cmdi", "traversal"}
SOCKET = "/tmp/csf-s1.sock"


def verify_frozen() -> str:
    """Abort unless the holdout's hash matches the manifest. A holdout that has
    changed since it was frozen invalidates every number derived from it."""
    recorded = json.loads(MANIFEST.read_text())["splits"]["test"]["sha256"]
    actual = hashlib.sha256(TEST.read_bytes()).hexdigest()
    if actual != recorded:
        sys.exit(f"FATAL: test.jsonl hash {actual} != manifest {recorded}. "
                 "The frozen holdout has been modified; results would be invalid.")
    return actual


def to_ex(r: Request):
    h = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
         for k, vs in r.headers.items() for v in vs]
    return extract(r.method, r.path, r.query.encode("latin-1", "replace"), h,
                   r.body.encode("latin-1", "replace"))


def main() -> int:
    digest = verify_frozen()
    print(f"=== frozen holdout verified: sha256={digest[:16]}… ===")

    rows = [Request.from_dict(json.loads(line))
            for line in TEST.read_text().splitlines() if line]
    print(f"  {len(rows)} requests (used for evaluation ONCE, now)")

    s1_block = S1Config().tau_high      # 11.0, on the attack score (ADR-0015)
    s2_block = S2Config().tau_block     # 4.0
    s1_field = S1Config().score_field   # "attack"
    print(f"  operating point: S1 {s1_field}_score >= {s1_block}  OR  S2 >= "
          f"{s2_block} (disjunctive, as shipped)\n")

    client = httpx.Client(transport=httpx.HTTPTransport(uds=SOCKET),
                          base_url="http://s1", timeout=60.0)
    results = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        s1 = client.post("/eval", json={
            "id": str(i), "method": r.method, "path": r.path,
            "query": r.query, "headers": r.headers, "body": r.body}).json()
        s2 = analyze_extraction(to_ex(r), S2Config()).score
        s1_score = s1.get("attack_score", s1["anomaly_score"])
        blocked = s1_score >= s1_block or s2 >= s2_block
        results.append({"label": str(r.label), "s1": s1_score,
                        "s1_anomaly": s1["anomaly_score"], "s2": s2,
                        "blocked": blocked, "by_s1": s1_score >= s1_block,
                        "by_s2": s2 >= s2_block})
        if (i + 1) % 500 == 0:
            print(f"    {i+1}/{len(rows)}…")
    client.close()
    print(f"  scored in {time.perf_counter()-t0:.1f}s\n")

    # Per-class recall and benign FPR at the shipped operating point.
    print("=== result at the shipped operating point ===")
    print(f"  {'class':<10} {'n':>5} {'blocked':>9} {'rate':>8}")
    per_class = {}
    for cls in ("benign", "other", *sorted(CLAIMED)):
        sub = [r for r in results if r["label"] == cls]
        if not sub:
            continue
        blk = sum(1 for r in sub if r["blocked"])
        rate = blk / len(sub) * 100
        tag = "(FPR)" if cls == "benign" else "(recall)" if cls in CLAIMED else ""
        print(f"  {cls:<10} {len(sub):>5} {blk:>9} {rate:>7.1f}% {tag}")
        per_class[cls] = {"n": len(sub), "blocked": blk, "rate_pct": round(rate, 2)}

    claimed = [r for r in results if r["label"] in CLAIMED]
    benign = [r for r in results if r["label"] == "benign"]
    overall_recall = sum(1 for r in claimed if r["blocked"]) / len(claimed) * 100
    overall_fpr = sum(1 for r in benign if r["blocked"]) / len(benign) * 100
    s1_only = sum(1 for r in claimed if r["by_s1"]) / len(claimed) * 100
    s2_only = sum(1 for r in claimed if r["by_s2"]) / len(claimed) * 100

    print(f"\n  claimed-class recall: {overall_recall:.1f}%")
    print(f"  benign FPR:           {overall_fpr:.2f}%")
    print(f"  (S1 alone {s1_only:.1f}%, S2 alone {s2_only:.1f}%, cascade "
          f"{overall_recall:.1f}%)")

    out = ROOT / "docs" / "benchmarks" / "frozen-holdout.json"
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "holdout_sha256": digest,
        "n": len(rows),
        "operating_point": {"s1_field": s1_field, "s1_block": s1_block,
                            "s2_block": s2_block, "fusion": "disjunctive"},
        "per_class": per_class,
        "claimed_recall_pct": round(overall_recall, 2),
        "benign_fpr_pct": round(overall_fpr, 2),
        "note": "In-distribution frozen holdout (CSIC-derived), used once. "
                "Cross-application transfer is measured separately on ECML/PKDD.",
    }, indent=2, sort_keys=True))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
