#!/usr/bin/env python3
"""Cross-corpus evaluation: tune on CSIC 2010, test on ECML/PKDD 2007.

This is the headline gate of the project's evaluation protocol. The
transformer-WAF literature almost never reports it, and the generalisation
literature says it is where same-corpus results fall apart.

Two questions:

1. **Does detection transfer?** Thresholds derived on CSIC, applied to a
   corpus with a different generator, different application, randomised
   paths, parameter names and headers.
2. **Do the TUNING EXCLUSIONS transfer?** The CSIC exclusions were written
   for a specific app (a password field named ``pwd``, 2010-era
   Accept-Charset). Exclusions that silently weaken detection on a different
   application would be a serious operational trap, so we measure with and
   without them.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from csf.data.corpus import AttackClass, Request, deduplicate  # noqa: E402
from csf.data.loaders import load_ecml_pkdd  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
SOCKET = os.environ.get("CSF_S1_SOCKET", "/tmp/csf-s1.sock")
ECML = (ROOT / "data/raw/waad/OriginalDataSets/ecml_pkdd/"
        "dataset_ecml_pkdd_train_test/xml_test.txt")
CLAIMED = (AttackClass.SQLI, AttackClass.XSS, AttackClass.CMDI,
           AttackClass.TRAVERSAL)


def load_csic_val() -> list[Request]:
    path = ROOT / "data/processed/val.jsonl"
    return [Request.from_dict(json.loads(line))
            for line in path.read_text().splitlines() if line]


def evaluate(rows: list[Request], label: str) -> list[dict]:
    client = httpx.Client(transport=httpx.HTTPTransport(uds=SOCKET),
                          base_url="http://s1", timeout=60.0)
    client.get("/healthz").raise_for_status()
    out = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        d = client.post("/eval", json={
            "id": str(i), "method": r.method, "path": r.path,
            "query": r.query, "headers": r.headers, "body": r.body}).json()
        out.append({"label": str(r.label), "detection": d["anomaly_score"],
                    "engine_us": d["elapsed_us"]})
        if (i + 1) % 1000 == 0:
            print(f"    {label}: {i+1}/{len(rows)}…")
    print(f"    {label}: {len(rows)} in {time.perf_counter()-t0:.1f}s")
    client.close()
    return out


def curve(results: list[dict], thresholds: list[int]) -> list[dict]:
    benign = [r["detection"] for r in results if r["label"] == "benign"]
    claimed = [r for r in results if r["label"] in {str(c) for c in CLAIMED}]
    rows = []
    for t in thresholds:
        fp = sum(1 for s in benign if s >= t)
        tp = sum(1 for r in claimed if r["detection"] >= t)
        rows.append({
            "threshold": t,
            "fpr_pct": fp / len(benign) * 100 if benign else 0.0,
            "recall_pct": tp / len(claimed) * 100 if claimed else 0.0,
            "false_positives": fp,
        })
    return rows


def per_class(results: list[dict], threshold: int) -> dict[str, float]:
    out = {}
    for cls in sorted({r["label"] for r in results if r["label"] != "benign"}):
        vals = [r["detection"] for r in results if r["label"] == cls]
        out[cls] = sum(1 for s in vals if s >= threshold) / len(vals) * 100
    return out


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else "tuned"
    thresholds = [1, 3, 5, 8, 10, 15, 20, 25, 30, 40]

    print(f"=== loading ECML/PKDD 2007 (config: {tag}) ===")
    normalize = os.environ.get("ECML_PROTOCOL_NORMALIZE", "1") == "1"
    print(f"  protocol_normalize={normalize}")
    ecml = load_ecml_pkdd(ECML, per_class_limit=700,
                          protocol_normalize=normalize)
    ecml, stats = deduplicate(ecml)
    print(f"  {len(ecml)} requests after dedup "
          f"({stats.exact_duplicates} dupes removed)")
    print("  by label: " + ", ".join(
        f"{k}={v}" for k, v in sorted(stats.by_label.items())))

    print("\n=== evaluating ===")
    csic = load_csic_val()
    csic_results = evaluate(csic, "CSIC val")
    ecml_results = evaluate(ecml, "ECML test")

    csic_curve = curve(csic_results, thresholds)
    ecml_curve = curve(ecml_results, thresholds)

    print("\n=== CROSS-CORPUS: recall on CLAIMED classes at matched FPR ===")
    print("  (claimed = sqli, xss, cmdi, traversal; CSIC 'other' and ECML"
          " ldap/xpath/ssi excluded from recall)")
    print(f"\n  {'thresh':>7} | {'CSIC FPR':>9} {'CSIC rec':>9} | "
          f"{'ECML FPR':>9} {'ECML rec':>9} | {'delta':>7}")
    print("  " + "-" * 68)
    for a, b in zip(csic_curve, ecml_curve, strict=True):
        delta = b["recall_pct"] - a["recall_pct"]
        print(f"  {a['threshold']:>7} | {a['fpr_pct']:>8.2f}% "
              f"{a['recall_pct']:>8.1f}% | {b['fpr_pct']:>8.2f}% "
              f"{b['recall_pct']:>8.1f}% | {delta:>+6.1f}pp")

    # The headline metric. Comparing recall at a matched THRESHOLD is
    # meaningless across corpora because the same threshold sits at wildly
    # different operating points. What matters is: at the same false-positive
    # rate, how much recall do we keep?
    def recall_at_fpr(results: list[dict], target_fpr: float) -> tuple[float, int]:
        benign = sorted(r["detection"] for r in results if r["label"] == "benign")
        claimed = [r["detection"] for r in results
                   if r["label"] in {str(c) for c in CLAIMED}]
        best = (0.0, 0)
        for t in range(0, 121):
            fpr = sum(1 for s in benign if s >= t) / len(benign)
            if fpr <= target_fpr:
                rec = sum(1 for s in claimed if s >= t) / len(claimed) * 100
                best = (rec, t)
                break
        return best

    print("\n=== HEADLINE: recall at MATCHED false-positive rate ===")
    print("  (comparing at a matched THRESHOLD is meaningless across corpora;"
          "\n   the same threshold sits at completely different operating points)")
    print(f"\n  {'target FPR':>11} | {'CSIC recall':>12} {'@thr':>5} | "
          f"{'ECML recall':>12} {'@thr':>5} | {'DROP':>8}")
    print("  " + "-" * 66)
    gate = None
    for target in (0.05, 0.02, 0.01, 0.005, 0.002, 0.001):
        a, ta = recall_at_fpr(csic_results, target)
        b, tb = recall_at_fpr(ecml_results, target)
        drop = a - b
        if abs(target - 0.001) < 1e-9:
            gate = drop
        print(f"  {target*100:>10.1f}% | {a:>11.1f}% {ta:>5} | "
              f"{b:>11.1f}% {tb:>5} | {drop:>+7.1f}pp")
    if gate is not None:
        verdict = "PASS" if gate <= 10 else "FAIL"
        print(f"\n  CROSS-CORPUS GATE (drop at FPR=0.1% must be <= 10pp): "
              f"{gate:+.1f}pp -> {verdict}")

    print("\n=== per-class recall at threshold 8 ===")
    csic_pc = per_class(csic_results, 8)
    ecml_pc = per_class(ecml_results, 8)
    all_classes = sorted(set(csic_pc) | set(ecml_pc))
    print(f"  {'class':<12} {'CSIC':>8} {'ECML':>8} {'delta':>9}")
    for cls in all_classes:
        a = csic_pc.get(cls)
        b = ecml_pc.get(cls)
        a_s = f"{a:.1f}%" if a is not None else "—"
        b_s = f"{b:.1f}%" if b is not None else "—"
        d_s = f"{b-a:+.1f}pp" if (a is not None and b is not None) else "—"
        print(f"  {cls:<12} {a_s:>8} {b_s:>8} {d_s:>9}")

    eng = sorted(r["engine_us"] for r in ecml_results)
    print("\n=== latency on ECML (larger requests: 42 headers) ===")
    print(f"  engine p50={eng[len(eng)//2]}us p95={eng[int(len(eng)*.95)]}us "
          f"p99={eng[int(len(eng)*.99)]}us")

    out = ROOT / "docs" / "benchmarks" / f"cross-corpus-{tag}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "config": tag,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "csic": {"n": len(csic_results), "curve": csic_curve,
                 "per_class_at_8": csic_pc},
        "ecml": {"n": len(ecml_results), "curve": ecml_curve,
                 "per_class_at_8": ecml_pc},
        "latency_us": {"ecml_engine_p50": eng[len(eng)//2],
                       "ecml_engine_p99": eng[int(len(eng)*.99)]},
    }, indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
