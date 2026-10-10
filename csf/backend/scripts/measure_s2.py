#!/usr/bin/env python3
"""Measure S2 (grammar-aware semantic analysis) on both corpora.

The question this answers: does grammar transfer across applications where
regex signatures do not? S1 lost 50.8pp of recall going CSIC -> ECML at
matched FPR. SQL grammar does not change when the application changes, so S2
should hold up far better. That is the hypothesis; this measures it.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.disable(logging.ERROR)  # sqlglot logs unsupported-syntax fallbacks

from csf.data.corpus import Request, deduplicate  # noqa: E402
from csf.data.loaders import load_ecml_pkdd  # noqa: E402
from csf.extraction import extract  # noqa: E402
from csf.semantic.detector import S2Config, analyze_extraction  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
ECML = (ROOT / "data/raw/waad/OriginalDataSets/ecml_pkdd/"
        "dataset_ecml_pkdd_train_test/xml_test.txt")
CLAIMED = {"sqli", "xss", "cmdi", "traversal"}


def to_extraction(r: Request):
    headers = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
               for k, vs in r.headers.items() for v in vs]
    return extract(r.method, r.path, r.query.encode("latin-1", "replace"),
                   headers, r.body.encode("latin-1", "replace"))


def run(rows: list[Request], label: str) -> list[dict]:
    cfg = S2Config()
    out = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        signal = analyze_extraction(to_extraction(r), cfg)
        out.append({"label": str(r.label), "score": signal.score,
                    "classes": signal.classes, "us": signal.elapsed_us,
                    "parsed": signal.candidates_parsed})
        if (i + 1) % 1000 == 0:
            print(f"    {label}: {i+1}/{len(rows)}…")
    print(f"    {label}: {len(rows)} in {time.perf_counter()-t0:.1f}s")
    return out


def recall_at_fpr(results: list[dict], target: float) -> tuple[float, float]:
    benign = [r["score"] for r in results if r["label"] == "benign"]
    claimed = [r["score"] for r in results if r["label"] in CLAIMED]
    if not benign or not claimed:
        return 0.0, 0.0
    for t in [x * 0.5 for x in range(0, 61)]:
        fpr = sum(1 for s in benign if s >= t) / len(benign)
        if fpr <= target:
            return sum(1 for s in claimed if s >= t) / len(claimed) * 100, t
    return 0.0, 30.0


def main() -> int:
    print("=== loading ===")
    csic = [Request.from_dict(json.loads(line))
            for line in (ROOT / "data/processed/val.jsonl").read_text().splitlines()
            if line]
    ecml, _ = deduplicate(load_ecml_pkdd(ECML, per_class_limit=700,
                                         protocol_normalize=True))
    print(f"  CSIC val {len(csic)}, ECML {len(ecml)}")

    print("\n=== evaluating ===")
    csic_r = run(csic, "CSIC")
    ecml_r = run(ecml, "ECML")

    for name, res in (("CSIC val", csic_r), ("ECML test", ecml_r)):
        print(f"\n=== {name}: score distribution ===")
        for cls in sorted({r["label"] for r in res}):
            vals = sorted(r["score"] for r in res if r["label"] == cls)
            nz = sum(1 for v in vals if v > 0)
            print(f"  {cls:<10} n={len(vals):<5} p50={vals[len(vals)//2]:<5.1f} "
                  f"p95={vals[int(len(vals)*.95)]:<5.1f} max={vals[-1]:<5.1f} "
                  f"nonzero={nz/len(vals)*100:.1f}%")

    print("\n=== S2 cross-corpus: recall on claimed classes at matched FPR ===")
    print(f"  {'target FPR':>11} | {'CSIC':>8} {'@thr':>6} | {'ECML':>8} {'@thr':>6} | {'DROP':>8}")
    print("  " + "-" * 60)
    gate = None
    for target in (0.05, 0.02, 0.01, 0.005, 0.002, 0.001):
        a, ta = recall_at_fpr(csic_r, target)
        b, tb = recall_at_fpr(ecml_r, target)
        if abs(target - 0.001) < 1e-9:
            gate = a - b
        print(f"  {target*100:>10.1f}% | {a:>7.1f}% {ta:>6.1f} | "
              f"{b:>7.1f}% {tb:>6.1f} | {a-b:>+7.1f}pp")
    if gate is not None:
        print(f"\n  S2 CROSS-CORPUS GATE (<=10pp at FPR 0.1%): {gate:+.1f}pp "
              f"-> {'PASS' if gate <= 10 else 'FAIL'}")
        print("  (S1 measured +50.8pp on the same comparison)")

    # Separating the two things the aggregate conflates. "Recall at matched
    # FPR" moves BOTH the threshold and the operating point, so a corpus whose
    # benign tail is heavier looks like a detection failure when it is really
    # a false-positive failure. At a MATCHED THRESHOLD the detector is doing
    # literally the same thing on both corpora, so recall and FPR can be read
    # independently.
    print("\n=== detection vs false-positive transfer, at MATCHED threshold ===")
    print(f"  {'thr':>5} | {'CSIC rec':>9} {'CSIC FPR':>9} | "
          f"{'ECML rec':>9} {'ECML FPR':>9} | {'rec delta':>10}")
    print("  " + "-" * 64)

    def at(results: list[dict], t: float) -> tuple[float, float]:
        benign = [r["score"] for r in results if r["label"] == "benign"]
        claimed = [r["score"] for r in results if r["label"] in CLAIMED]
        rec = sum(1 for s in claimed if s >= t) / len(claimed) * 100
        fpr = sum(1 for s in benign if s >= t) / len(benign) * 100
        return rec, fpr

    for t in (0.5, 2.5, 4.5, 5.5, 8.5):
        ra, fa = at(csic_r, t)
        rb, fb = at(ecml_r, t)
        print(f"  {t:>5.1f} | {ra:>8.1f}% {fa:>8.2f}% | "
              f"{rb:>8.1f}% {fb:>8.2f}% | {rb-ra:>+9.1f}pp")

    print("\n=== per-class recall at the CSIC 0.1%-FPR threshold ===")
    _, thr = recall_at_fpr(csic_r, 0.001)
    print(f"  threshold = {thr}")
    print(f"  {'class':<12} {'CSIC':>9} {'ECML':>9}")
    per_class: dict[str, dict[str, float | None]] = {}
    for cls in sorted(CLAIMED | {"other", "benign"}):
        a = [r["score"] for r in csic_r if r["label"] == cls]
        b = [r["score"] for r in ecml_r if r["label"] == cls]
        ra = sum(1 for s in a if s >= thr) / len(a) * 100 if a else None
        rb = sum(1 for s in b if s >= thr) / len(b) * 100 if b else None
        fa = f"{ra:.1f}%" if ra is not None else "—"
        fb = f"{rb:.1f}%" if rb is not None else "—"
        tag = " (FPR)" if cls == "benign" else ""
        print(f"  {cls:<12} {fa:>9} {fb:>9}{tag}")
        per_class[cls] = {"csic_pct": ra, "ecml_pct": rb}

    # Recall at the CONFIGURED blocking threshold, which the grid above does
    # not contain. This is the operating point the gateway ships with, so it
    # is the one a change to the analysers has to be judged at.
    tau = S2Config().tau_block
    deployed: dict[str, dict[str, float]] = {}
    for corpus, rows in (("CSIC", csic_r), ("ECML", ecml_r)):
        cl = [r["score"] for r in rows if r["label"] in CLAIMED]
        bn = [r["score"] for r in rows if r["label"] == "benign"]
        deployed[corpus] = {
            "threshold": tau,
            "recall_pct": sum(1 for s in cl if s >= tau) / len(cl) * 100 if cl else 0.0,
            "fpr_pct": sum(1 for s in bn if s >= tau) / len(bn) * 100 if bn else 0.0,
        }
    print(f"\n=== at the CONFIGURED blocking threshold (tau_block={tau}) ===")
    for corpus, d in deployed.items():
        print(f"  {corpus}: recall={d['recall_pct']:.1f}%  FPR={d['fpr_pct']:.2f}%")

    lat = sorted(r["us"] for r in csic_r + ecml_r)
    print("\n=== latency (pure CPU, no I/O) ===")
    print(f"  p50={lat[len(lat)//2]}us p95={lat[int(len(lat)*.95)]}us "
          f"p99={lat[int(len(lat)*.99)]}us max={lat[-1]}us")

    out = ROOT / "docs" / "benchmarks" / "s2-semantic.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "csic_n": len(csic_r), "ecml_n": len(ecml_r),
        "cross_corpus_drop_pp_at_fpr_0.1pct": gate,
        # The full table, not a headline. A benchmark file that records one
        # number cannot answer "did this change help?", which is the question
        # it exists for -- comparing two runs would mean re-running old code.
        "per_class_recall_at_csic_0.1pct_fpr": per_class,
        "at_configured_tau_block": deployed,
        "latency_us": {"p50": lat[len(lat)//2], "p95": lat[int(len(lat)*.95)],
                       "p99": lat[int(len(lat)*.99)], "max": lat[-1]},
    }, indent=2, sort_keys=True))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
