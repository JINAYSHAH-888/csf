#!/usr/bin/env python3
"""Does the cascade beat its parts? S1 alone vs S2 alone vs S1+S2.

The ablation the build spec requires. S2's absolute recall (~50%) is modest
and S1's cross-corpus FPR is unusable; the claim is that COMBINED they beat
either alone. This tests that claim on both corpora.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.disable(logging.ERROR)

import httpx  # noqa: E402

from csf.data.corpus import Request, deduplicate  # noqa: E402
from csf.data.loaders import load_ecml_pkdd  # noqa: E402
from csf.extraction import extract  # noqa: E402
from csf.semantic.detector import S2Config, analyze_extraction  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
ECML = (ROOT / "data/raw/waad/OriginalDataSets/ecml_pkdd/"
        "dataset_ecml_pkdd_train_test/xml_test.txt")
CLAIMED = {"sqli", "xss", "cmdi", "traversal"}


def to_ex(r: Request):
    h = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
         for k, vs in r.headers.items() for v in vs]
    return extract(r.method, r.path, r.query.encode("latin-1", "replace"), h,
                   r.body.encode("latin-1", "replace"))


def score_all(rows: list[Request], label: str) -> list[dict]:
    client = httpx.Client(transport=httpx.HTTPTransport(uds="/tmp/csf-s1.sock"),
                          base_url="http://s1", timeout=60.0)
    cfg = S2Config()
    out = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        s1 = client.post("/eval", json={
            "id": str(i), "method": r.method, "path": r.path,
            "query": r.query, "headers": r.headers,
            "body": r.body}).json()["anomaly_score"]
        s2 = analyze_extraction(to_ex(r), cfg).score
        out.append({"label": str(r.label), "s1": s1, "s2": s2})
        if (i + 1) % 1000 == 0:
            print(f"    {label}: {i+1}/{len(rows)}…")
    print(f"    {label}: {len(rows)} in {time.perf_counter()-t0:.1f}s")
    client.close()
    return out


def best_recall_at_fpr(results: list[dict], key, target: float,
                       grid) -> tuple[float, float]:
    """Highest recall achievable at or below target FPR, over the grid."""
    benign = [r for r in results if r["label"] == "benign"]
    claimed = [r for r in results if r["label"] in CLAIMED]
    best = (0.0, 0.0)
    for t in grid:
        fpr = sum(1 for r in benign if key(r, t)) / len(benign)
        if fpr <= target:
            rec = sum(1 for r in claimed if key(r, t)) / len(claimed) * 100
            if rec > best[0]:
                best = (rec, t)
    return best


def main() -> int:
    csic = [Request.from_dict(json.loads(line)) for line in
            (ROOT / "data/processed/val.jsonl").read_text().splitlines() if line]
    ecml, _ = deduplicate(load_ecml_pkdd(ECML, per_class_limit=700,
                                         protocol_normalize=True))
    print(f"=== scoring === CSIC {len(csic)}, ECML {len(ecml)}")
    data = {"CSIC": score_all(csic, "CSIC"), "ECML": score_all(ecml, "ECML")}

    s1_grid = list(range(0, 121, 1))
    s2_grid = [x * 0.5 for x in range(0, 41)]

    for target in (0.01, 0.001):
        print(f"\n=== recall on claimed classes at FPR <= {target*100:.1f}% ===")
        print(f"  {'corpus':<7} {'S1 only':>10} {'S2 only':>10} "
              f"{'S1 OR S2':>10} {'gain':>8}")
        print("  " + "-" * 50)
        for corpus, res in data.items():
            s1_rec, s1_t = best_recall_at_fpr(
                res, lambda r, t: r["s1"] >= t, target, s1_grid)
            s2_rec, s2_t = best_recall_at_fpr(
                res, lambda r, t: r["s2"] >= t, target, s2_grid)
            # Union at the per-stage thresholds that each hit the FPR target
            # individually; the combined FPR is measured, not assumed.
            benign = [r for r in res if r["label"] == "benign"]
            claimed = [r for r in res if r["label"] in CLAIMED]
            # Bind the thresholds explicitly rather than closing over the
            # loop variables: correct here only because the closure is used
            # in the same iteration, which is exactly the fragile pattern.
            def fired(r: dict, a: float = s1_t, b: float = s2_t) -> bool:
                return r["s1"] >= a or r["s2"] >= b

            comb_fpr = sum(1 for r in benign if fired(r)) / len(benign) * 100
            comb_rec = sum(1 for r in claimed if fired(r)) / len(claimed) * 100
            gain = comb_rec - max(s1_rec, s2_rec)
            print(f"  {corpus:<7} {s1_rec:>9.1f}% {s2_rec:>9.1f}% "
                  f"{comb_rec:>9.1f}% {gain:>+7.1f}pp   "
                  f"(combined FPR {comb_fpr:.2f}%)")

    # The deployment-realistic test. The ablation above hands each stage its
    # per-corpus OPTIMAL threshold, which no real deployment can know: you
    # tune on the traffic you have and ship to the application you have not
    # seen. This measures that instead.
    print("\n=== DEPLOYMENT-REALISTIC: tune on CSIC, deploy on ECML ===")
    print("  (thresholds frozen from CSIC; no re-tuning on the target)")
    csic_res, ecml_res = data["CSIC"], data["ECML"]
    _, s1_t = best_recall_at_fpr(csic_res, lambda r, t: r["s1"] >= t, 0.001, s1_grid)
    _, s2_t = best_recall_at_fpr(csic_res, lambda r, t: r["s2"] >= t, 0.001, s2_grid)
    print(f"  frozen thresholds: S1 >= {s1_t}, S2 >= {s2_t}")

    benign = [r for r in ecml_res if r["label"] == "benign"]
    claimed = [r for r in ecml_res if r["label"] in CLAIMED]
    print(f"\n  {'config':<12} {'recall':>9} {'FPR':>9}   verdict")
    print("  " + "-" * 52)
    for name, fired in (
        ("S1 only", lambda r: r["s1"] >= s1_t),
        ("S2 only", lambda r: r["s2"] >= s2_t),
        ("S1 OR S2", lambda r: r["s1"] >= s1_t or r["s2"] >= s2_t),
    ):
        rec = sum(1 for r in claimed if fired(r)) / len(claimed) * 100
        fpr = sum(1 for r in benign if fired(r)) / len(benign) * 100
        verdict = "UNUSABLE" if fpr > 5 else "usable"
        print(f"  {name:<12} {rec:>8.1f}% {fpr:>8.2f}%   {verdict}")

    # The residual: what neither stage catches. Reported at TWO operating
    # points, because the choice of point changes the number by a factor of
    # three and only one of them describes a deployment.
    #
    #   per-corpus 0.1% FPR -- each stage gets the threshold that is optimal on
    #     the corpus being measured. Tightest possible, and unobtainable: it
    #     requires labelled traffic from the application you have not deployed
    #     to yet. This is the point the 59.2% figure was first quoted at.
    #   configured -- the thresholds the gateway actually ships with
    #     (S2Config.tau_block) and the S1 threshold frozen from CSIC. This is
    #     what a real deployment misses.
    #
    # Reporting only the first understates detection; reporting only the second
    # understates the false-positive cost. Both are printed and persisted.
    print("\n=== complementarity: what each stage catches alone ===")

    _, frozen_s1 = best_recall_at_fpr(data["CSIC"], lambda r, t: r["s1"] >= t,
                                      0.001, s1_grid)
    points: dict[str, object] = {}
    for point in ("per-corpus 0.1% FPR", "configured thresholds"):
        print(f"\n  at {point}:")
        for corpus, res in data.items():
            if point.startswith("per-corpus"):
                _, s1_t = best_recall_at_fpr(res, lambda r, t: r["s1"] >= t,
                                             0.001, s1_grid)
                _, s2_t = best_recall_at_fpr(res, lambda r, t: r["s2"] >= t,
                                             0.001, s2_grid)
            else:
                s1_t, s2_t = frozen_s1, S2Config().tau_block
            claimed = [r for r in res if r["label"] in CLAIMED]
            benign_rows = [r for r in res if r["label"] == "benign"]
            both = sum(1 for r in claimed if r["s1"] >= s1_t and r["s2"] >= s2_t)
            only1 = sum(1 for r in claimed if r["s1"] >= s1_t and r["s2"] < s2_t)
            only2 = sum(1 for r in claimed if r["s1"] < s1_t and r["s2"] >= s2_t)
            neither = len(claimed) - both - only1 - only2
            fpr = (sum(1 for r in benign_rows
                       if r["s1"] >= s1_t or r["s2"] >= s2_t)
                   / len(benign_rows) * 100) if benign_rows else 0.0
            n = len(claimed)
            print(f"    {corpus}: S1>={s1_t} S2>={s2_t}  "
                  f"both={both/n*100:.1f}% S1-only={only1/n*100:.1f}% "
                  f"S2-only={only2/n*100:.1f}% MISSED={neither/n*100:.1f}%  "
                  f"(FPR {fpr:.2f}%)")
            points[f"{point}|{corpus}"] = {
                "s1_threshold": s1_t, "s2_threshold": s2_t, "claimed_n": n,
                "both_pct": both / n * 100, "s1_only_pct": only1 / n * 100,
                "s2_only_pct": only2 / n * 100, "missed_pct": neither / n * 100,
                "combined_fpr_pct": fpr,
            }

    out = ROOT / "docs" / "benchmarks" / "cascade-ablation.json"
    # Persist the full result, not a summary. A benchmark file that stores only
    # a headline number cannot answer "did this change help?", which is the one
    # question it exists for: comparing two runs then means re-running the old
    # code. Every printed figure is recorded here.
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "counts": {k: len(v) for k, v in data.items()},
        "residual_by_operating_point": points,
    }, indent=2, sort_keys=True))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
