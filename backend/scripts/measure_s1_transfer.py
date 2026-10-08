#!/usr/bin/env python3
"""Does scoring S1 on attack rules only make it transfer across applications?

The cross-corpus gap (ADR-0015): at a CSIC-derived threshold the full CRS
anomaly score gives 67% FPR on an unseen application (ECML) -- unusable.
Diagnosis showed every ECML benign false positive is anchored by a CRS
PROTOCOL-ENFORCEMENT rule, a concern CSF's S0 framing layer already owns. This
measures S1 scored on attack rules only (the sidecar's attack_score) against
the full anomaly score, on both corpora, and the resulting cascade.

The fix is justified by the S0/S1 responsibility split and VALIDATED to
preserve CSIC; the ECML numbers are a check, not a tuning target.
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
from csf.s1_rules import S1Config  # noqa: E402
from csf.semantic.detector import S2Config, analyze_extraction  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
ECML = (ROOT / "data/raw/waad/OriginalDataSets/ecml_pkdd/"
        "dataset_ecml_pkdd_train_test/xml_test.txt")
CLAIMED = {"sqli", "xss", "cmdi", "traversal"}
SOCKET = "/tmp/csf-s1.sock"


def to_ex(r: Request):
    h = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
         for k, vs in r.headers.items() for v in vs]
    return extract(r.method, r.path, r.query.encode("latin-1", "replace"), h,
                   r.body.encode("latin-1", "replace"))


def score(rows: list[Request], client: httpx.Client) -> list[dict]:
    out = []
    for r in rows:
        lab = str(r.label)
        if lab != "benign" and lab not in CLAIMED:
            continue
        res = client.post("/eval", json={
            "id": "x", "method": r.method, "path": r.path, "query": r.query,
            "headers": r.headers, "body": r.body}).json()
        s2 = analyze_extraction(to_ex(r), S2Config()).score
        out.append({"label": lab, "anomaly": res["anomaly_score"],
                    "attack": res.get("attack_score", res["anomaly_score"]),
                    "s2": s2})
    return out


def rates(rows: list[dict], fire) -> tuple[float, float]:
    cl = [r for r in rows if r["label"] in CLAIMED]
    bn = [r for r in rows if r["label"] == "benign"]
    return (sum(1 for r in cl if fire(r)) / len(cl) * 100,
            sum(1 for r in bn if fire(r)) / len(bn) * 100)


def main() -> int:
    client = httpx.Client(transport=httpx.HTTPTransport(uds=SOCKET),
                          base_url="http://s1", timeout=60.0)
    csic = [Request.from_dict(json.loads(line))
            for line in (ROOT / "data/processed/val.jsonl").read_text().splitlines()
            if line]
    ecml, _ = deduplicate(load_ecml_pkdd(ECML, per_class_limit=700,
                                         protocol_normalize=True))
    print("=== scoring ===")
    data = {"CSIC": score(csic, client), "ECML": score(ecml, client)}
    client.close()

    t1 = S1Config().tau_high      # 11
    t2 = S2Config().tau_block     # 4
    rows = []
    print(f"\n  S1 operating point tau_high={t1}, S2 tau_block={t2}\n")
    print(f"  {'variant':<34} {'CSIC rec':>9} {'CSIC FPR':>9} "
          f"{'ECML rec':>9} {'ECML FPR':>9}")
    print("  " + "-" * 74)
    variants = [
        ("S1 full anomaly alone", lambda r: r["anomaly"] >= t1),
        ("S1 attack-only alone", lambda r: r["attack"] >= t1),
        ("cascade: full anomaly OR S2", lambda r: r["anomaly"] >= t1 or r["s2"] >= t2),
        ("cascade: attack-only OR S2", lambda r: r["attack"] >= t1 or r["s2"] >= t2),
    ]
    for name, fire in variants:
        c = rates(data["CSIC"], fire)
        e = rates(data["ECML"], fire)
        print(f"  {name:<34} {c[0]:>8.1f}% {c[1]:>8.2f}% {e[0]:>8.1f}% {e[1]:>8.2f}%")
        rows.append({"variant": name, "csic_recall": round(c[0], 2),
                     "csic_fpr": round(c[1], 2), "ecml_recall": round(e[0], 2),
                     "ecml_fpr": round(e[1], 2)})

    out = ROOT / "docs" / "benchmarks" / "cross-corpus-attack-score.json"
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "s1_tau_high": t1, "s2_tau_block": t2,
        "protocol": "tune on CSIC, evaluate on ECML; attack-only vs full anomaly",
        "variants": rows,
    }, indent=2, sort_keys=True))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
