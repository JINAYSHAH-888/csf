#!/usr/bin/env python3
"""Cache per-request S1/S2 scores so decision policies can be compared offline.

Scoring both corpora costs ~50s and needs the sidecar running. Policy search
needs to sweep hundreds of threshold combinations. Separating the two means a
policy comparison is a second of arithmetic over a fixed set of scores rather
than a re-run, and -- more importantly -- every policy is compared on
IDENTICAL inputs, so a difference between policies cannot be a difference in
the traffic they saw.
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
CACHE = ROOT / "data/processed/decision-scores.json"
SOCKET = "/tmp/csf-s1.sock"


def to_ex(r: Request):
    h = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
         for k, vs in r.headers.items() for v in vs]
    return extract(r.method, r.path, r.query.encode("latin-1", "replace"), h,
                   r.body.encode("latin-1", "replace"))


def score_all(rows: list[Request], label: str) -> list[dict]:
    client = httpx.Client(transport=httpx.HTTPTransport(uds=SOCKET),
                          base_url="http://s1", timeout=60.0)
    cfg = S2Config()
    out: list[dict] = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        s1 = client.post("/eval", json={
            "id": str(i), "method": r.method, "path": r.path,
            "query": r.query, "headers": r.headers,
            "body": r.body}).json()
        signal = analyze_extraction(to_ex(r), cfg)
        out.append({
            "label": str(r.label),
            "s1": s1["anomaly_score"],
            # Kept distinct on purpose: conflating these was a measured bug in
            # Phase 3. The blocking score is what CRS would act on; the
            # anomaly score includes detection-only paranoia levels.
            "s1_blocking": s1.get("blocking_score", 0),
            "s2": signal.score,
            "s2_classes": signal.classes,
        })
        if (i + 1) % 1000 == 0:
            print(f"    {label}: {i+1}/{len(rows)}…")
    print(f"    {label}: {len(rows)} in {time.perf_counter()-t0:.1f}s")
    client.close()
    return out


def load_or_build(rebuild: bool = False) -> dict[str, list[dict]]:
    if CACHE.exists() and not rebuild:
        data = json.loads(CACHE.read_text())
        print(f"loaded cached scores from {CACHE.name} "
              f"(built {data['built_at']})")
        return data["corpora"]

    print("=== scoring (sidecar must be running) ===")
    csic = [Request.from_dict(json.loads(line))
            for line in (ROOT / "data/processed/val.jsonl").read_text().splitlines()
            if line]
    ecml, _ = deduplicate(load_ecml_pkdd(ECML, per_class_limit=700,
                                         protocol_normalize=True))
    corpora = {"CSIC": score_all(csic, "CSIC"), "ECML": score_all(ecml, "ECML")}
    CACHE.write_text(json.dumps({
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note": "S1 anomaly+blocking and S2 scores per request. Inputs for "
                "offline decision-policy comparison; not a benchmark result.",
        "corpora": corpora,
    }))
    print(f"wrote {CACHE}")
    return corpora


if __name__ == "__main__":
    load_or_build(rebuild="--rebuild" in sys.argv)
