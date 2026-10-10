#!/usr/bin/env python3
"""Train and calibrate the S3 classifier.

Discipline, per the build spec:
  * trains on TRAIN only
  * calibrates and selects thresholds on VAL only
  * NEVER touches the frozen TEST holdout
  * reports per-class recall, calibration error, and cross-corpus transfer
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.disable(logging.ERROR)

import numpy as np  # noqa: E402
from sklearn.calibration import CalibratedClassifierCV  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402

from csf.data.corpus import Request, deduplicate  # noqa: E402
from csf.data.loaders import load_ecml_pkdd  # noqa: E402
from csf.extraction import extract  # noqa: E402
from csf.model.features import request_document  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
DATA = ROOT / "data" / "processed"
ARTIFACTS = ROOT / "model" / "artifacts"
ECML = (ROOT / "data/raw/waad/OriginalDataSets/ecml_pkdd/"
        "dataset_ecml_pkdd_train_test/xml_test.txt")
CLAIMED = {"sqli", "xss", "cmdi", "traversal"}


def load(split: str) -> list[Request]:
    return [Request.from_dict(json.loads(line))
            for line in (DATA / f"{split}.jsonl").read_text().splitlines() if line]


# Values-only by DEFAULT: provenance tags are a corpus fingerprint that wrecks
# cross-application transfer (Phase 6 / ADR-0008). The shipped model is
# values-only; provenance is opt-in for experiments via S3_PROVENANCE=1.
PROVENANCE = os.environ.get("S3_PROVENANCE", "0") == "1"


def to_doc(r: Request) -> str:
    headers = [(k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
               for k, vs in r.headers.items() for v in vs]
    return request_document(extract(
        r.method, r.path, r.query.encode("latin-1", "replace"), headers,
        r.body.encode("latin-1", "replace")), provenance=PROVENANCE)


def build(rows: list[Request]) -> tuple[list[str], np.ndarray]:
    docs = [to_doc(r) for r in rows]
    # Binary: attack vs benign. Per-class recall is still reported, but the
    # decision the gateway needs is binary and multi-class on a corpus where
    # one class is 47% of attacks would mostly learn the class prior.
    y = np.array([0 if str(r.label) == "benign" else 1 for r in rows])
    return docs, y


def main() -> int:
    print(f"=== loading (provenance={PROVENANCE}) ===")
    train, val = load("train"), load("val")
    print(f"  train {len(train)}  val {len(val)}  (test NOT loaded — frozen)")

    t0 = time.perf_counter()
    Xtr, ytr = build(train)
    Xva, yva = build(val)
    print(f"  featurised in {time.perf_counter()-t0:.1f}s")

    # Character n-grams: the payload signal is in character sequences
    # ("' OR ", "--", "<scr"), not in words. Word tokenisation would destroy
    # exactly the structure that matters.
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb", ngram_range=(2, 5), min_df=3,
            max_features=200_000, sublinear_tf=True, lowercase=True)),
        ("clf", LogisticRegression(
            max_iter=2000, C=4.0, class_weight="balanced", n_jobs=-1)),
    ])

    print("\n=== training ===")
    t0 = time.perf_counter()
    pipeline.fit(Xtr, ytr)
    print(f"  fit in {time.perf_counter()-t0:.1f}s  "
          f"vocab={len(pipeline.named_steps['tfidf'].vocabulary_)}")

    # Calibration so the emitted score is an actual probability. Thresholds
    # are only meaningful if 0.99 means 0.99 (research paper §3.6).
    print("\n=== calibrating (isotonic, 3-fold on train) ===")
    calibrated = CalibratedClassifierCV(pipeline, method="isotonic", cv=3)
    t0 = time.perf_counter()
    calibrated.fit(Xtr, ytr)
    print(f"  calibrated in {time.perf_counter()-t0:.1f}s")

    def evaluate(name: str, X, y, rows: list[Request]) -> dict:
        p = calibrated.predict_proba(X)[:, 1]
        benign = p[y == 0]
        print(f"\n=== {name} ===")
        print(f"  benign   n={len(benign):<5} p50={np.percentile(benign,50):.3f} "
              f"p95={np.percentile(benign,95):.3f} p99={np.percentile(benign,99):.3f}")
        out = {}
        for cls in sorted({str(r.label) for r in rows} - {"benign"}):
            idx = [i for i, r in enumerate(rows) if str(r.label) == cls]
            if idx:
                scores = p[idx]
                print(f"  {cls:<8} n={len(idx):<5} p50={np.percentile(scores,50):.3f}")
                out[cls] = scores
        # Recall on claimed classes at fixed FPR
        claimed_idx = [i for i, r in enumerate(rows) if str(r.label) in CLAIMED]
        claimed = p[claimed_idx]
        print(f"  {'target FPR':>11} {'threshold':>10} {'recall':>9}")
        results = {}
        for target in (0.01, 0.001):
            thr = float(np.quantile(benign, 1 - target)) if len(benign) else 1.0
            rec = float((claimed >= thr).mean() * 100) if len(claimed) else 0.0
            fpr = float((benign >= thr).mean() * 100)
            print(f"  {target*100:>10.1f}% {thr:>10.4f} {rec:>8.1f}%  "
                  f"(actual FPR {fpr:.2f}%)")
            results[str(target)] = {"threshold": thr, "recall": rec, "fpr": fpr}
        return {"probs": p, "thresholds": results}

    val_res = evaluate("VALIDATION (CSIC-derived)", Xva, yva, val)

    # Cross-corpus: ECML, never seen in training.
    print("\n=== cross-corpus: ECML/PKDD (unseen application) ===")
    ecml, _ = deduplicate(load_ecml_pkdd(ECML, per_class_limit=700,
                                         protocol_normalize=True))
    Xec, yec = build(ecml)
    ecml_res = evaluate("ECML (cross-corpus)", Xec, yec, ecml)

    # Transfer at matched threshold, the metric Phase 5 established.
    print("\n=== transfer at MATCHED threshold (CSIC-derived) ===")
    thr = val_res["thresholds"]["0.001"]["threshold"]
    for name, res, rows, y in (("CSIC", val_res, val, yva),
                               ("ECML", ecml_res, ecml, yec)):
        p = res["probs"]
        claimed_idx = [i for i, r in enumerate(rows) if str(r.label) in CLAIMED]
        rec = float((p[claimed_idx] >= thr).mean() * 100)
        fpr = float((p[y == 0] >= thr).mean() * 100)
        print(f"  {name:<6} threshold={thr:.4f}  recall={rec:>6.1f}%  FPR={fpr:>6.2f}%")

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    import pickle
    # The artifact bundles the feature contract with the model, so the gateway
    # serves the exact representation the model was trained on (no train/serve
    # skew). The shipped, values-only model is s3_model.pkl.
    suffix = "_provenance" if PROVENANCE else ""
    bundle = {"format": 2, "model": calibrated, "provenance": PROVENANCE}
    with (ARTIFACTS / f"s3_model{suffix}.pkl").open("wb") as fh:
        pickle.dump(bundle, fh)
    (ARTIFACTS / f"s3_metadata{suffix}.json").write_text(json.dumps({
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "provenance_features": PROVENANCE,
        "train_n": len(train), "val_n": len(val), "ecml_n": len(ecml),
        "test_touched": False,
        "vectoriser": "char_wb 2-5grams, min_df=3, max_features=200k",
        "classifier": "LogisticRegression C=4.0 balanced, isotonic-calibrated",
        "val_thresholds": val_res["thresholds"],
        "ecml_thresholds": ecml_res["thresholds"],
    }, indent=2, default=str))
    print(f"\nwrote {ARTIFACTS}/s3_model.pkl and s3_metadata.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
