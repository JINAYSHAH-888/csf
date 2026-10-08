#!/usr/bin/env python3
"""Build the CSF evaluation corpus: load, dedupe, split, freeze.

Phase 4 exit gate. Produces a frozen test set whose hash is recorded, so
"nothing trained on it" is checkable rather than asserted.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from csf.data.corpus import (  # noqa: E402
    AttackClass,
    deduplicate,
    freeze,
    split_by_group,
    split_warnings,
    verify_no_leakage,
)
from csf.data.loaders import (  # noqa: E402
    benign_request_shapes,
    load_csic,
    load_payload_list,
)

RAW = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
OUT = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

#: Payload lists, mapped to the class they represent.
PAYLOAD_SOURCES = [
    ("foospidy/other/sqli/libinjection-bypasses.txt", AttackClass.SQLI, "libinjection-bypass"),
    ("foospidy/other/sqli/sqlifuzzer.txt", AttackClass.SQLI, "sqlifuzzer"),
    ("foospidy/owasp/jbrofuzz/sqli.txt", AttackClass.SQLI, "jbrofuzz-sqli"),
    ("foospidy/other/xss/ismailtasdelen.txt", AttackClass.XSS, "xss-ismailtasdelen"),
    ("foospidy/other/xss/xssdb.txt", AttackClass.XSS, "xssdb"),
    ("foospidy/other/xss/packetstorm.txt", AttackClass.XSS, "xss-packetstorm"),
    ("foospidy/owasp/jbrofuzz/xss.txt", AttackClass.XSS, "jbrofuzz-xss"),
    ("foospidy/other/commandinjection/ismailtasdelen-windows.txt", AttackClass.CMDI, "cmdi-windows"),
    ("foospidy/other/traversal/traversal.txt", AttackClass.TRAVERSAL, "traversal"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csic-limit", type=int, default=20000)
    parser.add_argument("--payload-limit", type=int, default=800)
    parser.add_argument("--seed", type=int, default=20261001)
    args = parser.parse_args()

    requests = []
    shapes = []

    print("=== loading ===")
    csic_dir = RAW / "csic"
    if (csic_dir / "normalTrafficTraining.txt").exists():
        benign = load_csic(csic_dir / "normalTrafficTraining.txt",
                           AttackClass.BENIGN, limit=args.csic_limit)
        anomalous = load_csic(csic_dir / "anomalousTrafficTest.txt",
                              AttackClass.OTHER, limit=args.csic_limit // 2)
        requests += benign + anomalous
        # Payload-list attacks are embedded in shapes drawn from THIS benign
        # traffic, so the endpoint cannot leak the label.
        shapes = benign_request_shapes(benign)
        print(f"  csic2010         benign={len(benign)} anomalous={len(anomalous)}")
        print(f"  request shapes   {len(shapes)} sampled from benign traffic")
    else:
        print("  csic2010         MISSING")

    for rel, label, source in PAYLOAD_SOURCES:
        path = RAW / rel
        if not path.exists():
            print(f"  {source:<16} MISSING ({rel})")
            continue
        rows = load_payload_list(path, label, source, limit=args.payload_limit,
                                 shapes=shapes)
        requests += rows
        print(f"  {source:<16} {label}={len(rows)}")

    if not requests:
        print("fatal: no corpora found", file=sys.stderr)
        return 1

    print(f"\n=== deduplicating ({len(requests)} in) ===")
    kept, stats = deduplicate(requests)
    print(stats.render())

    warnings = split_warnings(kept)
    if warnings:
        print("\n=== corpus warnings ===")
        for w in warnings:
            print(f"  WARN: {w}")

    print("\n=== splitting by template group (NOT by row) ===")
    split = split_by_group(kept, seed=args.seed)
    print(split.summary())

    print("\n=== leakage check ===")
    problems = verify_no_leakage(split)
    if problems:
        for p in problems:
            print(f"  FAIL: {p}")
        return 1
    print("  clean: no shared requests and no shared template groups "
          "across train/val/test")

    print("\n=== freezing ===")
    OUT.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name, rows in (("train", split.train), ("val", split.val),
                       ("test", split.test)):
        digest = freeze(rows, OUT / f"{name}.jsonl")
        hashes[name] = digest
        print(f"  {name:<6} n={len(rows):<7} sha256={digest[:16]}…")

    manifest = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "seed": args.seed,
        "splitting": "by template group (endpoint + param names + value types), "
                     "never by row",
        "stats": {
            "input": stats.total_in, "exact_duplicates": stats.exact_duplicates,
            "label_conflicts": stats.label_conflicts, "kept": stats.kept,
            "groups": stats.groups, "by_label": stats.by_label,
            "by_source": stats.by_source,
        },
        "splits": {name: {"n": len(rows), "sha256": hashes[name]}
                   for name, rows in (("train", split.train), ("val", split.val),
                                      ("test", split.test))},
        "frozen_test_warning":
            "test.jsonl is the frozen holdout. Training or threshold "
            "derivation on it invalidates every number in the evaluation. "
            "Its sha256 is recorded here so that can be checked.",
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nwrote {OUT}/manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
