#!/usr/bin/env python3
"""Phase 8: adversarial evaluation (A3 black-box mutation).

Measures the evasion rate against the two targets the threat model commits to
(T1): <=15% for mutation-based evasion. The number is the deliverable; this
does not tune anything to hit it, and an honest miss is reported as a miss.

What "evasion" means here, precisely
------------------------------------
Start from seed payloads that CSF's analysers block. Mutate each into many
semantics-preserving variants (the mutation oracle in csf.adversarial discards
any that stop being an attack). A variant EVADES if the analyser that blocked
the seed no longer blocks the variant. Evasion rate = evading variants / total
surviving variants.

Two measurement planes, both against our own code:
  * S2 in-process  -- the primary number, large sample, no network.
  * full gateway    -- a smaller sample sent over loopback to the containerised
                       gateway, to confirm the in-process result holds through
                       decode + S1 + S2 + the decision engine. Opt-in via
                       --gateway URL, because it needs the stack up.

Scope: seeds and mutations are sent only to 127.0.0.1. The script refuses any
non-loopback target.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import socket
import sys
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.disable(logging.ERROR)

from csf.adversarial import SQL_OPERATORS, Mutator, sqlite_attack_survives  # noqa: E402
from csf.semantic.detector import S2Config, analyze_candidate  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent

# Seeds that S2 blocks at the shipped tau_block. Drawn from the regression
# suite so the adversary starts from known-detected attacks, not from strings
# that were never caught in the first place.
SQL_SEEDS = [
    "1' OR '1'='1", "x' UNION SELECT NULL,NULL-- ", "x'; DROP TABLE users-- ",
    "admin'--", "') OR ('a'='a", "1' UNION ALL SELECT @@version-- ",
    "x' UNION SELECT LOAD_FILE('/etc/passwd')-- ", "1' OR 'ns' BETWEEN 'a' AND 'z'-- ",
]

TAU = S2Config().tau_block


def _blocks_s2(payload: str) -> bool:
    """Does S2 block this value in a query position? Uses the real analyser."""
    score, _cls, _why = analyze_candidate(payload, S2Config(), location="query")
    return score >= TAU


def _require_loopback(url: str) -> None:
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (OSError, ValueError):
        sys.exit(f"refusing non-resolvable gateway host: {host!r}")
    if not ip.is_loopback:
        sys.exit(f"refusing non-loopback gateway target {host!r} ({ip}); "
                 "the adversarial harness attacks our own gateway only")


def measure_s2(depth: int, per_depth: int, seed: int) -> dict:
    """In-process evasion rate against S2."""
    mutator = Mutator(SQL_OPERATORS, sqlite_attack_survives, seed=seed)
    total = evaded = 0
    confirmed_seeds = 0
    evasions: list[dict] = []
    for s in SQL_SEEDS:
        if not _blocks_s2(s):
            print(f"  skip seed (S2 did not block it): {s!r}")
            continue
        confirmed_seeds += 1
        for mut in mutator.variants(s, depth=depth, per_depth=per_depth):
            total += 1
            if not _blocks_s2(mut.payload):
                evaded += 1
                evasions.append({"seed": s, "payload": mut.payload,
                                 "operators": list(mut.operators)})
    rate = evaded / total * 100 if total else 0.0
    return {"plane": "s2_in_process", "seeds_confirmed": confirmed_seeds,
            "surviving_variants": total, "evasions": evaded,
            "evasion_rate_pct": round(rate, 2), "examples": evasions[:25],
            "all_evasions": evasions}


def measure_s1(socket_path: str, depth: int, per_depth: int, seed: int) -> dict:
    """In-process evasion rate against S1 (CRS regex) via the sidecar socket.

    Scored at the CRS blocking score, the value CRS itself would act on. This
    plane exists to test the cascade hypothesis directly: the obfuscation
    operators here are the ones grammar analysis absorbs, so if the cascade's
    premise holds they should evade the regex layer far more than they evade
    S2. A low S1 evasion rate would actually be the surprising result.
    """
    import httpx

    client = httpx.Client(transport=httpx.HTTPTransport(uds=socket_path),
                          base_url="http://s1", timeout=10.0)
    # S1 blocks at the CRS inbound threshold (sidecar default 5). We read the
    # blocking score, not the detection/anomaly score -- conflating them was a
    # measured bug in Phase 3.
    s1_block_threshold = 5

    def blocks(payload: str) -> bool:
        r = client.post("/eval", json={"id": "x", "method": "GET",
                                       "path": "/shop", "query": f"q={payload}",
                                       "headers": {}, "body": ""}).json()
        return r.get("blocking_score", 0) >= s1_block_threshold

    mutator = Mutator(SQL_OPERATORS, sqlite_attack_survives, seed=seed)
    total = evaded = confirmed = 0
    evasions: list[dict] = []
    for sd in SQL_SEEDS:
        if not blocks(sd):
            continue
        confirmed += 1
        for mut in mutator.variants(sd, depth=depth, per_depth=per_depth):
            total += 1
            if not blocks(mut.payload):
                evaded += 1
                evasions.append({"seed": sd, "payload": mut.payload,
                                 "operators": list(mut.operators)})
    client.close()
    rate = evaded / total * 100 if total else 0.0
    return {"plane": "s1_regex", "seeds_confirmed": confirmed,
            "surviving_variants": total, "evasions": evaded,
            "evasion_rate_pct": round(rate, 2), "examples": evasions[:25],
            "all_evasions": evasions}


def measure_gateway(url: str, depth: int, per_depth: int, seed: int) -> dict:
    """End-to-end evasion rate against the live gateway on loopback."""
    import httpx

    _require_loopback(url)
    client = httpx.Client(base_url=url, timeout=10.0)

    def blocks(payload: str) -> bool:
        # Shadow mode returns 200 but records would-block; enforce returns 403.
        # We read the decision from the response, falling back to status.
        q = urllib.parse.urlencode({"q": payload})
        r = client.get(f"/shop?{q}")
        return r.status_code == 403 or r.headers.get("x-csf-would-block") == "1"

    mutator = Mutator(SQL_OPERATORS, sqlite_attack_survives, seed=seed)
    total = evaded = confirmed = 0
    evasions: list[dict] = []
    for s in SQL_SEEDS:
        if not blocks(s):
            continue
        confirmed += 1
        for mut in mutator.variants(s, depth=depth, per_depth=per_depth):
            total += 1
            if not blocks(mut.payload):
                evaded += 1
                evasions.append({"seed": s, "payload": mut.payload,
                                 "operators": list(mut.operators)})
    client.close()
    rate = evaded / total * 100 if total else 0.0
    return {"plane": "full_gateway", "target": url, "seeds_confirmed": confirmed,
            "surviving_variants": total, "evasions": evaded,
            "evasion_rate_pct": round(rate, 2), "examples": evasions[:25],
            "all_evasions": evasions}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--per-depth", type=int, default=6)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--gateway", help="loopback gateway URL for the end-to-end plane")
    ap.add_argument("--s1-socket", help="sidecar socket for the S1 regex plane")
    args = ap.parse_args()

    print("=== Phase 8: adversarial evasion (A3 mutation) ===")
    print(f"  operators: {list(SQL_OPERATORS)}")
    print(f"  depth={args.depth} per_depth={args.per_depth} seed={args.seed}")
    print(f"  S2 tau_block={TAU}\n")

    results = [measure_s2(args.depth, args.per_depth, args.seed)]
    if args.s1_socket:
        print(f"\n  also measuring against S1 regex via {args.s1_socket} …")
        results.append(measure_s1(args.s1_socket, args.depth,
                                  args.per_depth, args.seed))
    if args.gateway:
        print(f"\n  also measuring against gateway {args.gateway} …")
        results.append(measure_gateway(args.gateway, args.depth,
                                       args.per_depth, args.seed))

    print(f"\n  {'plane':<16} {'seeds':>6} {'variants':>9} {'evasions':>9} "
          f"{'rate':>7}  {'gate <=15%':>11}")
    print("  " + "-" * 64)
    for r in results:
        verdict = "PASS" if r["evasion_rate_pct"] <= 15.0 else "FAIL"
        print(f"  {r['plane']:<16} {r['seeds_confirmed']:>6} "
              f"{r['surviving_variants']:>9} {r['evasions']:>9} "
              f"{r['evasion_rate_pct']:>6.1f}% {verdict:>11}")

    # Operator breakdown for the in-process plane: which transforms evade.
    s2 = results[0]
    by_op: dict[str, int] = defaultdict(int)
    for e in s2["all_evasions"]:
        for op in e["operators"]:
            by_op[op] += 1
    if by_op:
        print("\n  operators appearing in S2 evasions:")
        for op, n in sorted(by_op.items(), key=lambda kv: -kv[1]):
            print(f"    {op:<20} {n}")

    out = ROOT / "docs" / "benchmarks" / "adversarial.json"
    payload = {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
               "config": {"depth": args.depth, "per_depth": args.per_depth,
                          "seed": args.seed, "tau_block": TAU},
               "planes": [{k: v for k, v in r.items() if k != "all_evasions"}
                          for r in results]}
    out.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"\nwrote {out}")

    # Persist the full evasion set for regression-test generation.
    corpus = ROOT / "data" / "processed" / "adversarial-evasions.json"
    corpus.write_text(json.dumps(
        {"evasions": results[0]["all_evasions"]}, indent=2))
    print(f"wrote {corpus} ({len(results[0]['all_evasions'])} evasions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
