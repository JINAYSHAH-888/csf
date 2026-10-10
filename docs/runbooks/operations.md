# CSF operations runbook

Concrete procedures for running CSF in production. Every step references a
control that actually exists in this codebase; nothing here is aspirational.

## Signals to watch (from `/metrics`)

| metric | meaning | alert when |
|---|---|---|
| `csf_request_duration_seconds` | adjudication latency histogram | p99 > 0.010 (the budget) sustained |
| `csf_requests_total{decision}` | traffic by outcome | `block` rate deviates sharply from baseline |
| `csf_block_rate_ratio` | observed block rate over the decision window | > your configured budget |
| `csf_block_rate_over_budget` | 1 if block rate exceeds budget | == 1 |
| `csf_circuit_breaker_tripped` | 1 if degraded (learned stage skipped) | == 1 |
| `csf_stage_blocks_total{stage}` | enforced blocks by stage | a single stage dominating unexpectedly |
| `csf_up` | gateway serving | == 0 |

`/statusz` gives the same state as JSON for humans; `/readyz` is the
load-balancer readiness gate; `/healthz` is liveness only.

## 1. Turning on enforcement (shadow → enforce)

**Never enforce on day one.** CSF ships in shadow mode: it evaluates fully and
logs what it *would* do (`shadow_would_block`, `csf_requests_total`) but forwards
everything.

1. Run in shadow for a representative period (at least a full traffic cycle).
2. Capture that traffic (the requests CSF saw) to a JSONL.
3. Calibrate the operating point to **this application's** traffic:
   ```bash
   python backend/scripts/calibrate.py shadow-traffic.jsonl --budget-pct 0.5
   ```
   It recommends the `s1.tau_high` / `s2.tau_block` that keep the block rate
   (≈ false-positive rate on near-all-benign traffic) within budget, and prints
   a config snippet. **There is no safe default to skip this** (ADR-0011/0017):
   a threshold good on one application can block the majority of another's
   traffic.
4. Apply the snippet, keep `mode: shadow`, and confirm `csf_block_rate_ratio`
   sits within budget and `/readyz` is 200.
5. Flip `mode: enforce`. Watch `csf_requests_total{decision="block"}` and the
   upstream's own error rate for the first minutes.

## 2. Block rate over budget / `/readyz` returning 503

Symptom: `csf_block_rate_over_budget == 1`, or `/readyz` lists a block-rate
blocker.

- **This is a guard, not an auto-action** — CSF reports it and (via `/readyz`)
  pulls the pod from rotation on enablement, but it never silently stops
  blocking. An attacker who raises the block rate by sending attacks must not be
  able to switch the firewall off (ADR-0011).
- Decide which it is: a real attack campaign (check `csf_stage_blocks_total`,
  the audit log's reasons) or a misconfiguration (thresholds too low for this
  app). If misconfiguration, re-run calibration (§1) and roll the config.
- If it is an attack, the high block rate is CSF working; do not loosen.

## 3. Circuit breaker tripped (`csf_circuit_breaker_tripped == 1`)

Means a detector stage was unavailable for a sustained fraction of requests and
CSF degraded to S1+S2 (it skips the learned stage). Detection by S1/S2 is
unchanged — only cost was shed.

- Find the failing stage in the logs (`detector error`, `s3_unavailable`).
- The breaker self-recovers after its cooldown once the stage is healthy; it
  will not flap.
- S3 is off by default, so in a default deployment a trip means S1/S2
  availability — check the sidecar (§4).

## 4. S1 sidecar unreachable

Symptom: logs show `s1 sidecar unavailable`; S1 contributes nothing.

- Default `s1.fail_open=true`: the cascade continues on S2 and the request is
  served. Attacks only S1 would have caught can reach the backend while it is
  down — this is a deliberate availability-over-strictness choice (T5).
- For high-risk routes an operator may set `fail_open=false`, which turns a
  sidecar outage into a 503 for those requests. Know which you chose.
- In k8s the sidecar is in the same pod; a crashed sidecar means the pod's
  shared socket is gone — check the `s1` container, not the network.

## 5. 401 spike on protected routes

Usually a JWKS/key-rotation issue, not an attack.

- CSF refreshes keys on an unknown `kid`, rate-limited so an unknown-kid flood
  cannot amplify into outbound requests (an amplification guard, by design).
- If the issuer rotated keys and CSF has not picked them up, check the JWKS URL
  is reachable and `/readyz` — a missing verification key makes `/readyz` fail
  closed so the pod leaves rotation rather than 401-ing every request.
- CSF never logs raw JWTs (token hash only); do not add logging that would.

## 6. Rotating the (signed) config

If `CSF_CONFIG_PUBKEY` is set, the gateway refuses to start on an unsigned or
tampered config (ADR-0014/0017).

1. Edit the config where the private key lives (never on the gateway host).
2. Re-sign: `python -c "from csf.config_integrity import sign_ed25519; \
   sign_ed25519('gateway.json', open('csf-config.key','rb').read())"`
3. Roll config + `.sig` together. The startup log records the new
   `config_sha256` — that hash change is the audit trail of what changed.

## 7. Rollback

- Config: redeploy the previous config + `.sig`; the `config_sha256` in the logs
  tells you which version is live.
- Thresholds too aggressive after an enforce cutover: set `mode: shadow`
  immediately (stops all blocking while you recalibrate), or revert to the
  previous ConfigMap.
- Image: the images are tagged; redeploy the prior tag. (Base images are not
  yet digest-pinned — ADR-0010 — so pin before you rely on tag rollback.)
