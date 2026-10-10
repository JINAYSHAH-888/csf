# CSF Security Console: demo guide

A web console for the CSF cascaded semantic firewall (`backend/`). Traffic goes through the real
gateway to a deliberately vulnerable sample shop; the console shows every decision.

## Run

Prerequisites: Docker Desktop, Node 20+, and `vendor/crs` (OWASP CRS v4.21.0, gitignored).

```
git clone --depth 1 --branch v4.21.0 https://github.com/coreruleset/coreruleset vendor/crs
run-demo.bat
```

Open http://localhost:5173. The gateway listens on https://localhost:8080 (self-signed), the console
API on http://localhost:8000. Without Docker, `console-api/server.py` runs natively but without S1.

## Project proposal vs implementation

| Proposal component | Implementation | Where to see it |
|---|---|---|
| Reverse proxy, TLS termination, header parsing | Gateway serves HTTPS (TLS 1.3) and applies strict HTTP framing checks | Dashboard: Transport node, hero banner |
| JWT / RSA / ECDSA verification | RS256 and ES256, RFC 8725 checks, JWKS-capable | Token verification (12 tokens) |
| Deterministic rule engine (ModSecurity / OWASP CRS) | Coraza with CRS v4.21 in a Go sidecar (S1) | Threat simulator: S1 trace with CRS rule IDs |
| Tokeniser and feature encoder | Normalisation, decoded candidates, model feature builder | Threat simulator: Inspected values |
| Grammar-aware detection of obfuscated payloads | SQL / HTML / shell / path parsers (S2) | Threat simulator: S2 trace; Detection performance |
| Learned classifier | Character n-gram model (S3), **off by default** | Pipeline shows it as optional |
| Decision and policy engine | Disjunctive fusion, deferral, block-rate budget, rate limit, circuit breaker | Dashboard: Decision node, Gateway health |
| Logging and alerting | JSON audit log, Live traffic log, alert rules, Prometheus `/metrics` | Live traffic, Dashboard: Alerts |
| Retraining from logs | Labelled feedback dataset export (JSONL, model input format) | Live traffic: Export feedback dataset |

## Known limitations (stated openly)

- The learned stage is a scikit-learn n-gram classifier, not BERT/DistilBERT. The team's own
  measurements show it does not generalise across applications (ADR-0017), so it stays off.
- Retraining is not automated: the console exports a labelled dataset; labels come from the gateway's
  own decisions and need review.
- TLS uses a generated self-signed certificate.
- An ES256 token whose `kid` points at an RSA key triggers an unhandled error in
  `backend/csf/jwtverify.py` (HTTP 500, no audit entry; the request is still not forwarded). Not part of
  the demo token set.
- Not independently security-audited. See `docs/security/threat-model.md` for non-goals.
