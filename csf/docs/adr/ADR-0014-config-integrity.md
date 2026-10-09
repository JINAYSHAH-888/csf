# ADR-0014 — Config integrity: fingerprint, optional signature, safe-fail

**Status:** Accepted (Phase 13) · **Date:** 2026-10-08 · **Threat:** T7

## Context

CSF's config decides the enforcement mode, the thresholds, the upstream, and
the auth issuers. An attacker who can rewrite it on disk turns enforcement off
or points auth at their own JWKS without touching code. T7 asks for signed and
validated config, an audit trail with actor and diff, and safe-fail on
corruption. Loading config had been a plain `json.loads` + validate.

## Decision

A thin integrity layer (`csf/config_integrity.py`) wraps config loading:

1. **Fingerprint every load.** The SHA-256 of the exact bytes read is recorded
   and logged at startup. A changed hash across restarts is the "diff" T7 asks
   for, at the granularity that matters: did the policy change at all, and when.
2. **Signature when a key is configured.** With `CSF_CONFIG_HMAC_KEY` set, the
   config must carry a matching HMAC-SHA256 signature (`<config>.sig`) or
   startup fails. Opt-in, because a local dev has no key and should not be
   forced to sign — but the moment a key exists, a valid signature is
   mandatory. A signature the system will run without is theatre. The compare
   is constant-time.
3. **Safe-fail.** Unreadable file, bad JSON, failed validation, or a bad
   signature all raise `ConfigIntegrityError` and startup stops. A gateway that
   falls back to defaults on a corrupt config is one an attacker disables by
   corrupting the config.

The actor (config-file owner) and byte size round out the audit record.

## Consequences

- `main.py` loads via `load_trusted()` → `_from_raw()`, and logs the audit
  record (`config_sha256`, `config_signed`, `config_actor`) at startup.
- `sign()` lives in the same module as the verifier so the two cannot drift;
  it is operator tooling, not used at runtime.
- 10 tests, including the one that matters: a body tampered after signing fails
  to load.

## Known limitations

- **HMAC, not asymmetric signatures.** Anyone who can verify can also sign — the
  key is shared. That defends against on-disk tampering by a party without the
  key, not against an attacker who already holds it. Asymmetric (sign offline
  with a private key, verify with a public one) is the stronger design and is
  not built.
- **No rollback automation.** T7 mentions a rollback path; the fingerprint log
  makes "what changed" answerable, but reverting is still a manual
  redeploy of a previous config.
- **Diff granularity is the whole file.** The audit says the policy changed, not
  which field; a field-level diff would need the previous content, which the
  gateway does not retain.
- The HMAC key itself comes from an env var; its own protection (a secrets
  manager) is out of scope for this component.
