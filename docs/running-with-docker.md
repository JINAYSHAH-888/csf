# Running CSF with Docker

Two containers: the gateway and the S1 sidecar, talking over a unix socket on
a shared volume. Nothing publishes S1. See ADR-0010 for why it is built this
way, and for the limitations.

## Bring it up

```bash
docker compose up -d --build
```

```bash
docker compose ps
```

The gateway listens on `127.0.0.1:8080` and proxies to the `upstream` named in
`configs/gateway.docker.json` — by default `http://host.docker.internal:3000`,
i.e. a service on the host. It starts in **shadow mode**: decisions are logged
with `"enforced": false` and nothing is actually blocked. Change `mode` to
`enforce` in that config when you want it to act.

## Watch what it decides

```bash
docker compose logs -f gateway | grep '"msg": "decision"'
```

Each line carries the decision, the stage that made it, the score, and the
reason — for S1 the CRS rule IDs, for S2 the named structural findings.

## Configuration

| file | role |
|---|---|
| `configs/gateway.docker.json` | gateway config, mounted read-only |
| `configs/crs/exclusions-csic.conf` | per-application CRS exclusions, mounted read-only |
| `vendor/crs` | the rule set — **baked into the image**, not mounted |

The split is deliberate: rules are part of the detector and ship with the image
so the image's tag identifies its rules; exclusions are per-application
deployment config. Do not move the rule set to a mount to make editing easier.

S3 is disabled by default — Phase 6 recorded it as a negative result. Its
dependencies are an optional extra (`pip install '.[s3]'`), because scikit-learn
is needed to deserialise the artifact even though no module imports it by name.

## Verifying a change

The sidecar image must score identically to whatever you were benchmarking
against before. Equivalence was established across 400 real corpus requests
(ADR-0010); if you change the Dockerfile, the rule set, or the exclusions, that
comparison is what tells you whether you changed the detector.

A mismatch is not automatically a bug — the first run of that check showed
400/400 mismatches because the host sidecar had exclusions loaded and the
container did not. Check the configuration before suspecting the image.

## Teardown

```bash
docker compose down -v
```

`-v` removes the socket volume. Leaving it behind is harmless; the socket is
recreated on the next start.

## Signing the config (production)

The gateway can require its config to be signed, so a tampered config fails to
load rather than silently taking effect (ADR-0014/0017). Preferred scheme is
Ed25519 (asymmetric): sign offline with a private key the server never holds.

```bash
# one-time: generate a keypair (private key stays OFF the server)
python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; \
from cryptography.hazmat.primitives import serialization as s; k=Ed25519PrivateKey.generate(); \
open('csf-config.key','wb').write(k.private_bytes(s.Encoding.PEM,s.PrivateFormat.PKCS8,s.NoEncryption())); \
open('csf-config.pub','wb').write(k.public_key().public_bytes(s.Encoding.PEM,s.PublicFormat.SubjectPublicKeyInfo))"
```

```bash
# sign the config (run wherever the private key lives, not on the gateway)
python -c "from csf.config_integrity import sign_ed25519; sign_ed25519('configs/gateway.docker.json', open('csf-config.key','rb').read())"
```

Mount the public key and point `CSF_CONFIG_PUBKEY` at it; the gateway then
refuses to start unless `configs/gateway.docker.json.sig` verifies.
