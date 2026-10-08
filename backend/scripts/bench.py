import json
import time

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from csf.extraction import extract
from csf.framing import check_framing
from csf.jwtverify import Config, IssuerConfig, Verifier
from csf.normalization import normalize


def bench(name, fn, n=20000):
    fn()  # warm
    ts=[]
    for _ in range(min(n, 2000)):
        t0=time.perf_counter_ns(); fn(); ts.append(time.perf_counter_ns()-t0)
    ts.sort()
    p50=ts[len(ts)//2]/1000; p99=ts[int(len(ts)*0.99)]/1000
    print(f"  {name:<38} p50={p50:8.2f}us  p99={p99:8.2f}us")

print("\n=== CSF component benchmarks (Apple M5, Python 3.14.6) ===")

k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
v = Verifier(Config(issuers={"i": IssuerConfig("i","a",("RS256",),{"k1":k.public_key()})}))
priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
tok = pyjwt.encode({"iss":"i","aud":"a","sub":"u","exp":9999999999}, priv, algorithm="RS256", headers={"kid":"k1"})
bench("jwt verify RS256", lambda: v.verify(tok))

bench("normalize benign", lambda: normalize("Product Name (Large, Blue)"))
bench("normalize encoded attack", lambda: normalize("%2527%20UNION%20SELECT%20NULL%2C%20NULL--%20"))

H=[(b"host",b"h"),(b"user-agent",b"Mozilla/5.0"),(b"content-type",b"application/json")]
bench("check_framing", lambda: check_framing("GET","/api/x",H))

body=json.dumps({"user":{"name":"alice","email":"a@b.c","tags":["x","y","z"]},"page":1}).encode()
bench("extract json request", lambda: extract("POST","/api/users",b"ref=home",H,body))

def s0_full():
    check_framing("POST","/api/users",H)
    extract("POST","/api/users",b"ref=home",H,body)
bench("S0 framing+extraction (no auth)", s0_full)

def s0_auth():
    check_framing("POST","/api/users",H)
    v.verify(tok)
    extract("POST","/api/users",b"ref=home",H,body)
bench("S0 full incl. JWT verify", s0_auth)
