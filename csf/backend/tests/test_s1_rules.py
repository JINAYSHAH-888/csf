"""S1 detector: thresholding, degradation, and the payload contract."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from csf.extraction import extract
from csf.gateway import Decision, Stage
from csf.s1_rules import S1Config, S1RulesDetector


def H(*pairs: tuple[str, str]) -> list[tuple[bytes, bytes]]:
    return [(k.encode(), v.encode()) for k, v in pairs]


class FakeSidecar:
    """A controllable stand-in for the Coraza sidecar."""

    def __init__(self, detection: int = 0, **extra: Any) -> None:
        self.detection = detection
        self.extra = extra
        self.requests: list[dict[str, Any]] = []
        self.raise_error: Exception | None = None
        self.status = 200
        self.body: bytes | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, text="ok")
        if self.raise_error is not None:
            raise self.raise_error
        import json

        self.requests.append(json.loads(request.content))
        if self.body is not None:
            return httpx.Response(self.status, content=self.body)
        payload = {
            "id": "x",
            "anomaly_score": self.detection,
            "attack_score": self.extra.get("attack", self.detection),
            "blocking_score": self.extra.get("blocking", 0),
            "score_by_pl": self.extra.get("by_pl", {}),
            "matched_rules": self.extra.get("rules", []),
            "categories": self.extra.get("categories", []),
            "total_rules_fired": self.extra.get("fired", 0),
            "elapsed_us": 900,
        }
        return httpx.Response(self.status, json=payload)


def make_detector(sidecar: FakeSidecar, **cfg: Any) -> S1RulesDetector:
    detector = S1RulesDetector(S1Config(**cfg))
    detector._client = httpx.AsyncClient(
        transport=httpx.MockTransport(sidecar.handler), base_url="http://s1"
    )
    return detector


def sample_request(query: bytes = b"q=test", body: bytes = b""):
    headers = H(("host", "app.local"), ("user-agent", "curl/8"))
    if body:
        headers.append((b"content-type", b"application/json"))
    result = extract("GET", "/api/items", query, headers, body)
    result.request_meta["request_id"] = "req-1"
    return result


# ---------------------------------------------------------------------------
# Thresholding — the measured band from Phase 3
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expect_decision", "why"),
    [
        (0, Decision.ALLOW, "clean traffic is forwarded without escalation"),
        (4, Decision.ALLOW, "at tau_low exactly: still clean"),
        (5, Decision.ALLOW, "in the band: allowed here so the cascade continues"),
        (7, Decision.ALLOW, "in the band"),
        (8, Decision.BLOCK, "at tau_high: block"),
        (40, Decision.BLOCK, "well above tau_high"),
    ],
)
async def test_threshold_bands(score, expect_decision, why):
    sidecar = FakeSidecar(detection=score)
    detector = make_detector(sidecar, tau_low=4.0, tau_high=8.0)
    verdict = await detector.evaluate(sample_request())
    assert verdict.decision is expect_decision, why
    assert verdict.stage is Stage.RULES
    assert verdict.score == float(score)
    await detector.aclose()


async def test_escalation_band_is_counted_separately():
    """The band is the whole point of the cascade; it must be observable."""
    sidecar = FakeSidecar(detection=6)
    detector = make_detector(sidecar, tau_low=4.0, tau_high=8.0)
    await detector.evaluate(sample_request())
    assert detector.escalations == 1
    assert detector.blocks == 0
    await detector.aclose()


async def test_block_reason_carries_rules_and_categories():
    """An operator must be able to diagnose a block without reading source."""
    sidecar = FakeSidecar(
        detection=40, categories=["sqli", "rce"],
        rules=[{"id": 942100}, {"id": 942130}],
    )
    detector = make_detector(sidecar, tau_high=8.0)
    verdict = await detector.evaluate(sample_request())
    assert verdict.decision is Decision.BLOCK
    assert "942100" in verdict.reason
    assert "sqli" in verdict.reason
    assert "attack=40" in verdict.reason and "anomaly=40" in verdict.reason
    await detector.aclose()


# ---------------------------------------------------------------------------
# Degradation: a rules outage must not become an application outage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "setup"),
    [
        ("connect_error", lambda s: setattr(s, "raise_error", httpx.ConnectError("down"))),
        ("timeout", lambda s: setattr(s, "raise_error", httpx.ReadTimeout("slow"))),
        ("http_500", lambda s: setattr(s, "status", 500)),
        ("garbage_body", lambda s: setattr(s, "body", b"<html>not json</html>")),
    ],
)
async def test_sidecar_failure_degrades_rather_than_blocks(name, setup):
    sidecar = FakeSidecar()
    setup(sidecar)
    detector = make_detector(sidecar)
    verdict = await detector.evaluate(sample_request())

    assert verdict.decision is Decision.ALLOW, (
        "a rules-engine outage must not fail the request; the cascade "
        "continues to S2/S3"
    )
    assert "s1_unavailable" in verdict.reason, (
        "degradation must be recorded, not silent — it is alertable"
    )
    assert detector.unavailable_count == 1
    await detector.aclose()


async def test_unavailable_is_distinguishable_from_clean():
    """A silent failure that looks like 'score 0' would be a security hole:
    every request would appear clean while nothing was being checked."""
    clean = make_detector(FakeSidecar(detection=0))
    clean_verdict = await clean.evaluate(sample_request())
    await clean.aclose()

    broken_sidecar = FakeSidecar()
    broken_sidecar.raise_error = httpx.ConnectError("down")
    broken = make_detector(broken_sidecar)
    broken_verdict = await broken.evaluate(sample_request())
    await broken.aclose()

    assert clean_verdict.reason == ""
    assert "s1_unavailable" in broken_verdict.reason
    assert clean.unavailable_count == 0
    assert broken.unavailable_count == 1


async def test_healthcheck_reports_reachability():
    ok = make_detector(FakeSidecar())
    assert await ok.healthcheck() is True
    await ok.aclose()

    down_sidecar = FakeSidecar()
    down_sidecar.raise_error = httpx.ConnectError("down")
    down = make_detector(down_sidecar)
    # /healthz short-circuits before raise_error in the fake, so force it.
    down._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("down"))
        ),
        base_url="http://s1",
    )
    assert await down.healthcheck() is False
    await down.aclose()


# ---------------------------------------------------------------------------
# The payload contract with the sidecar
# ---------------------------------------------------------------------------


async def test_payload_is_rebuilt_from_extraction_not_reparsed():
    """The sidecar must never re-parse raw HTTP: a second parser is a second
    interpretation to disagree with (threat model T3)."""
    sidecar = FakeSidecar()
    detector = make_detector(sidecar)
    extracted = sample_request(query=b"id=1%27+OR+%271%27%3D%271")
    await detector.evaluate(extracted)

    sent = sidecar.requests[0]
    assert sent["method"] == "GET"
    assert sent["path"] == "/api/items"
    assert sent["query"] == "id=1%27+OR+%271%27%3D%271", (
        "the RAW query must be forwarded; sending the decoded form would "
        "hide double-encoding from CRS"
    )
    assert sent["headers"]["host"] == ["app.local"]
    assert sent["id"] == "req-1", "request id must flow through for correlation"
    await detector.aclose()


async def test_body_is_forwarded_and_bounded():
    sidecar = FakeSidecar()
    detector = make_detector(sidecar, max_body_bytes=20)
    big = b'{"x":"' + b"A" * 500 + b'"}'
    await detector.evaluate(sample_request(body=big))

    sent = sidecar.requests[0]
    assert len(sent["body"]) == 20, "body must be bounded before leaving the gateway"
    await detector.aclose()


async def test_duplicate_headers_are_preserved_to_the_sidecar():
    sidecar = FakeSidecar()
    detector = make_detector(sidecar)
    headers = H(("host", "a"), ("x-dup", "1"), ("x-dup", "2"))
    extracted = extract("GET", "/x", b"", headers, b"")
    extracted.request_meta["request_id"] = "r"
    await detector.evaluate(extracted)

    assert sidecar.requests[0]["headers"]["x-dup"] == ["1", "2"]
    await detector.aclose()


# ---------------------------------------------------------------------------
# Configuration safety
# ---------------------------------------------------------------------------


def test_config_rejects_empty_escalation_band():
    """tau_high <= tau_low collapses the cascade into a binary CRS
    deployment, which is the design this project exists to improve on."""
    from csf.config import S1Settings

    with pytest.raises(ValueError, match="must exceed tau_low"):
        S1Settings(enabled=True, tau_low=10.0, tau_high=5.0).validate()
    with pytest.raises(ValueError, match="must exceed tau_low"):
        S1Settings(enabled=True, tau_low=8.0, tau_high=8.0).validate()


def test_config_defaults_match_measurements():
    """If these drift from the benchmarks, one of them is wrong. Thresholds are
    measured, not chosen. tau_high=11 on the attack score is the cross-corpus
    re-derivation (ADR-0015, docs/benchmarks/cross-corpus-attack-score.json);
    it replaced the Phase 3 provisional 8 on the full anomaly score."""
    from csf.config import S1Settings

    settings = S1Settings()
    assert settings.tau_low == 1.0
    assert settings.tau_high == 11.0
    assert settings.score_field == "attack"


async def test_fail_closed_blocks_when_sidecar_unavailable():
    """fail_open=False is for routes where serving without CRS is
    unacceptable. It turns a sidecar outage into an application outage, which
    is a deliberate trade and must actually work."""
    sidecar = FakeSidecar()
    sidecar.raise_error = httpx.ConnectError("down")
    detector = make_detector(sidecar, fail_open=False)
    verdict = await detector.evaluate(sample_request())

    assert verdict.decision is Decision.BLOCK
    assert "fail_closed" in verdict.reason
    assert detector.unavailable_count == 1
    await detector.aclose()


async def test_fail_open_is_the_default():
    sidecar = FakeSidecar()
    sidecar.raise_error = httpx.ConnectError("down")
    detector = make_detector(sidecar)
    verdict = await detector.evaluate(sample_request())
    assert verdict.decision is Decision.ALLOW
    await detector.aclose()


async def test_s1_thresholds_on_attack_score_not_anomaly():
    """The cross-corpus fix (ADR-0015): a request whose score is mostly
    PROTOCOL-ENFORCEMENT (which S0 owns) must NOT block on S1, even when its
    full anomaly score is high. Only the attack-rule contribution counts."""
    # anomaly 40 but attack 3 -> protocol-dominated (an ECML-style benign
    # request). Must not block at tau_high=11.
    sidecar = FakeSidecar(detection=40, attack=3, categories=["protocol"])
    detector = make_detector(sidecar, tau_low=4.0, tau_high=11.0)
    verdict = await detector.evaluate(sample_request())
    assert verdict.decision is Decision.ALLOW, (
        "a protocol-dominated request must not block S1 on attack score"
    )


async def test_s1_blocks_when_attack_score_is_high():
    sidecar = FakeSidecar(detection=45, attack=25, categories=["sqli"],
                          rules=[{"id": 942100}])
    detector = make_detector(sidecar, tau_low=4.0, tau_high=11.0)
    verdict = await detector.evaluate(sample_request())
    assert verdict.decision is Decision.BLOCK


async def test_anomaly_scoring_still_available_as_an_option():
    """score_field='anomaly' restores the old behaviour for operators who want
    CRS's full score."""
    sidecar = FakeSidecar(detection=40, attack=3)
    detector = make_detector(sidecar, tau_high=11.0, score_field="anomaly")
    verdict = await detector.evaluate(sample_request())
    assert verdict.decision is Decision.BLOCK
