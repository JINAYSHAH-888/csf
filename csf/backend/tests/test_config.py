import json

import pytest

from csf.config import Config, DecisionSettings, load
from csf.telemetry import Mode


def test_default_mode_is_shadow():
    """Enforcement must be chosen deliberately, never inherited."""
    assert Config().mode is Mode.SHADOW


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda c: setattr(c, "upstream", ""), "upstream is required"),
    (lambda c: setattr(c, "upstream", "notaurl"), "http"),
    (lambda c: setattr(c, "listen_port", 0), "listen_port"),
    (lambda c: setattr(c.limits, "max_body_bytes", 0), "max_body_bytes"),
    (lambda c: setattr(c.limits, "max_decode_depth", 0), "max_decode_depth"),
    (lambda c: setattr(c.limits, "max_decode_depth", 50), "max_decode_depth"),
    (lambda c: setattr(c.limits, "max_json_depth", 500), "max_json_depth"),
    (lambda c: setattr(c.limits, "max_candidates", 0), "max_candidates"),
    (lambda c: setattr(c.auth, "enabled", True), "protected_prefixes"),
])
def test_invalid_configs_are_rejected(mutate, match):
    cfg = Config(upstream="http://localhost:3000")
    mutate(cfg)
    with pytest.raises(ValueError, match=match):
        cfg.validate()


def test_load_from_file(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({
        "upstream": "http://localhost:3000", "mode": "enforce",
        "limits": {"max_decode_depth": 2},
        "auth": {
            "enabled": True,
            "protected_prefixes": ["/admin"],
            "issuers": [{
                "issuer": "https://auth.example",
                "audience": "api",
                "allowed_algs": ["RS256"],
                "jwks_url": "https://auth.example/.well-known/jwks.json",
            }],
        },
    }))
    cfg = load(p)
    assert cfg.mode is Mode.ENFORCE
    assert cfg.limits.max_decode_depth == 2
    assert cfg.auth.protected_prefixes == ("/admin",)
    assert cfg.auth.issuers[0].jwks_url.endswith("jwks.json")
    assert cfg.auth.issuers[0].allowed_algs == ("RS256",)


def test_auth_enabled_without_issuers_is_rejected():
    """Enabling auth with no issuers means no token could ever verify."""
    cfg = Config(upstream="http://localhost:3000")
    cfg.auth.enabled = True
    cfg.auth.protected_prefixes = ("/admin",)
    with pytest.raises(ValueError, match="no issuers"):
        cfg.validate()


@pytest.mark.parametrize(("overrides", "match"), [
    ({"issuer": ""}, "issuer is required"),
    ({"audience": ""}, "audience is required"),
    ({"jwks_url": "", "static_keys": {}}, "exactly one of"),
    ({"jwks_url": "https://a/j", "static_keys": {"k": "key.pem"}}, "exactly one of"),
])
def test_invalid_issuer_settings_rejected(overrides, match):
    from csf.config import IssuerSettings

    base = {"issuer": "https://a", "audience": "api",
            "jwks_url": "https://a/.well-known/jwks.json"}
    base.update(overrides)
    with pytest.raises(ValueError, match=match):
        IssuerSettings(**base).validate()


# -- decision policy (Phase 7) --------------------------------------------


def test_decision_defaults_validate():
    DecisionSettings().validate()


@pytest.mark.parametrize("pct", [0.0, -1.0, 101.0])
def test_block_rate_budget_must_be_a_real_percentage(pct):
    with pytest.raises(ValueError, match="max_block_rate_pct"):
        DecisionSettings(max_block_rate_pct=pct).validate()


def test_window_smaller_than_sample_floor_is_rejected():
    """A window that can never hold enough samples can never be conclusive,
    so the budget guard would silently never fire."""
    with pytest.raises(ValueError, match="budget_window"):
        DecisionSettings(budget_window=50, budget_min_samples=200).validate()


def test_decision_section_is_loaded_from_config_file(tmp_path):
    path = tmp_path / "gw.json"
    path.write_text(json.dumps({
        "upstream": "http://localhost:3000",
        "decision": {"max_block_rate_pct": 1.5, "budget_min_samples": 50,
                     "budget_window": 500},
    }))
    cfg = load(path)
    assert cfg.decision.max_block_rate_pct == 1.5
    assert cfg.decision.budget_min_samples == 50


def test_invalid_decision_section_fails_config_validation(tmp_path):
    path = tmp_path / "gw.json"
    path.write_text(json.dumps({
        "upstream": "http://localhost:3000",
        "decision": {"max_block_rate_pct": 0},
    }))
    with pytest.raises(ValueError, match="max_block_rate_pct"):
        load(path)


# -- resilience config (Phase 9/10) ----------------------------------------


def test_resilience_sections_load(tmp_path):
    path = tmp_path / "gw.json"
    path.write_text(json.dumps({
        "upstream": "http://localhost:3000",
        "rate_limit": {"enabled": True, "rate_per_second": 20, "burst": 40},
        "circuit_breaker": {"trip_threshold_pct": 30, "min_samples": 100,
                            "window": 1000},
    }))
    cfg = load(path)
    assert cfg.rate_limit.enabled and cfg.rate_limit.rate_per_second == 20
    assert cfg.circuit_breaker.trip_threshold_pct == 30


def test_invalid_rate_limit_fails_validation(tmp_path):
    path = tmp_path / "gw.json"
    path.write_text(json.dumps({"upstream": "http://localhost:3000",
                                "rate_limit": {"rate_per_second": -1}}))
    with pytest.raises(ValueError, match="rate_per_second"):
        load(path)


def test_invalid_breaker_window_fails_validation(tmp_path):
    path = tmp_path / "gw.json"
    path.write_text(json.dumps({"upstream": "http://localhost:3000",
                                "circuit_breaker": {"window": 10, "min_samples": 50}}))
    with pytest.raises(ValueError, match="window"):
        load(path)
