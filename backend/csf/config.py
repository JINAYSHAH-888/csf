"""Gateway configuration loading and validation.

Validation is strict and happens at startup. An unsafe configuration must
crash the process, not degrade a request: a gateway that silently starts in a
weaker posture than the operator intended is worse than one that refuses to
start.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from csf.extraction import ExtractionLimits
from csf.framing import FramingLimits
from csf.normalization import Limits as NormLimits
from csf.resilience import CircuitBreakerConfig, RateLimitConfig
from csf.telemetry import Mode

__all__ = [
    "AuthConfig",
    "Config",
    "IssuerSettings",
    "LimitsConfig",
    "S1Settings",
    "S2Settings",
    "S3Settings",
    "TimeoutsConfig",
    "load",
]


@dataclass(slots=True)
class TimeoutsConfig:
    upstream: float = 30.0
    keep_alive: float = 5.0


@dataclass(slots=True)
class LimitsConfig:
    max_body_bytes: int = 1 << 20
    max_candidates: int = 256
    max_json_depth: int = 20
    max_decode_depth: int = 3
    max_value_bytes: int = 64 * 1024
    max_headers: int = 100
    inspect_cookies: bool = False


@dataclass(slots=True)
class IssuerSettings:
    """One trusted issuer. Keys come from a JWKS endpoint or static PEMs."""

    issuer: str
    audience: str
    allowed_algs: tuple[str, ...] = ("RS256",)
    #: Pre-configured JWKS endpoint. Never derived from a token.
    jwks_url: str = ""
    #: Alternative to jwks_url: kid -> PEM public key file path.
    static_keys: dict[str, str] = field(default_factory=dict)
    jwks_ttl_seconds: float = 600.0
    jwks_min_refresh_interval_seconds: float = 30.0
    leeway_seconds: int = 0

    def validate(self) -> None:
        if not self.issuer:
            raise ValueError("config: issuer is required")
        if not self.audience:
            raise ValueError(f"config: issuer {self.issuer!r}: audience is required")
        if bool(self.jwks_url) == bool(self.static_keys):
            raise ValueError(
                f"config: issuer {self.issuer!r}: exactly one of jwks_url or "
                "static_keys must be set"
            )


@dataclass(slots=True)
class AuthConfig:
    enabled: bool = False
    protected_prefixes: tuple[str, ...] = ()
    #: Behaviour when verification cannot be performed at all (e.g. JWKS
    #: unreachable). True = reject. Default True: failing open on
    #: authentication is how breaches happen.
    fail_closed: bool = True
    issuers: tuple[IssuerSettings, ...] = ()


@dataclass(slots=True)
class S1Settings:
    """S1 rules stage. Thresholds MUST come from a measured curve."""

    enabled: bool = False
    socket_path: str = "/tmp/csf-s1.sock"  # noqa: S108 - operator-configured
    timeout_seconds: float = 0.050
    #: Phase 4 values, re-derived on the real corpus (CSIC 2010 + payload
    #: lists), validation split, WITH the per-application CRS exclusions in
    #: configs/crs/exclusions-csic.conf applied.
    #:
    #: At tau_high=8: FPR 0.18%, recall sqli 97.1% / xss 96.4% / cmdi 77.6%.
    #:
    #: ⚠ These replace the Phase 3 defaults, which were derived from 40
    #: hand-built benign samples and would have produced a 99.46% FPR on real
    #: traffic. Thresholds are corpus- AND tuning-specific: re-derive them
    #: against your own traffic with your own exclusions before enforcing.
    tau_low: float = 1.0
    #: tau_high re-derived in ADR-0015 (cross-corpus): 11 on the attack score.
    tau_high: float = 11.0
    #: "attack" (default) thresholds on the protocol-excluded attack score;
    #: "anomaly" on the full CRS score. See ADR-0015.
    score_field: str = "attack"
    #: See S1Config.fail_open. True = a sidecar outage degrades the cascade;
    #: False = a sidecar outage blocks traffic.
    fail_open: bool = True

    def validate(self) -> None:
        if not self.enabled:
            return
        if self.tau_low < 0:
            raise ValueError("config: s1.tau_low must be >= 0")
        if self.tau_high <= self.tau_low:
            raise ValueError(
                f"config: s1.tau_high ({self.tau_high}) must exceed tau_low "
                f"({self.tau_low}); otherwise the escalation band is empty "
                "and the cascade degenerates to a binary CRS deployment"
            )
        if self.timeout_seconds <= 0:
            raise ValueError("config: s1.timeout_seconds must be > 0")
        if self.score_field not in ("attack", "anomaly"):
            raise ValueError(
                f"config: s1.score_field must be 'attack' or 'anomaly', "
                f"got {self.score_field!r}")


@dataclass(slots=True)
class S2Settings:
    """S2 grammar-aware semantic stage. Pure CPU, no external dependency."""

    enabled: bool = False
    #: Measured calibration: every analyser weights a lone weak marker below
    #: this, so corroborating evidence alone cannot block.
    tau_block: float = 4.0
    tau_flag: float = 1.0
    min_finding_score: float = 3.0
    max_value_length: int = 4096
    max_candidates: int = 64
    enable_sql: bool = True
    enable_xss: bool = True
    enable_shell: bool = True
    enable_traversal: bool = True

    def validate(self) -> None:
        if not self.enabled:
            return
        if self.tau_block <= self.tau_flag:
            raise ValueError(
                f"config: s2.tau_block ({self.tau_block}) must exceed "
                f"tau_flag ({self.tau_flag})"
            )
        if not any((self.enable_sql, self.enable_xss, self.enable_shell,
                    self.enable_traversal)):
            raise ValueError(
                "config: s2 is enabled but every analyser is disabled; "
                "the stage would examine every request and conclude nothing"
            )


@dataclass(slots=True)
class S3Settings:
    """S3 learned stage.

    **Disabled by default.** Phase 6 measured ROC-AUC 0.9993 in-corpus and
    0.5250–0.7059 on an unseen application *when trained on a single
    application* — the model learned one app's benign vocabulary.

    ADR-0019 revisits this: training on MULTIPLE applications (CSIC + ECML)
    teaches attack structure instead, raising cross-application ROC-AUC on a
    third unseen app from ~0.50 to ~0.94. With the threshold calibrated on the
    deployment's own benign (shadow mode), that is ~82% recall at ~2–5% FPR.
    So S3 is defensible where it was trained on diverse / the protected
    application's traffic AND calibrated on that application's benign. It stays
    off by default and advisory-only (ADR-0017) until an operator does both.
    `scripts/train_s3_multiapp.py` trains the shipped multi-application model.
    """

    enabled: bool = False
    model_path: str = ""
    #: Calibrated probability, not a raw score.
    tau_block: float = 0.99
    tau_flag: float = 0.80
    timeout_seconds: float = 0.020
    fail_open: bool = True
    #: Set True only when the model was trained on traffic from THIS
    #: application. Startup refuses to enable S3 without it.
    trained_on_this_application: bool = False
    #: S3 may FLAG but never BLOCK while True (the default). A deliberate
    #: safety bound on a stage whose failure mode is a cross-app FPR collapse
    #: (ADR-0017). Set False only after validating a per-application model.
    advisory_only: bool = True

    def validate(self) -> None:
        if not self.enabled:
            return
        if not self.model_path:
            raise ValueError("config: s3 enabled but no model_path")
        if not self.trained_on_this_application:
            raise ValueError(
                "config: s3 enabled but trained_on_this_application is false. "
                "Measured cross-corpus ROC-AUC is 0.53-0.71 versus 0.999 "
                "in-corpus: a model trained on another application's traffic "
                "classifies ordinary requests as attacks. Train on this "
                "application's traffic, then set the flag."
            )
        if not 0.0 < self.tau_flag < self.tau_block <= 1.0:
            raise ValueError(
                f"config: s3 thresholds must satisfy "
                f"0 < tau_flag ({self.tau_flag}) < tau_block "
                f"({self.tau_block}) <= 1"
            )


@dataclass(slots=True)
class DecisionSettings:
    """How stage verdicts become one action (ADR-0011).

    ``max_block_rate_pct`` is the field that matters, and it has no
    corpus-derived default because Phase 7 measured that no corpus can supply
    one: every policy tested scored 0.00% FPR on the development corpus while
    the same thresholds ranged to 96.71% FPR on an unseen application. 5% is a
    placeholder meaning "obviously too many"; the operator is expected to set
    it from their own shadow-mode traffic.
    """

    short_circuit_on_block: bool = True
    max_block_rate_pct: float = 5.0
    budget_min_samples: int = 200
    budget_window: int = 2000

    def validate(self) -> None:
        if not 0.0 < self.max_block_rate_pct <= 100.0:
            raise ValueError(
                f"config: decision.max_block_rate_pct must be in (0, 100], "
                f"got {self.max_block_rate_pct}")
        if self.budget_min_samples < 1:
            raise ValueError("config: decision.budget_min_samples must be positive")
        if self.budget_window < self.budget_min_samples:
            raise ValueError(
                f"config: decision.budget_window ({self.budget_window}) must be "
                f"at least budget_min_samples ({self.budget_min_samples}); a "
                f"window smaller than the sample floor can never be conclusive")


@dataclass(slots=True)
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    upstream: str = ""
    #: Shadow is the default posture. Enforcement must be chosen
    #: deliberately, never inherited by accident.
    mode: Mode = Mode.SHADOW
    log_level: str = "info"
    log_json: bool = True
    timeouts: TimeoutsConfig = field(default_factory=TimeoutsConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    s1: S1Settings = field(default_factory=S1Settings)
    s2: S2Settings = field(default_factory=S2Settings)
    s3: S3Settings = field(default_factory=S3Settings)
    decision: DecisionSettings = field(default_factory=DecisionSettings)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)

    def validate(self) -> None:
        self.decision.validate()
        self.rate_limit.validate()
        self.circuit_breaker.validate()
        if not self.upstream:
            raise ValueError("config: upstream is required")
        if not self.upstream.startswith(("http://", "https://")):
            raise ValueError(f"config: upstream must be an http(s) URL, got {self.upstream!r}")
        if not 1 <= self.listen_port <= 65535:
            raise ValueError(f"config: listen_port out of range: {self.listen_port}")
        if self.mode not in tuple(Mode):
            raise ValueError(f"config: unknown mode {self.mode!r}")
        if self.limits.max_body_bytes <= 0:
            raise ValueError(
                "config: max_body_bytes must be positive "
                "(unbounded bodies are a DoS vector)"
            )
        if not 1 <= self.limits.max_decode_depth <= 10:
            raise ValueError(
                f"config: max_decode_depth must be 1..10, got {self.limits.max_decode_depth}"
            )
        if not 1 <= self.limits.max_json_depth <= 100:
            raise ValueError(
                f"config: max_json_depth must be 1..100, got {self.limits.max_json_depth}"
            )
        if self.limits.max_candidates <= 0:
            raise ValueError("config: max_candidates must be positive")
        if self.auth.enabled:
            if not self.auth.protected_prefixes:
                raise ValueError(
                    "config: auth enabled but no protected_prefixes; "
                    "this would silently protect nothing"
                )
            if not self.auth.issuers:
                raise ValueError(
                    "config: auth enabled but no issuers configured; "
                    "no token could ever verify"
                )
            for issuer in self.auth.issuers:
                issuer.validate()
        self.s1.validate()
        self.s2.validate()
        self.s3.validate()

    def extraction_limits(self) -> ExtractionLimits:
        return ExtractionLimits(
            max_candidates=self.limits.max_candidates,
            max_body_bytes=self.limits.max_body_bytes,
            max_json_depth=self.limits.max_json_depth,
            inspect_cookies=self.limits.inspect_cookies,
            normalization=NormLimits(
                max_decode_depth=self.limits.max_decode_depth,
                max_value_bytes=self.limits.max_value_bytes,
            ),
        )

    def framing_limits(self) -> FramingLimits:
        return FramingLimits(max_headers=self.limits.max_headers)


def _apply(cfg: Config, raw: dict[str, Any]) -> None:
    """Overlay parsed JSON onto a Config. Shared by load() and _from_raw()."""
    for key in ("listen_host", "listen_port", "upstream", "log_level", "log_json"):
        if key in raw:
            setattr(cfg, key, raw[key])
    if "mode" in raw:
        cfg.mode = Mode(raw["mode"])
    if "timeouts" in raw:
        cfg.timeouts = TimeoutsConfig(**raw["timeouts"])
    if "limits" in raw:
        cfg.limits = LimitsConfig(**raw["limits"])
    if "s1" in raw:
        cfg.s1 = S1Settings(**raw["s1"])
    if "s2" in raw:
        cfg.s2 = S2Settings(**raw["s2"])
    if "s3" in raw:
        cfg.s3 = S3Settings(**raw["s3"])
    if "decision" in raw:
        cfg.decision = DecisionSettings(**raw["decision"])
    if "rate_limit" in raw:
        cfg.rate_limit = RateLimitConfig(**raw["rate_limit"])
    if "circuit_breaker" in raw:
        cfg.circuit_breaker = CircuitBreakerConfig(**raw["circuit_breaker"])
    if "auth" in raw:
        auth = dict(raw["auth"])
        auth["protected_prefixes"] = tuple(auth.get("protected_prefixes", ()))
        issuers = []
        for entry in auth.pop("issuers", ()):
            entry = dict(entry)
            entry["allowed_algs"] = tuple(entry.get("allowed_algs", ("RS256",)))
            issuers.append(IssuerSettings(**entry))
        auth["issuers"] = tuple(issuers)
        cfg.auth = AuthConfig(**auth)


def _from_raw(raw: dict[str, Any]) -> Config:
    """Build and validate a Config from already-parsed JSON."""
    cfg = Config()
    _apply(cfg, raw)
    cfg.validate()
    return cfg


def load(path: str | Path | None = None) -> Config:
    """Load configuration, applying defaults, then validate."""
    cfg = Config()
    if path:
        raw: dict[str, Any] = json.loads(Path(path).read_text())
        _apply(cfg, raw)
    cfg.validate()
    return cfg
