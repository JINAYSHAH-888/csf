"""Entrypoint for the CSF gateway."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path

import uvicorn

from csf import framing
from csf.bootstrap import BuiltAuth, build_auth, run_refresh_loop
from csf.config import Config, _from_raw
from csf.config_integrity import ConfigAudit, ConfigIntegrityError, load_trusted
from csf.decision import DecisionConfig
from csf.gateway import Detector, Gateway, GatewayOptions
from csf.model.detector import S3Config, S3LearnedDetector
from csf.s1_rules import S1Config, S1RulesDetector
from csf.semantic.detector import S2Config, S2SemanticDetector
from csf.telemetry import Mode, configure_logging

VERSION = "0.1.0"


async def build_app(cfg: Config) -> tuple[Gateway, BuiltAuth | None]:
    log = configure_logging(cfg.log_level, cfg.log_json)
    # Built before the server starts listening: with fail_closed set, an
    # unreachable JWKS endpoint must prevent startup, not surface later.
    auth = await build_auth(cfg.auth, log)

    detectors: list[Detector] = []
    if cfg.s1.enabled:
        s1 = S1RulesDetector(
            S1Config(
                socket_path=cfg.s1.socket_path,
                timeout_seconds=cfg.s1.timeout_seconds,
                tau_low=cfg.s1.tau_low,
                tau_high=cfg.s1.tau_high,
                score_field=cfg.s1.score_field,
                fail_open=cfg.s1.fail_open,
            ),
            logger=log,
        )
        healthy = await s1.healthcheck()
        log.info("s1 rules stage enabled", extra={"fields": {
            "socket": cfg.s1.socket_path, "reachable": healthy,
            "tau_low": cfg.s1.tau_low, "tau_high": cfg.s1.tau_high,
            "fail_open": cfg.s1.fail_open,
        }})
        if not healthy:
            # Not fatal: S1 degrades to "unavailable" per request and the
            # cascade continues. But an operator must see this at startup
            # rather than infer it from a drop in block rate.
            log.warning(
                "s1 sidecar is NOT reachable; the rules stage will report "
                "unavailable for every request and the gateway will run "
                "without CRS until it recovers",
                extra={"fields": {"socket": cfg.s1.socket_path}},
            )
        detectors.append(s1)

    if cfg.s2.enabled:
        s2 = S2SemanticDetector(
            S2Config(
                tau_block=cfg.s2.tau_block,
                tau_flag=cfg.s2.tau_flag,
                min_finding_score=cfg.s2.min_finding_score,
                max_value_length=cfg.s2.max_value_length,
                max_candidates=cfg.s2.max_candidates,
                enable_sql=cfg.s2.enable_sql,
                enable_xss=cfg.s2.enable_xss,
                enable_shell=cfg.s2.enable_shell,
                enable_traversal=cfg.s2.enable_traversal,
            ),
            logger=log,
        )
        log.info("s2 semantic stage enabled", extra={"fields": {
            "tau_block": cfg.s2.tau_block,
            "analysers": [n for n, on in (
                ("sql", cfg.s2.enable_sql), ("xss", cfg.s2.enable_xss),
                ("shell", cfg.s2.enable_shell),
                ("traversal", cfg.s2.enable_traversal)) if on],
        }})
        detectors.append(s2)

    if cfg.s3.enabled:
        s3 = S3LearnedDetector(
            S3Config(
                model_path=Path(cfg.s3.model_path),
                tau_block=cfg.s3.tau_block,
                tau_flag=cfg.s3.tau_flag,
                timeout_seconds=cfg.s3.timeout_seconds,
                fail_open=cfg.s3.fail_open,
                advisory_only=cfg.s3.advisory_only,
            ),
            logger=log,
        )
        log.info("s3 learned stage enabled", extra={"fields": {
            "model_path": cfg.s3.model_path, "healthy": s3.healthy,
            "tau_block": cfg.s3.tau_block,
        }})
        log.warning(
            "s3 generalises poorly across applications: measured ROC-AUC "
            "0.9993 in-corpus vs 0.5250-0.7059 on an unseen application. "
            "This model is only valid for the application it was trained on",
            extra={"fields": {}},
        )
        detectors.append(s3)

    options = GatewayOptions(
        upstream=cfg.upstream,
        mode=cfg.mode,
        framing_limits=cfg.framing_limits(),
        extraction_limits=cfg.extraction_limits(),
        verifier=auth.verifier if auth else None,
        key_resolvers=dict(auth.resolvers) if auth else {},
        auth_enabled=cfg.auth.enabled,
        protected_prefixes=cfg.auth.protected_prefixes,
        auth_fail_closed=cfg.auth.fail_closed,
        upstream_timeout=cfg.timeouts.upstream,
        detectors=tuple(detectors),
        decision=DecisionConfig(
            short_circuit_on_block=cfg.decision.short_circuit_on_block,
            max_block_rate_pct=cfg.decision.max_block_rate_pct,
            budget_min_samples=cfg.decision.budget_min_samples,
            budget_window=cfg.decision.budget_window,
        ),
        rate_limit=cfg.rate_limit,
        circuit_breaker=cfg.circuit_breaker,
        version=VERSION,
    )
    log.info("s4 decision engine", extra={"fields": {
        "fusion": "disjunctive",
        "short_circuit_on_block": cfg.decision.short_circuit_on_block,
        "max_block_rate_pct": cfg.decision.max_block_rate_pct,
    }})
    log.info("csf-gateway starting", extra={"fields": {
        "version": VERSION, "listen": f"{cfg.listen_host}:{cfg.listen_port}",
        "upstream": cfg.upstream, "mode": str(cfg.mode),
        "auth_enabled": cfg.auth.enabled, "detectors": len(detectors),
    }})
    # Which HTTP parser is installed changes our framing coverage. Make it
    # observable at startup rather than discovered during an incident.
    parser = framing.http_parser_in_use()
    log.info("http parser selected", extra={"fields": {"parser": parser}})
    for warning in framing.parser_warnings():
        log.warning(warning, extra={"fields": {"parser": parser}})

    if cfg.mode is Mode.ENFORCE and not detectors:
        log.warning(
            "running in ENFORCE mode with NO detection stages enabled; "
            "only S0 framing and authentication are enforced",
            extra={"fields": {}},
        )
    return Gateway(options, log), auth


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="csf-gateway")
    parser.add_argument("--config", help="path to config JSON")
    parser.add_argument("--upstream", help="upstream base URL (overrides config)")
    parser.add_argument("--host", help="listen host (overrides config)")
    parser.add_argument("--port", type=int, help="listen port (overrides config)")
    parser.add_argument("--mode", choices=[m.value for m in Mode])
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        print(f"csf-gateway {VERSION}")
        return 0

    config_audit: ConfigAudit | None = None
    try:
        if args.config:
            # T7: the config file is a trust decision, not just a parse. Verify
            # integrity (and a signature when CSF_CONFIG_HMAC_KEY is set) before
            # it becomes policy; record a fingerprint for the audit trail.
            raw_bytes, config_audit = load_trusted(args.config)
            cfg = _from_raw(json.loads(raw_bytes))
        else:
            cfg = Config()
        if args.upstream:
            cfg.upstream = args.upstream
        if args.host:
            cfg.listen_host = args.host
        if args.port:
            cfg.listen_port = args.port
        if args.mode:
            cfg.mode = Mode(args.mode)
        # Validate AFTER overrides, so a flag cannot bypass validation.
        cfg.validate()
    except (ValueError, OSError, ConfigIntegrityError) as exc:
        # Safe-fail: any doubt about the config stops startup. A gateway that
        # falls back to defaults on a corrupt/tampered config is one an
        # attacker disables by corrupting the config.
        print(f"fatal: {exc}", file=sys.stderr)
        return 1

    try:
        asyncio.run(_serve(cfg, config_audit))
    except RuntimeError as exc:
        print(f"fatal: {exc}", file=sys.stderr)
        return 1
    return 0


async def _serve(cfg: Config, config_audit: ConfigAudit | None = None) -> None:
    app, auth = await build_app(cfg)
    if config_audit is not None:
        # The audit trail T7 asks for: who loaded which policy, its fingerprint,
        # and whether it was signature-verified. A changed sha256 across
        # restarts is the config "diff" at the granularity that matters.
        app._log.info("config loaded", extra={"fields": config_audit.as_fields()})
    else:
        app._log.info("config loaded",
                      extra={"fields": {"config_path": "<defaults>",
                                        "config_signed": False}})
    refresher: asyncio.Task[None] | None = None
    if auth is not None and auth.resolvers:
        refresher = asyncio.create_task(run_refresh_loop(auth.resolvers, app._log))

    server = uvicorn.Server(uvicorn.Config(
        app,
        host=cfg.listen_host,
        port=cfg.listen_port,
        log_level="warning",
        access_log=False,
        # httptools is strict about framing; h11 is not (see csf/framing.py).
        # We request httptools explicitly and our own check covers either.
        http="auto",
    ))
    try:
        await server.serve()
    finally:
        if refresher is not None:
            refresher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await refresher
        if auth is not None:
            await auth.aclose()
        await app.aclose()


if __name__ == "__main__":
    raise SystemExit(main())
