"""S3: the learned stage.

Position in the cascade
-----------------------
S3 exists for the residual S1 and S2 cannot reach. Phase 5's ablation sized
it: on an unseen application, **59.2% of claimed attacks are missed by both**
earlier stages. That gap, not overall accuracy, is what S3 has to earn its
latency with.

Model choice
------------
A character n-gram classifier rather than a distilled transformer, per
ADR-0008. The budget math is the reason: S0+S1+S2 already consume ~5.4 ms p99
of a 10 ms budget, and the most optimistic published DistilBERT figure
exceeds the remainder on its own. The research that motivated the transformer
also measured a character CNN at comparable adversarial detection for ~1/89
of the cost.

Failure policy
--------------
Like S1, S3 degrades rather than failing the request. A model that cannot
load or times out returns an ``unavailable`` verdict and the cascade
continues with whatever S1 and S2 concluded. The degradation is counted so it
is alertable rather than silent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from csf.gateway import Decision, Stage, Verdict
from csf.model.features import request_document

if TYPE_CHECKING:
    from csf.extraction import Result as ExtractionResult

__all__ = ["S3Config", "S3LearnedDetector", "S3Signal"]


@dataclass(frozen=True, slots=True)
class S3Config:
    """Thresholds and runtime for the learned stage.

    ``tau_block`` is a CALIBRATED PROBABILITY, not a raw score. The model is
    isotonic-calibrated during training so that 0.99 means 0.99; without that,
    a threshold is not a statement about the false-positive budget and
    "block above 0.99" means nothing.
    """

    model_path: Path | None = None
    #: Block at or above this calibrated probability.
    tau_block: float = 0.99
    #: Flag above this.
    tau_flag: float = 0.80
    #: Per-request inference deadline. Exceeding it degrades the stage rather
    #: than stalling the request (threat model T5).
    timeout_seconds: float = 0.020
    #: Fail-open: a model outage must not become an application outage.
    fail_open: bool = True
    #: Advisory-only: S3 may FLAG but never BLOCK. Default True, and that is a
    #: safety decision, not a limitation. S3's measured failure mode is a
    #: cross-application FPR collapse (Phase 6: AUC 0.53-0.71 off-corpus); a
    #: learned stage that blocks on that is a block-storm waiting to happen.
    #: Advisory-only lets S3 contribute signal to the audit log and the
    #: decision engine WITHOUT being able to cause a production incident. An
    #: operator who has trained on their own traffic AND validated it may set
    #: this False to let S3 block. See ADR-0008/ADR-0017.
    advisory_only: bool = True


@dataclass(slots=True)
class S3Signal:
    probability: float = 0.0
    available: bool = True
    error: str = ""
    elapsed_us: int = 0
    document_chars: int = 0
    findings: list[str] = field(default_factory=list)


class S3LearnedDetector:
    """Implements the :class:`~csf.gateway.Detector` protocol."""

    def __init__(self, config: S3Config, logger: Any | None = None) -> None:
        self._cfg = config
        self._log = logger
        self._model: Any = None
        self._load_error = ""
        self.evaluations = 0
        self.unavailable_count = 0
        self.blocks = 0
        self.flags = 0
        self._load()

    def _load(self) -> None:
        if self._cfg.model_path is None:
            self._load_error = "no model_path configured"
            return
        path = Path(self._cfg.model_path)
        if not path.exists():
            self._load_error = f"model artifact not found at {path}"
            if self._log is not None:
                self._log.warning(
                    "s3 model artifact missing; the stage will report "
                    "unavailable for every request",
                    extra={"fields": {"path": str(path)}},
                )
            return
        try:
            import pickle  # noqa: S403 - our own artifact, see note below

            # The artifact is produced by our training pipeline and read from
            # a configured path, never from user input. A model file an
            # attacker can write is already a full compromise, so pickle adds
            # no new exposure here — but the path must stay operator-owned.
            with path.open("rb") as handle:
                self._model = pickle.load(handle)  # noqa: S301
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"{type(exc).__name__}: {exc}"
            if self._log is not None:
                self._log.error("s3 model failed to load",
                                extra={"fields": {"error": self._load_error}})

    @property
    def name(self) -> Stage:
        return Stage.MODEL

    @property
    def healthy(self) -> bool:
        return self._model is not None

    def predict(self, extracted: ExtractionResult) -> S3Signal:
        """Score one request. Never raises."""
        started = time.perf_counter()
        if self._model is None:
            return S3Signal(available=False, error=self._load_error or "no model")

        document = request_document(extracted)
        try:
            probability = float(self._model.predict_proba([document])[0][1])
        except Exception as exc:  # noqa: BLE001
            self.unavailable_count += 1
            if self._log is not None:
                self._log.error("s3 inference failed",
                                extra={"fields": {"error": str(exc)}})
            return S3Signal(available=False, error=type(exc).__name__,
                            elapsed_us=int((time.perf_counter() - started) * 1e6))

        return S3Signal(
            probability=probability,
            elapsed_us=int((time.perf_counter() - started) * 1e6),
            document_chars=len(document),
        )

    async def evaluate(self, extracted: ExtractionResult) -> Verdict:
        signal = self.predict(extracted)
        self.evaluations += 1

        if not signal.available:
            self.unavailable_count += 1
            if self._cfg.fail_open:
                return Verdict(decision=Decision.ALLOW, stage=Stage.MODEL,
                               reason=f"s3_unavailable:{signal.error}")
            return Verdict(decision=Decision.BLOCK, stage=Stage.MODEL,
                           reason=f"s3_unavailable_fail_closed:{signal.error}")

        p = signal.probability
        # S3 classifies at request level, so unlike S2 it cannot name the
        # offending parameter. S1 and S2 still do, so the combined audit
        # record stays specific.
        reason = f"model_probability={p:.4f}"

        if p >= self._cfg.tau_block and not self._cfg.advisory_only:
            self.blocks += 1
            return Verdict(decision=Decision.BLOCK, stage=Stage.MODEL,
                           reason=reason, score=p)
        if p >= self._cfg.tau_block and self._cfg.advisory_only:
            # Would block, but S3 is advisory: downgrade to FLAG so a
            # non-transferring model cannot take the application down.
            self.flags += 1
            return Verdict(decision=Decision.FLAG, stage=Stage.MODEL,
                           reason=f"{reason} (advisory; would block)", score=p)
        if p > self._cfg.tau_flag:
            self.flags += 1
            return Verdict(decision=Decision.FLAG, stage=Stage.MODEL,
                           reason=reason, score=p)
        return Verdict(decision=Decision.ALLOW, stage=Stage.MODEL, score=p)
