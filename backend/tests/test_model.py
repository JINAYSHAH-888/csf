"""S3 learned stage: feature contract, degradation, thresholds."""

from __future__ import annotations

from pathlib import Path

import pytest

from csf.extraction import extract
from csf.gateway import Decision, Stage
from csf.model.detector import S3Config, S3LearnedDetector
from csf.model.features import MAX_DOC_CHARS, request_document


def H(*pairs):
    return [(k.encode(), v.encode()) for k, v in pairs]


def sample(query=b"q=test", body=b"", path="/api/items"):
    headers = H(("host", "app.local"), ("user-agent", "curl/8"))
    if body:
        headers.append((b"content-type", b"application/json"))
    return extract("GET", path, query, headers, body)


# -- the feature contract (train/serve skew) ------------------------------


def test_document_uses_the_shared_candidate_serialisation():
    """The training pipeline and the gateway must build the model's input
    the same way, or the model is served inputs it never saw and the failure
    is silent. One definition, imported by both."""
    result = sample(query=b"q=lamp&page=2")
    doc = request_document(result)
    for candidate in result.candidates:
        if candidate.content_type not in ("number", "bool", "null"):
            assert candidate.model_input() in doc


def test_document_is_deterministic():
    """The same request must always produce the same string regardless of
    dict ordering, or training and serving diverge for one request in many."""
    a = request_document(sample(query=b"b=2&a=1&c=3"))
    b = request_document(sample(query=b"b=2&a=1&c=3"))
    assert a == b


def test_document_is_bounded():
    """An attacker controls request size; the feature string must be capped
    before it reaches the vectoriser."""
    big = b"q=" + b"A" * 50_000
    doc = request_document(sample(query=big))
    assert len(doc) <= MAX_DOC_CHARS + 64
    assert "[TRUNCATED]" in doc


def test_inert_types_are_excluded():
    doc = request_document(extract(
        "POST", "/", b"", H(("content-type", "application/json")),
        b'{"n":123,"flag":true,"nil":null,"s":"text"}'))
    assert "text" in doc
    assert "[TYPE] number" not in doc
    assert "[TYPE] bool" not in doc


# -- degradation ----------------------------------------------------------


async def test_missing_model_degrades_rather_than_failing():
    detector = S3LearnedDetector(S3Config(model_path=Path("/nonexistent.pkl")))
    assert not detector.healthy
    verdict = await detector.evaluate(sample())
    assert verdict.decision is Decision.ALLOW
    assert "s3_unavailable" in verdict.reason


async def test_no_model_path_degrades():
    detector = S3LearnedDetector(S3Config(model_path=None))
    verdict = await detector.evaluate(sample())
    assert verdict.decision is Decision.ALLOW
    assert "s3_unavailable" in verdict.reason


async def test_fail_closed_blocks_when_model_unavailable():
    detector = S3LearnedDetector(
        S3Config(model_path=Path("/nonexistent.pkl"), fail_open=False))
    verdict = await detector.evaluate(sample())
    assert verdict.decision is Decision.BLOCK
    assert "fail_closed" in verdict.reason


async def test_broken_model_degrades_rather_than_raising():
    class Exploding:
        def predict_proba(self, docs):
            raise RuntimeError("boom")

    detector = S3LearnedDetector(S3Config(model_path=None))
    detector._model = Exploding()
    verdict = await detector.evaluate(sample())
    assert verdict.decision is Decision.ALLOW
    assert detector.unavailable_count >= 1


# -- thresholds -----------------------------------------------------------


class FixedModel:
    def __init__(self, p: float) -> None:
        self.p = p

    def predict_proba(self, docs):
        return [[1 - self.p, self.p] for _ in docs]


@pytest.mark.parametrize(("probability", "expected"), [
    (0.10, Decision.ALLOW),
    (0.80, Decision.ALLOW),
    (0.85, Decision.FLAG),
    (0.99, Decision.BLOCK),
    (1.00, Decision.BLOCK),
])
async def test_threshold_bands(probability, expected):
    # advisory_only=False to exercise the raw bands; the advisory downgrade is
    # tested separately below.
    detector = S3LearnedDetector(S3Config(model_path=None, advisory_only=False))
    detector._model = FixedModel(probability)
    verdict = await detector.evaluate(sample())
    assert verdict.decision is expected
    assert verdict.stage is Stage.MODEL


async def test_reason_carries_the_probability():
    """An operator must be able to see why S3 blocked."""
    detector = S3LearnedDetector(S3Config(model_path=None))
    detector._model = FixedModel(0.9987)
    verdict = await detector.evaluate(sample())
    assert "0.998" in verdict.reason


def test_trained_artifact_loads_if_present():
    """Smoke test against the real artifact when training has been run."""
    artifact = Path(__file__).parent.parent.parent / "model" / "artifacts" / "s3_model.pkl"
    if not artifact.exists():
        pytest.skip("no trained artifact; run scripts/train_s3.py")
    detector = S3LearnedDetector(S3Config(model_path=artifact))
    assert detector.healthy
    benign = detector.predict(sample(query=b"q=desk+lamp"))
    attack = detector.predict(sample(query=b"id=1%27+OR+%271%27%3D%271"))
    assert benign.available and attack.available
    assert 0.0 <= benign.probability <= 1.0
    assert 0.0 <= attack.probability <= 1.0


# -- the generalisation guard --------------------------------------------


def test_s3_refuses_to_enable_without_the_application_flag():
    """Measured ROC-AUC 0.9993 in-corpus vs 0.5250 on an unseen application.
    Enabling S3 on an application it was not trained on would classify
    ordinary traffic as hostile, so the config refuses it."""
    from csf.config import S3Settings

    with pytest.raises(ValueError, match="trained_on_this_application"):
        S3Settings(enabled=True, model_path="/m.pkl").validate()

    S3Settings(enabled=True, model_path="/m.pkl",
               trained_on_this_application=True).validate()


def test_s3_is_disabled_by_default():
    from csf.config import S3Settings

    assert S3Settings().enabled is False


@pytest.mark.parametrize(("flag", "block"), [(0.0, 0.9), (0.9, 0.5), (0.5, 1.5)])
def test_s3_threshold_ordering_is_enforced(flag, block):
    from csf.config import S3Settings

    with pytest.raises(ValueError, match="thresholds"):
        S3Settings(enabled=True, model_path="/m.pkl",
                   trained_on_this_application=True,
                   tau_flag=flag, tau_block=block).validate()


# -- advisory-only safety bound (ADR-0017) --------------------------------


async def test_advisory_only_downgrades_block_to_flag():
    """Default advisory_only=True: S3 may FLAG but never BLOCK, so a
    non-transferring model cannot take the application down."""
    detector = S3LearnedDetector(S3Config(model_path=None))  # default advisory
    detector._model = FixedModel(1.0)
    verdict = await detector.evaluate(sample())
    assert verdict.decision is Decision.FLAG
    assert "would block" in verdict.reason
    assert detector.blocks == 0


async def test_advisory_default_is_on():
    assert S3Config(model_path=None).advisory_only is True


async def test_opting_out_of_advisory_allows_block():
    detector = S3LearnedDetector(S3Config(model_path=None, advisory_only=False))
    detector._model = FixedModel(1.0)
    verdict = await detector.evaluate(sample())
    assert verdict.decision is Decision.BLOCK


# -- artifact bundle format + train/serve provenance consistency (ADR-0008) --


# Module-level so they pickle (local classes cannot be pickled).
class _NovenanceEcho:
    """P(attack)=1 only if the doc has NO provenance tags, so a test can tell
    which representation the detector fed the model."""
    def predict_proba(self, docs):
        out = []
        for d in docs:
            novenance = "[ENDPOINT]" not in d and "[PARAM]" not in d
            out.append([0.0, 1.0] if novenance else [1.0, 0.0])
        return out


class _ConstModel:
    def predict_proba(self, docs):
        return [[0.2, 0.8] for _ in docs]


async def test_bundle_format_sets_provenance_from_artifact(tmp_path):
    """A format-2 bundle carries the feature contract; the detector must serve
    with the SAME provenance the model was trained on, or it is train/serve
    skew -- the failure ADR-0006 exists to prevent."""
    import pickle

    path = tmp_path / "m.pkl"
    with path.open("wb") as fh:
        pickle.dump({"format": 2, "model": _NovenanceEcho(), "provenance": False}, fh)
    det = S3LearnedDetector(S3Config(model_path=path, advisory_only=False))
    assert det._provenance is False
    # The detector must build a values-only doc (no provenance tags) -> Echo 1.0.
    assert det.predict(sample()).probability == 1.0


async def test_bare_estimator_is_treated_as_provenance(tmp_path):
    """Backward compatibility: a legacy pickle of a bare estimator loads and is
    assumed provenance-tagged."""
    import pickle

    path = tmp_path / "legacy.pkl"
    with path.open("wb") as fh:
        pickle.dump(_ConstModel(), fh)
    det = S3LearnedDetector(S3Config(model_path=path))
    assert det._provenance is True
    assert det.healthy


def test_shipped_artifact_loads_and_is_values_only():
    """The shipped artifact, if present, must be a values-only bundle (the
    cross-corpus-robust representation). Skipped if the model isn't built."""
    from pathlib import Path

    art = Path(__file__).resolve().parent.parent.parent / "model/artifacts/s3_model.pkl"
    if not art.exists():
        import pytest
        pytest.skip("s3_model.pkl not built (run scripts/train_s3.py)")
    det = S3LearnedDetector(S3Config(model_path=art))
    assert det.healthy
    assert det._provenance is False, "shipped model must be values-only (ADR-0008)"
