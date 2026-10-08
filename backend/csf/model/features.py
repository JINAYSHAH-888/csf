"""Feature construction for S3 — shared by training and serving.

Train/serve skew is the failure this module exists to prevent
---------------------------------------------------------------
If the training pipeline and the gateway build the model's input differently,
the model is served inputs it was never trained on and **the failure is
silent**: no error, no alert, just quietly degraded detection. This was the
deciding argument for a single-language backend (ADR-0006).

So there is exactly one definition of a model input, here, and both sides
import it. The gateway does not reimplement it and the training script does
not approximate it.
"""

from __future__ import annotations

from csf.extraction import Candidate
from csf.extraction import Result as ExtractionResult

__all__ = ["MAX_DOC_CHARS", "candidate_document", "request_document"]

#: Bound on the serialised request. An attacker controls request size, so the
#: feature string must be bounded before it reaches the vectoriser
#: (threat model T4).
MAX_DOC_CHARS = 4096

#: Candidates that cannot carry injection and only add noise to the document.
_INERT_TYPES = frozenset({"number", "bool", "null"})


def candidate_document(candidate: Candidate, provenance: bool = True) -> str:
    """The model's view of one candidate value.

    With ``provenance=True`` this delegates to :meth:`Candidate.model_input`,
    the single definition of provenance tagging. WADBERT's finding that
    parameter-level modelling with provenance beats flat request text is why
    endpoint, location and parameter name are included.

    **But provenance is also a corpus fingerprint.** ``[ENDPOINT]
    /tienda1/publico/anadir.jsp [PARAM] nombre`` identifies CSIC 2010 as
    surely as a watermark. A model trained with those tags can separate
    corpora without learning anything about payloads, and then classifies an
    unseen application's ordinary traffic as hostile because it is simply not
    CSIC-shaped.

    ``provenance=False`` emits the value and its inferred type only, keeping
    the payload signal and discarding the fingerprint. Which setting is used
    must be reported with any number derived from the model.
    """
    if provenance:
        return candidate.model_input()
    return f"[TYPE] {candidate.content_type} [VALUE] {candidate.normalized}"


def request_document(extracted: ExtractionResult, max_chars: int = MAX_DOC_CHARS,
                     provenance: bool = True) -> str:
    """The model's view of a whole request.

    S3 classifies at REQUEST level rather than per candidate. The trade-off,
    stated plainly:

    * **Why request level:** attack corpora label requests, not parameters.
      Labelling every candidate of an attack request as malicious would mark
      its benign fields (``page=1``, ``sort=asc``) as attacks and poison the
      model. Picking "the attacking candidate" automatically would mean using
      S1 or S2 to choose, which makes S3's evaluation circular.
    * **What it costs:** S3 cannot say *which* parameter was malicious, so its
      audit entry is less specific than S2's. S1 and S2 still name the
      parameter, so the combined audit record is not degraded.

    Candidates are sorted by location then parameter so the document is
    deterministic: the same request must always produce the same string
    regardless of dict ordering.
    """
    parts: list[str] = []
    seen = 0
    for candidate in sorted(
        extracted.candidates,
        key=lambda c: (str(c.location), c.parameter),
    ):
        if candidate.content_type in _INERT_TYPES:
            continue
        if not candidate.normalized:
            continue
        piece = candidate_document(candidate, provenance=provenance)
        if seen + len(piece) > max_chars:
            parts.append("[TRUNCATED]")
            break
        parts.append(piece)
        seen += len(piece)
    return " ".join(parts)
