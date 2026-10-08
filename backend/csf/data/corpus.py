"""Corpus loading, normalisation, deduplication and leakage-safe splitting.

Why this module is the most important one in the evaluation
------------------------------------------------------------
The transformer-WAF literature reports F1 scores of 99.5–99.7% on CSIC 2010.
Those numbers are very likely inflated by *leakage*: CSIC 2010 is
auto-generated traffic against a single application, built from a small set of
templates with substituted parameter values. A random row split puts the same
template on both sides of the split, so the model is tested on paraphrases of
its training data and learns the generator, not the attack.

This module makes that failure mode hard to commit by accident:

* **Normalised-form deduplication.** Requests that differ only in session
  cookie, ordering, or percent-encoding collapse to one.
* **Template-aware grouping.** A request's *shape* (endpoint + parameter names
  + value types) is its group key. Splits are made over GROUPS, never rows, so
  every request sharing a template lands on one side.
* **Source-aware splitting.** Corpora never mix across a split boundary when
  used for cross-corpus evaluation.
* **A frozen holdout** whose hash is recorded, so "we never trained on it" is
  checkable rather than asserted.

Nothing here is clever. It is just the discipline the literature mostly skips.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

__all__ = [
    "AttackClass",
    "CorpusStats",
    "Request",
    "Split",
    "deduplicate",
    "group_key",
    "split_by_group",
]


class AttackClass(StrEnum):
    BENIGN = "benign"
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    TRAVERSAL = "traversal"
    OTHER = "other"


@dataclass(slots=True)
class Request:
    """One labelled HTTP request."""

    method: str
    path: str
    query: str
    headers: dict[str, list[str]] = field(default_factory=dict)
    body: str = ""
    label: AttackClass = AttackClass.BENIGN
    #: Which corpus this came from. Split boundaries respect this.
    source: str = "unknown"
    #: Free-form provenance, e.g. the file and line it was parsed from.
    origin: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["label"] = str(self.label)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Request:
        d = dict(d)
        d["label"] = AttackClass(d["label"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Normalisation for deduplication
# ---------------------------------------------------------------------------

#: Headers that vary per request without changing what the request *means*.
#: Keeping them would defeat deduplication entirely: every CSIC request has a
#: unique JSESSIONID, so no two requests would ever look like duplicates.
_VOLATILE_HEADERS = frozenset(
    {"cookie", "date", "if-modified-since", "if-none-match", "authorization",
     "x-request-id", "x-correlation-id", "referer", "content-length"}
)


def _canonical_pairs(blob: str) -> list[tuple[str, str]]:
    pairs = []
    for chunk in blob.split("&"):
        if not chunk:
            continue
        key, sep, value = chunk.partition("=")
        pairs.append((unquote_plus(key), unquote_plus(value) if sep else ""))
    return pairs


def normalised_form(request: Request) -> str:
    """A canonical string for duplicate detection.

    Percent-decodes, sorts parameters, and drops volatile headers, so two
    requests that differ only in encoding, ordering or session identity
    produce the same string.
    """
    query_pairs = sorted(_canonical_pairs(request.query))
    body_pairs = sorted(_canonical_pairs(request.body)) if "=" in request.body else []
    body_repr = "" if body_pairs else unquote_plus(request.body)
    stable_headers = sorted(
        (k.lower(), ",".join(v))
        for k, v in request.headers.items()
        if k.lower() not in _VOLATILE_HEADERS
    )
    return json.dumps(
        [request.method, request.path, query_pairs, body_pairs, body_repr,
         stable_headers],
        sort_keys=True, ensure_ascii=False,
    )


def content_hash(request: Request) -> str:
    return hashlib.sha256(normalised_form(request).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Template-aware grouping — the actual leakage defence
# ---------------------------------------------------------------------------

_DIGITS = re.compile(r"\d+")


def _value_shape(value: str) -> str:
    """Collapse a value to its *type*, discarding the specific content.

    "55", "100" and "3" all become "int"; the point is that requests differing
    only in a substituted parameter value come from the same generator
    template and must not be split apart.
    """
    if not value:
        return "empty"
    if value.isdigit():
        return "int"
    if _DIGITS.fullmatch(value.replace(".", "", 1)):
        return "float"
    if len(value) > 40:
        return "long"
    return "str"


#: Sources that are curated payload LISTS rather than generated traffic.
#: The distinction matters for how we group (see group_key).
PAYLOAD_LIST_SOURCES = frozenset({
    "libinjection-bypass", "sqlifuzzer", "jbrofuzz-sqli", "jbrofuzz-xss",
    "xss-ismailtasdelen", "xssdb", "xss-packetstorm", "cmdi-windows",
    "cmdi-unix", "traversal",
})

_SKELETON_STRIP = re.compile(r"[\s\d]+")


def _payload_skeleton(value: str) -> str:
    """A coarse shape for a hand-written payload, for near-duplicate grouping.

    Lowercases, removes digits and whitespace, and truncates. ``<img src=x
    onerror=alert(1)>`` and ``<img src=y onerror=alert(99)>`` collapse to the
    same skeleton, so they cannot straddle a split; genuinely different
    payloads keep different skeletons and split normally.
    """
    stripped = _SKELETON_STRIP.sub("", value.lower())
    return hashlib.sha256(stripped[:64].encode()).hexdigest()[:16]


def group_key(request: Request) -> str:
    """The group a request belongs to.

    Two regimes, because the leakage risk differs:

    **Generated traffic** (CSIC 2010 and similar) is built from a handful of
    templates with substituted values, so the group is the TEMPLATE: endpoint,
    parameter names, and parameter value *types*. Splitting by row would put
    paraphrases of the same template on both sides.

    **Curated payload lists** have no templates — each entry is a distinct
    hand-written payload — but they do contain near-duplicates. Grouping them
    by template would be worse than useless: every payload in a list shares
    one synthetic endpoint and parameter, so the whole list collapses into a
    single group and the entire class lands in one split. Measured: this put
    ZERO command-injection samples in the test set. For these we group by
    payload *skeleton*, so near-duplicates stay together and distinct
    payloads split.
    """
    if request.source in PAYLOAD_LIST_SOURCES:
        values = [v for _, v in _canonical_pairs(request.query)]
        skeleton = _payload_skeleton(values[0] if values else request.path)
        return f"{request.source}|payload|{skeleton}"
    return _template_key(request)


def _template_key(request: Request) -> str:
    """Template group for generated traffic.

    Splits are made over these groups, never over rows. Two requests with the
    same endpoint, the same parameter names and the same value *types* are
    treated as the same template, because in a generated corpus they almost
    certainly are.

    Path components that look like identifiers are collapsed too, so
    ``/product/12`` and ``/product/4567`` share a group.
    """
    path = "/".join(
        "{id}" if seg.isdigit() or _DIGITS.search(seg) and len(seg) > 8 else seg
        for seg in request.path.split("/")
    )
    params = sorted(
        f"{k}:{_value_shape(v)}" for k, v in _canonical_pairs(request.query)
    )
    body_params = sorted(
        f"{k}:{_value_shape(v)}" for k, v in _canonical_pairs(request.body)
    ) if "=" in request.body else []
    return f"{request.source}|{request.method}|{path}|{','.join(params)}|{','.join(body_params)}"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CorpusStats:
    total_in: int = 0
    exact_duplicates: int = 0
    kept: int = 0
    by_label: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    groups: int = 0
    #: Labels that disagreed for the same normalised content. A request that
    #: appears as both benign and attack is a corpus defect, and silently
    #: keeping one of them would poison training.
    label_conflicts: int = 0

    def render(self) -> str:
        lines = [
            f"  input           {self.total_in}",
            f"  exact dupes     {self.exact_duplicates}",
            f"  label conflicts {self.label_conflicts}",
            f"  kept            {self.kept}",
            f"  groups          {self.groups}",
            "  by label:       " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.by_label.items())),
            "  by source:      " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.by_source.items())),
        ]
        return "\n".join(lines)


def deduplicate(requests: list[Request]) -> tuple[list[Request], CorpusStats]:
    """Drop exact duplicates by normalised form and report conflicts.

    A normalised form appearing with two different labels is dropped entirely
    rather than arbitrarily resolved: we cannot know which label is right, and
    guessing teaches the model noise.
    """
    stats = CorpusStats(total_in=len(requests))
    by_hash: dict[str, Request] = {}
    labels_seen: dict[str, set[AttackClass]] = defaultdict(set)

    for request in requests:
        digest = content_hash(request)
        labels_seen[digest].add(request.label)
        if digest in by_hash:
            stats.exact_duplicates += 1
            continue
        by_hash[digest] = request

    kept = []
    for digest, request in by_hash.items():
        if len(labels_seen[digest]) > 1:
            stats.label_conflicts += 1
            continue
        kept.append(request)

    stats.kept = len(kept)
    stats.by_label = dict(Counter(str(r.label) for r in kept))
    stats.by_source = dict(Counter(r.source for r in kept))
    stats.groups = len({group_key(r) for r in kept})
    return kept, stats


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Split:
    train: list[Request] = field(default_factory=list)
    val: list[Request] = field(default_factory=list)
    test: list[Request] = field(default_factory=list)

    def summary(self) -> str:
        def describe(name: str, rows: list[Request]) -> str:
            counts = Counter(str(r.label) for r in rows)
            return f"  {name:<6} n={len(rows):<7} " + " ".join(
                f"{k}={v}" for k, v in sorted(counts.items()))
        return "\n".join([
            describe("train", self.train),
            describe("val", self.val),
            describe("test", self.test),
        ])


def split_by_group(
    requests: list[Request],
    ratios: tuple[float, float, float] = (0.7, 0.15, 0.15),
    seed: int = 20261001,
) -> Split:
    """Split over template groups, never over rows — stratified by label.

    Every request sharing a ``group_key`` lands in exactly one split. That is
    the difference between measuring generalisation and measuring
    memorisation of a generator's templates.

    **Stratification matters as much as grouping.** A first implementation
    assigned groups greedily without regard to label and produced a test set
    containing ZERO command-injection samples and a validation set containing
    one SQLi sample. Per-class recall is the metric that stops a weak class
    hiding behind a strong one, so a split that cannot measure a class is
    worthless for the very thing it exists to check.

    Groups are therefore bucketed per label, shuffled deterministically, and
    assigned within each label stratum to whichever split is furthest below
    its target share for that label.
    """
    if not 0.999 <= sum(ratios) <= 1.001:
        raise ValueError(f"ratios must sum to 1.0, got {sum(ratios)}")

    groups: dict[str, list[Request]] = defaultdict(list)
    for request in requests:
        groups[group_key(request)].append(request)

    # A group's label is the majority label of its members. Groups are
    # template-shaped, so in practice they are label-pure; taking the majority
    # keeps the function total if they are not.
    by_label: dict[AttackClass, list[str]] = defaultdict(list)
    for key, rows in groups.items():
        label = Counter(r.label for r in rows).most_common(1)[0][0]
        by_label[label].append(key)

    split = Split()
    buckets = [split.train, split.val, split.test]
    # Deterministic shuffling for reproducible splits — not security.
    rng = random.Random(seed)  # noqa: S311

    for label in sorted(by_label, key=str):
        keys = sorted(by_label[label])
        rng.shuffle(keys)
        counts = [0, 0, 0]
        for key in keys:
            rows = groups[key]
            total = sum(counts) or 1
            deficits = [ratios[i] - counts[i] / total for i in range(3)]
            target = deficits.index(max(deficits))
            buckets[target].extend(rows)
            counts[target] += len(rows)

    return split


def split_warnings(requests: list[Request], min_groups: int = 3) -> list[str]:
    """Report classes that cannot be meaningfully split.

    A class whose members all collapse into one or two groups cannot be
    spread across train/val/test, so one split will be empty for it and that
    class's recall becomes unmeasurable. This must be reported loudly rather
    than discovered later as a suspiciously perfect score.

    It is a corpus problem, not a splitter bug: the fix is more diverse source
    data for that class, not a weaker grouping rule.
    """
    per_label: dict[AttackClass, set[str]] = defaultdict(set)
    for request in requests:
        per_label[request.label].add(group_key(request))

    warnings = []
    for label, groups in sorted(per_label.items(), key=lambda kv: str(kv[0])):
        if len(groups) < min_groups:
            warnings.append(
                f"class {label} has only {len(groups)} distinct group(s); "
                f"it cannot be split across 3 sets and at least one split "
                f"will contain none of it. Add more diverse sources for "
                f"{label} rather than weakening the grouping rule."
            )
    return warnings


def verify_no_leakage(split: Split) -> list[str]:
    """Return a list of leakage problems. Empty means clean.

    Checks both content-level and template-level overlap. A split that passes
    content dedup but shares templates is still leaking.
    """
    problems = []
    sets = {
        "train": split.train, "val": split.val, "test": split.test,
    }
    hashes = {name: {content_hash(r) for r in rows} for name, rows in sets.items()}
    groups = {name: {group_key(r) for r in rows} for name, rows in sets.items()}

    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        shared_rows = hashes[a] & hashes[b]
        if shared_rows:
            problems.append(
                f"{len(shared_rows)} identical requests appear in both {a} and {b}"
            )
        shared_groups = groups[a] & groups[b]
        if shared_groups:
            problems.append(
                f"{len(shared_groups)} template groups span {a} and {b}; "
                "the split is measuring memorisation, not generalisation"
            )
    return problems


def freeze(rows: list[Request], path: Path) -> str:
    """Write a split to disk and return its content hash.

    The hash is what makes "we never trained on the holdout" checkable rather
    than merely asserted.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    serialised = "\n".join(
        json.dumps(r.to_dict(), sort_keys=True, ensure_ascii=False) for r in rows
    )
    path.write_text(serialised)
    return hashlib.sha256(serialised.encode()).hexdigest()
