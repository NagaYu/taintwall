"""Deterministic provenance and taint tracking primitives."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, TypedDict


class Origin(str, Enum):
    SYSTEM = "system"
    USER = "user"
    TOOL_OUTPUT = "tool_output"
    RAG = "rag"
    FILE = "file"
    WEB = "web"
    EMAIL = "email"


TRUSTED_ORIGINS = frozenset({Origin.SYSTEM, Origin.USER})
CONFIDENTIALITY_LABELS = frozenset({"private", "secret", "pii", "public"})


@dataclass(frozen=True)
class Segment:
    """A text segment with direct provenance and sticky taint metadata."""

    id: str
    text: str
    origin: Origin
    labels: frozenset[str] = field(default_factory=frozenset)
    source_ids: tuple[str, ...] = ()
    tainted_by: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.origin, Origin):
            raise TypeError("origin must be an Origin")

        labels = frozenset(self.labels)
        invalid_labels = labels - CONFIDENTIALITY_LABELS
        if invalid_labels:
            raise ValueError(f"unsupported confidentiality labels: {sorted(invalid_labels)}")
        object.__setattr__(self, "labels", labels)
        object.__setattr__(self, "source_ids", tuple(self.source_ids))
        object.__setattr__(self, "tainted_by", frozenset(self.tainted_by))

    @property
    def trust(self) -> str:
        """Trust is derived from origin so the two cannot drift apart."""

        return "trusted" if self.origin in TRUSTED_ORIGINS else "untrusted"


def derive(
    new_text: str,
    sources: Iterable[Segment],
    new_id: str,
    *,
    origin: Origin,
) -> Segment:
    """Create a derived segment, unioning labels and preserving untrusted ancestry.

    The caller supplies the output origin. ``tainted_by`` records only root
    untrusted segment IDs: an untrusted source is added when its own
    ``tainted_by`` is empty; otherwise only its inherited roots are propagated.
    """

    source_segments = tuple(sources)
    labels = frozenset(label for source in source_segments for label in source.labels)
    tainted_ids: set[str] = set()
    for source in source_segments:
        tainted_ids.update(source.tainted_by)
        if source.trust == "untrusted" and not source.tainted_by:
            tainted_ids.add(source.id)
    tainted_by = frozenset(tainted_ids)

    return Segment(
        id=new_id,
        text=new_text,
        origin=origin,
        labels=labels,
        source_ids=tuple(source.id for source in source_segments),
        tainted_by=tainted_by,
    )


class ProvenanceExplanation(TypedDict):
    message: str
    segment_id: str
    origin: str
    trust: str
    source_ids: list[str]
    untrusted_source_ids: list[str]


def explain(segment: Segment) -> ProvenanceExplanation:
    """Return a readable explanation and structured provenance identifiers."""

    sources = ", ".join(segment.source_ids) if segment.source_ids else "none"
    untrusted_ids = set(segment.tainted_by)
    if segment.trust == "untrusted" and not segment.tainted_by:
        untrusted_ids.add(segment.id)
    ordered_untrusted_ids = sorted(untrusted_ids)
    untrusted = ", ".join(ordered_untrusted_ids) if ordered_untrusted_ids else "none"
    message = (
        f"Segment {segment.id!r} (origin={segment.origin.value}, trust={segment.trust}) "
        f"derives from [{sources}]; untrusted sources: [{untrusted}]."
    )
    return {
        "message": message,
        "segment_id": segment.id,
        "origin": segment.origin.value,
        "trust": segment.trust,
        "source_ids": list(segment.source_ids),
        "untrusted_source_ids": ordered_untrusted_ids,
    }
