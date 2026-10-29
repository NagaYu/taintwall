"""Deterministic provenance attribution for free-form LLM tool arguments."""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Sequence

from taintwall.llm_client import ToolCallProposal
from taintwall.provenance import Origin, Segment, derive


DESTINATION_NAMES = frozenset({"to", "url", "recipient", "destination"})
EMAIL_PATTERN = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")
URL_PATTERN = re.compile(r"(?i)https?://[^\s<>\"']+")
ACCOUNT_NUMBER_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){8,17}\d(?!\d)")
API_KEY_PATTERN = re.compile(
    r"(?i)(?:\bsk-[A-Za-z0-9_-]{12,}\b|\b(?:api[_ -]?key|token)\s*[:=]\s*[A-Za-z0-9._-]{8,})"
)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}'\""


@dataclass(frozen=True)
class UserIntent:
    authorized_tools: frozenset[str]
    explicit_recipients: frozenset[str]


def normalize(text: str) -> str:
    """NFKC-normalize, lowercase, and remove whitespace and Unicode punctuation."""

    normalized = unicodedata.normalize("NFKC", text).lower()
    return "".join(
        character
        for character in normalized
        if not character.isspace() and not unicodedata.category(character).startswith("P")
    )


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _extract_addresses_and_urls(text: str) -> set[str]:
    entities = {match.group(0).lower() for match in EMAIL_PATTERN.finditer(text)}
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(TRAILING_URL_PUNCTUATION).lower()
        if url:
            entities.add(url)
    return entities


def _is_destination_argument(name: str, value: str) -> bool:
    return name.lower() in DESTINATION_NAMES or bool(_extract_addresses_and_urls(value))


def _is_untrusted(segment: Segment) -> bool:
    return bool(segment.tainted_by) or segment.trust == "untrusted"


def _segment_id(proposal: ToolCallProposal, argument_name: str, value: str) -> str:
    digest = hashlib.sha256(
        f"{proposal.tool}\0{argument_name}\0{value}".encode("utf-8")
    ).hexdigest()[:12]
    return f"llm-argument:{proposal.tool}:{argument_name}:{digest}"


def _matching_segments(
    value: str,
    argument_name: str,
    visible_segments: Sequence[Segment],
) -> list[Segment]:
    normalized_value = normalize(value)
    destination_argument = _is_destination_argument(argument_name, value)
    value_entities = _extract_addresses_and_urls(value) if destination_argument else set()
    matches: list[Segment] = []

    for segment in visible_segments:
        normalized_text = normalize(segment.text)
        direct_match = (
            len(normalized_value) >= 4
            and bool(normalized_text)
            and (normalized_value in normalized_text or normalized_text in normalized_value)
        )
        entity_match = False
        if destination_argument and value_entities:
            entity_match = bool(value_entities.intersection(_extract_addresses_and_urls(segment.text)))
        if direct_match or entity_match:
            matches.append(segment)
    return matches


def _inferred_labels(value: str) -> frozenset[str]:
    labels: set[str] = set()
    if ACCOUNT_NUMBER_PATTERN.search(value):
        labels.add("private")
    if API_KEY_PATTERN.search(value):
        labels.add("secret")
    return frozenset(labels)


def attribute_arguments(
    proposal: ToolCallProposal,
    visible_segments: Sequence[Segment],
) -> dict[str, Segment]:
    """Attach deterministic provenance to each proposed argument value."""

    result: dict[str, Segment] = {}
    untrusted_segments = [segment for segment in visible_segments if _is_untrusted(segment)]

    for argument_name in sorted(proposal.arguments):
        text = _stringify(proposal.arguments[argument_name])
        matching = _matching_segments(text, argument_name, visible_segments)
        segment_id = _segment_id(proposal, argument_name, text)

        if matching:
            output_origin = (
                Origin.TOOL_OUTPUT
                if any(_is_untrusted(segment) for segment in matching)
                else Origin.USER
            )
            attributed = derive(
                new_text=text,
                sources=matching,
                new_id=segment_id,
                origin=output_origin,
            )
        elif _is_destination_argument(argument_name, text):
            attributed = derive(
                new_text=text,
                sources=untrusted_segments,
                new_id=segment_id,
                origin=Origin.TOOL_OUTPUT,
            )
        else:
            attributed = Segment(
                id=segment_id,
                text=text,
                origin=Origin.USER,
                labels=_inferred_labels(text),
            )

        result[argument_name] = attributed
    return result


def plan_segment(
    step_segments: Sequence[Sequence[Segment]],
    step_index: int,
) -> Segment:
    """Build an initiator segment from the user prompt and all context seen by a step."""

    if step_index < 0 or step_index >= len(step_segments):
        raise IndexError("step_index is outside the available step segment history")

    unique_sources: list[Segment] = []
    seen_ids: set[str] = set()
    for step in step_segments[: step_index + 1]:
        for segment in step:
            if segment.id not in seen_ids:
                unique_sources.append(segment)
                seen_ids.add(segment.id)

    is_untrusted = any(_is_untrusted(segment) for segment in unique_sources)
    return derive(
        new_text=f"LLM plan at step {step_index + 1}",
        sources=unique_sources,
        new_id=f"llm-plan:step-{step_index + 1}",
        origin=Origin.TOOL_OUTPUT if is_untrusted else Origin.USER,
    )
