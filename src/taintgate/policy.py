"""Deterministic YAML-configured policy evaluation for tool calls."""

from dataclasses import dataclass
from pathlib import Path

import yaml

from taintgate.provenance import ProvenanceExplanation, Segment, explain


ALLOW = "ALLOW"
BLOCK = "BLOCK"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"

SEND_TOOLS = frozenset({"send_email", "http_post", "send_message"})
IRREVERSIBLE_TOOLS = frozenset({"delete_file", "purchase", "exec"})
PERSISTENCE_TOOLS = frozenset({"memory_save", "write_file"})
DESTINATION_ARGUMENTS = ("to", "recipient", "url", "destination")
POLICY_IDS = frozenset({"P1", "P2", "P3", "P4", "P5", "P6"})
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"


@dataclass(frozen=True)
class ToolCall:
    tool: str
    arguments: dict[str, Segment]
    initiated_by: Segment
    user_authorized_tools: frozenset[str]
    user_explicit_recipients: frozenset[str]


@dataclass(frozen=True)
class Decision:
    action: str
    fired_policies: tuple[str, ...]
    reasons: tuple[str, ...]
    taint_paths: dict[str, ProvenanceExplanation]
    redaction_targets: tuple[str, ...] = ()


def _is_untrusted(segment: Segment) -> bool:
    return bool(segment.tainted_by) or (
        segment.trust == "untrusted" and not segment.tainted_by
    )


def load_policy(path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, bool]:
    """Load and validate enabled flags for P1 through P6 from YAML."""

    with Path(path).open("r", encoding="utf-8") as policy_file:
        document = yaml.safe_load(policy_file)

    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ValueError("policy YAML must contain a 'rules' list")

    enabled: dict[str, bool] = {}
    for rule in document["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("each policy rule must be a mapping")
        policy_id = rule.get("id")
        state = rule.get("enabled")
        if policy_id not in POLICY_IDS:
            raise ValueError(f"unknown policy id: {policy_id!r}")
        if not isinstance(state, bool):
            raise ValueError(f"policy {policy_id} must have a boolean enabled value")
        if policy_id in enabled:
            raise ValueError(f"duplicate policy id: {policy_id}")
        enabled[policy_id] = state

    missing = POLICY_IDS - enabled.keys()
    if missing:
        raise ValueError(f"missing policy ids: {', '.join(sorted(missing))}")
    return enabled


class PolicyEngine:
    def __init__(self, policy_path: str | Path = DEFAULT_POLICY_PATH) -> None:
        self.enabled_rules = load_policy(policy_path)

    def evaluate(self, call: ToolCall) -> Decision:
        """Evaluate every enabled policy and resolve the result by severity."""

        fired: list[str] = []
        reasons: list[str] = []
        redaction_targets: list[str] = []
        destinations = [
            call.arguments[name]
            for name in DESTINATION_ARGUMENTS
            if name in call.arguments
        ]

        def fire(policy_id: str, reason: str) -> None:
            fired.append(policy_id)
            reasons.append(reason)

        if self.enabled_rules["P1"] and _is_untrusted(call.initiated_by):
            if call.tool not in call.user_authorized_tools:
                fire("P1", "Untrusted content initiated a tool not authorized by the user.")

        if self.enabled_rules["P2"] and call.tool in SEND_TOOLS:
            if any(_is_untrusted(destination) for destination in destinations):
                fire("P2", "An untrusted value determines a sending tool's destination.")

        sensitive_arguments = {
            name: segment
            for name, segment in call.arguments.items()
            if segment.labels.intersection({"private", "secret"})
        }
        destination_is_explicit = bool(destinations) and all(
            destination.text in call.user_explicit_recipients
            for destination in destinations
        )
        if self.enabled_rules["P3"] and call.tool in SEND_TOOLS:
            if sensitive_arguments and not destination_is_explicit:
                fire("P3", "Private or secret data would be sent to a non-explicit destination.")

        if self.enabled_rules["P4"] and call.tool in IRREVERSIBLE_TOOLS:
            if any(_is_untrusted(argument) for argument in call.arguments.values()):
                fire("P4", "An irreversible tool has an argument tainted by untrusted content.")

        if self.enabled_rules["P5"] and call.tool in PERSISTENCE_TOOLS:
            content = call.arguments.get("content")
            if content is not None and _is_untrusted(content):
                fire("P5", "Untrusted content cannot be persisted in instruction form.")

        has_block = "P1" in fired or "P2" in fired or "P3" in fired or "P5" in fired
        if self.enabled_rules["P6"] and not has_block and call.tool in SEND_TOOLS:
            if destination_is_explicit:
                for name, segment in call.arguments.items():
                    if "secret" in segment.labels:
                        redaction_targets.append(name)
                if redaction_targets:
                    fire("P6", "Secret-labeled arguments may be sent after masking.")

        if any(policy_id in fired for policy_id in ("P1", "P2", "P3", "P5")):
            action = BLOCK
        elif "P4" in fired:
            action = REQUIRE_APPROVAL
        elif "P6" in fired:
            action = ALLOW_WITH_REDACTION
        else:
            action = ALLOW

        taint_paths = {
            "initiated_by": explain(call.initiated_by),
            **{name: explain(segment) for name, segment in call.arguments.items()},
        }
        return Decision(
            action=action,
            fired_policies=tuple(fired),
            reasons=tuple(reasons),
            taint_paths=taint_paths,
            redaction_targets=tuple(redaction_targets),
        )
