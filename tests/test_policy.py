from pathlib import Path

from taintwall.policy import (
    ALLOW,
    ALLOW_WITH_REDACTION,
    BLOCK,
    REQUIRE_APPROVAL,
    PolicyEngine,
    ToolCall,
)
from taintwall.provenance import Origin, Segment


def segment(
    segment_id: str,
    *,
    origin: Origin = Origin.USER,
    labels: set[str] | None = None,
    tainted_by: frozenset[str] = frozenset(),
    text: str | None = None,
) -> Segment:
    return Segment(
        id=segment_id,
        text=text or segment_id,
        origin=origin,
        labels=labels or set(),
        tainted_by=tainted_by,
    )


def call(
    tool: str,
    arguments: dict[str, Segment] | None = None,
    *,
    initiated_by: Segment | None = None,
    authorized: frozenset[str] | None = None,
    recipients: frozenset[str] = frozenset(),
) -> ToolCall:
    return ToolCall(
        tool=tool,
        arguments=arguments or {},
        initiated_by=initiated_by or segment("user-request"),
        user_authorized_tools=authorized if authorized is not None else frozenset({tool}),
        user_explicit_recipients=recipients,
    )


def test_p1_blocks_untrusted_unauthorized_tool_and_allows_authorized_tool() -> None:
    engine = PolicyEngine()
    untrusted_initiator = segment("email-root", origin=Origin.EMAIL)

    blocked = engine.evaluate(
        call("exec", initiated_by=untrusted_initiator, authorized=frozenset())
    )
    allowed = engine.evaluate(
        call("exec", initiated_by=untrusted_initiator, authorized=frozenset({"exec"}))
    )

    assert blocked.action == BLOCK
    assert "P1" in blocked.fired_policies
    assert allowed.action == ALLOW
    assert "P1" not in allowed.fired_policies


def test_p2_blocks_untrusted_destination_and_allows_trusted_destination() -> None:
    engine = PolicyEngine()
    blocked = engine.evaluate(
        call(
            "send_email",
            {"to": segment("injected-to", origin=Origin.EMAIL, text="attacker@example.test")},
        )
    )
    allowed = engine.evaluate(
        call("send_email", {"to": segment("user-to", text="friend@example.test")})
    )

    assert blocked.action == BLOCK
    assert "P2" in blocked.fired_policies
    assert allowed.action == ALLOW
    assert "P2" not in allowed.fired_policies


def test_p2_does_not_block_untrusted_repetition_of_user_explicit_destination() -> None:
    recipient = "ops@internal.example"
    result = PolicyEngine().evaluate(
        call(
            "send_email",
            {
                "to": segment(
                    "runbook-recipient",
                    origin=Origin.FILE,
                    text=recipient,
                )
            },
            recipients=frozenset({recipient}),
        )
    )

    assert result.action == ALLOW
    assert "P2" not in result.fired_policies


def test_p2_still_blocks_untrusted_destination_outside_explicit_set() -> None:
    recipient = "attacker@example.test"
    result = PolicyEngine().evaluate(
        call(
            "send_email",
            {"to": segment("runbook-recipient", origin=Origin.FILE, text=recipient)},
            recipients=frozenset({"ops@internal.example"}),
        )
    )

    assert result.action == BLOCK
    assert "P2" in result.fired_policies


def test_p3_blocks_sensitive_data_to_non_explicit_recipient_and_allows_explicit_one() -> None:
    engine = PolicyEngine()
    secret_body = segment("secret-body", labels={"secret"}, text="private details")
    blocked = engine.evaluate(
        call(
            "send_email",
            {
                "to": segment("recipient", text="other@example.test"),
                "body": secret_body,
            },
        )
    )
    allowed = engine.evaluate(
        call(
            "send_email",
            {
                "to": segment("recipient", text="friend@example.test"),
                "body": secret_body,
            },
            recipients=frozenset({"friend@example.test"}),
        )
    )

    assert blocked.action == BLOCK
    assert "P3" in blocked.fired_policies
    assert allowed.action == ALLOW_WITH_REDACTION
    assert "P3" not in allowed.fired_policies


def test_p4_requires_approval_for_untrusted_irreversible_argument() -> None:
    engine = PolicyEngine()
    blocked = engine.evaluate(
        call("purchase", {"item": segment("item-root", origin=Origin.WEB)})
    )
    allowed = engine.evaluate(call("purchase", {"item": segment("item-user")}))

    assert blocked.action == REQUIRE_APPROVAL
    assert "P4" in blocked.fired_policies
    assert allowed.action == ALLOW
    assert "P4" not in allowed.fired_policies


def test_p5_blocks_untrusted_persisted_content_and_allows_trusted_content() -> None:
    engine = PolicyEngine()
    blocked = engine.evaluate(
        call("memory_save", {"content": segment("instruction", origin=Origin.FILE)})
    )
    allowed = engine.evaluate(call("memory_save", {"content": segment("user-note")}))

    assert blocked.action == BLOCK
    assert "P5" in blocked.fired_policies
    assert allowed.action == ALLOW
    assert "P5" not in allowed.fired_policies


def test_p6_redacts_secret_argument_for_explicit_destination() -> None:
    engine = PolicyEngine()
    result = engine.evaluate(
        call(
            "send_email",
            {
                "to": segment("recipient", text="friend@example.test"),
                "body": segment("secret-body", labels={"secret"}),
            },
            recipients=frozenset({"friend@example.test"}),
        )
    )

    assert result.action == ALLOW_WITH_REDACTION
    assert "P6" in result.fired_policies
    assert result.redaction_targets == ("body",)


def test_secret_data_to_explicit_recipient_without_secret_label_does_not_fire_p6() -> None:
    engine = PolicyEngine()
    result = engine.evaluate(
        call(
            "send_email",
            {
                "to": segment("recipient", text="friend@example.test"),
                "body": segment("ordinary-body", labels={"private"}),
            },
            recipients=frozenset({"friend@example.test"}),
        )
    )

    assert result.action == ALLOW
    assert "P6" not in result.fired_policies


def test_user_explicit_recipient_with_unlabeled_email_is_allowed() -> None:
    result = PolicyEngine().evaluate(
        call(
            "send_email",
            {
                "to": segment("recipient", text="friend@example.test"),
                "body": segment("ordinary-body", text="Hello"),
            },
            recipients=frozenset({"friend@example.test"}),
        )
    )

    assert result.action == ALLOW
    assert result.fired_policies == ()


def test_p2_can_be_disabled_in_a_temporary_policy_file(tmp_path: Path) -> None:
    default_policy = Path(__file__).parents[1] / "policies" / "default.yaml"
    temporary_policy = tmp_path / "policy.yaml"
    text = default_policy.read_text(encoding="utf-8")
    text = text.replace("  - id: P2\n    enabled: true", "  - id: P2\n    enabled: false")
    temporary_policy.write_text(text, encoding="utf-8")

    result = PolicyEngine(temporary_policy).evaluate(
        call(
            "send_email",
            {"to": segment("injected-to", origin=Origin.EMAIL)},
        )
    )

    assert result.action != BLOCK
    assert "P2" not in result.fired_policies


def test_block_has_priority_when_p1_and_p4_both_fire() -> None:
    result = PolicyEngine().evaluate(
        call(
            "exec",
            {"command": segment("command-root", origin=Origin.FILE)},
            initiated_by=segment("initiator-root", origin=Origin.EMAIL),
            authorized=frozenset(),
        )
    )

    assert "P1" in result.fired_policies
    assert "P4" in result.fired_policies
    assert result.action == BLOCK
