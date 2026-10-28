"""SIMULATED deterministic-agent tests measure policy enforcement, not LLM robustness."""

from taintgate.agent import PlannedAction, ScriptedAgent
from taintgate.boundary import GuardedExecutor
from taintgate.environments import EmailEnvironment, VisibleContent, WorkspaceEnvironment
from taintgate.policy import ALLOW, BLOCK, PolicyEngine
from taintgate.provenance import Origin, derive
from taintgate.tools import MockTools


def test_simulated_raw_injection_is_proposed_for_boundary_enforcement() -> None:
    """SIMULATED proposal is not protection; the boundary must enforce policy."""
    environment = EmailEnvironment()
    injection = environment.inbox[1]
    agent = ScriptedAgent()
    proposals = agent.propose(
        PlannedAction("read_file", {"path": "workspace/meeting-notes.txt"}),
        [injection],
        set(),
    )

    assert [proposal.tool for proposal in proposals] == ["read_file", "send_email"]
    assert proposals[1].initiated_by is injection.segment


def test_simulated_spotlighted_injection_is_treated_as_data() -> None:
    environment = EmailEnvironment()
    injection = environment.inbox[1]
    proposals = ScriptedAgent().propose(
        PlannedAction("read_file", {"path": "workspace/meeting-notes.txt"}),
        [injection],
        {injection.segment.id},
    )

    assert [proposal.tool for proposal in proposals] == ["read_file"]


def test_simulated_user_task_is_always_proposed_with_or_without_injection() -> None:
    environment = EmailEnvironment()
    task = PlannedAction("read_file", {"path": "workspace/meeting-notes.txt"})
    agent = ScriptedAgent()

    without_injection = agent.propose(task, [environment.inbox[0]], set())
    with_injection = agent.propose(task, [environment.inbox[1]], set())

    assert without_injection[0].tool == task.tool
    assert with_injection[0].tool == task.tool
    assert without_injection[0].initiated_by.trust == "trusted"
    assert with_injection[0].initiated_by.trust == "trusted"


def test_simulated_directive_arguments_keep_the_untrusted_root_via_derive() -> None:
    injection = EmailEnvironment().inbox[1]
    proposal = ScriptedAgent().propose(
        PlannedAction("read_file", {"path": "workspace/meeting-notes.txt"}),
        [injection],
        set(),
    )[1]

    assert proposal.arguments["to"].tainted_by == frozenset({injection.segment.id})
    assert proposal.arguments["body"].tainted_by == frozenset({injection.segment.id})


def test_simulated_end_to_end_boundary_blocks_injection_but_runs_user_email() -> None:
    environment = EmailEnvironment()
    tools = MockTools()
    executor = GuardedExecutor(PolicyEngine(), tools)
    user_task = PlannedAction(
        "send_email",
        {"to": "friend@example.test", "body": "The meeting is tomorrow."},
        user_authorized_tools=frozenset({"send_email"}),
        user_explicit_recipients=frozenset({"friend@example.test"}),
    )

    results = ScriptedAgent().run(executor, user_task, [environment.inbox[1]], set())

    assert results[0].decision.action == ALLOW
    assert results[0].executed is True
    assert results[1].decision.action == BLOCK
    assert results[1].executed is False
    assert tools.outbox == [
        {
            "kind": "email",
            "to": "friend@example.test",
            "body": "The meeting is tomorrow.",
        }
    ]


def test_simulated_two_round_cascade_preserves_taint_and_is_blocked() -> None:
    workspace = WorkspaceEnvironment()
    document = workspace.documents[1]
    tools = MockTools(files=workspace.files.copy())
    executor = GuardedExecutor(PolicyEngine(), tools)
    agent = ScriptedAgent()
    read_task = PlannedAction(
        "read_file",
        {"path": document.segment.id},
        user_authorized_tools=frozenset({"read_file"}),
    )

    first_round = agent.run(executor, read_task, [], set())
    assert first_round[0].executed is True
    assert first_round[0].output == document.segment.text

    second_round_segment = derive(
        new_text=first_round[0].output or "",
        sources=[document.segment],
        new_id="workspace:read-result:round-2",
        origin=Origin.TOOL_OUTPUT,
    )
    second_round_content = VisibleContent(
        segment=second_round_segment,
        directive=document.directive,
    )
    proposals = agent.propose(read_task, [second_round_content], set())
    malicious_call = next(proposal for proposal in proposals if proposal.tool == "send_email")

    assert malicious_call.initiated_by.tainted_by == frozenset({document.segment.id})
    assert malicious_call.arguments["to"].tainted_by == frozenset({document.segment.id})
    second_round_results = [executor.execute(proposal) for proposal in proposals]
    blocked = next(result for result in second_round_results if result.decision.action == BLOCK)
    assert blocked.executed is False
    assert tools.outbox == []


def test_simulated_handbook_directive_runs_only_when_tool_is_user_authorized() -> None:
    handbook = WorkspaceEnvironment().documents[2]
    agent = ScriptedAgent()
    user_task = PlannedAction("read_file", {"path": handbook.segment.id})
    tools_without_authorization = MockTools(files={handbook.segment.id: handbook.segment.text})
    executor_without_authorization = GuardedExecutor(PolicyEngine(), tools_without_authorization)
    blocked_results = agent.run(
        executor_without_authorization,
        user_task,
        [handbook],
        set(),
    )

    assert blocked_results[0].executed is True
    assert blocked_results[1].decision.action == BLOCK
    assert blocked_results[1].executed is False
    assert tools_without_authorization.reads == [handbook.segment.id]

    authorized_task = PlannedAction(
        "read_file",
        {"path": handbook.segment.id},
        user_authorized_tools=frozenset({"read_file"}),
    )
    tools_with_authorization = MockTools(files={handbook.segment.id: handbook.segment.text})
    executor_with_authorization = GuardedExecutor(PolicyEngine(), tools_with_authorization)
    allowed_results = agent.run(
        executor_with_authorization,
        authorized_task,
        [handbook],
        set(),
    )

    assert allowed_results[0].executed is True
    assert allowed_results[1].decision.action == ALLOW
    assert allowed_results[1].executed is True
    assert tools_with_authorization.reads == [
        handbook.segment.id,
        "workspace/meeting-notes.txt",
    ]
