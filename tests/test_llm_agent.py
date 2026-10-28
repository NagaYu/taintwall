from taintgate.llm_agent import LLMAgent
from taintgate.llm_client import FakeLLMClient, LLMResponse, ToolCallProposal
from taintgate.provenance import Origin, Segment


def test_fake_llm_reads_then_proposes_email_with_result_in_next_step() -> None:
    client = FakeLLMClient(
        [
            LLMResponse(
                tool_calls=[
                    ToolCallProposal("read_file", {"path": "workspace/agenda.txt"})
                ]
            ),
            LLMResponse(
                tool_calls=[
                    ToolCallProposal(
                        "send_email",
                        {"to": "friend@example.test", "body": "The agenda says 10:00."},
                    )
                ]
            ),
            LLMResponse(text="The email proposal is ready."),
        ]
    )
    visible = Segment(
        id="file:agenda",
        text="Synthetic agenda content.",
        origin=Origin.FILE,
    )

    result = LLMAgent(client).run(
        user_prompt="Read the agenda and share its time.",
        visible_segments=[visible],
        tool_result_provider=lambda proposal, step_segments: (
            "File contents: the meeting starts at 10:00."
        ),
    )

    assert [proposal.tool for proposal in result.proposals] == ["read_file", "send_email"]
    assert result.end_reason == "text_response"
    assert result.final_text == "The email proposal is ready."
    assert client.calls[1]["messages"][-1]["content"] == (
        "Tool result for read_file:\nFile contents: the meeting starts at 10:00."
    )
    assert any(
        segment.origin == Origin.TOOL_OUTPUT
        and segment.text == "File contents: the meeting starts at 10:00."
        for segment in result.step_segments[1]
    )
    assert result.tool_result_segments[0].origin == Origin.TOOL_OUTPUT


def test_fake_llm_loop_stops_at_step_limit() -> None:
    client = FakeLLMClient(
        [
            LLMResponse(tool_calls=[ToolCallProposal("read_file", {"path": "a.txt"})]),
            LLMResponse(tool_calls=[ToolCallProposal("read_file", {"path": "b.txt"})]),
            LLMResponse(text="This response must not be requested."),
        ]
    )

    result = LLMAgent(client).run(
        user_prompt="Read these files.",
        visible_segments=[],
        max_steps=2,
        tool_result_provider=lambda proposal, step_segments: (
            f"Read result for {proposal.arguments['path']}."
        ),
    )

    assert result.end_reason == "max_steps"
    assert len(result.proposals) == 2
    assert len(client.calls) == 2


def test_fake_llm_text_only_response_ends_immediately() -> None:
    client = FakeLLMClient([LLMResponse(text="No tool call needed.")])

    result = LLMAgent(client).run(
        user_prompt="What time is the meeting?",
        visible_segments=[],
    )

    assert result.end_reason == "text_response"
    assert result.proposals == []
    assert result.final_text == "No tool call needed."
    assert len(result.step_segments) == 1


def test_fake_client_raises_when_script_is_exhausted() -> None:
    client = FakeLLMClient([LLMResponse(text="First response.")])

    client.complete(messages=[], tools=[])

    try:
        client.complete(messages=[], tools=[])
    except RuntimeError as error:
        assert "exhausted" in str(error)
    else:
        raise AssertionError("Expected FakeLLMClient to reject an exhausted script.")
