from collections import Counter

from taintgate.bench import generate_cases
from taintgate.bench2 import convert_cases
from taintgate.llm_client import FakeLLMClient, LLMResponse, ToolCallProposal
from taintgate.llm_runner import run_llm_benchmark


def test_v2_conversion_preserves_case_ids_categories_counts_and_attack_tools() -> None:
    v1_cases = generate_cases()
    v2_cases = convert_cases()

    assert len(v2_cases) == 200
    assert [(case.case_id, case.category, case.attack_tool) for case in v2_cases] == [
        (case.case_id, case.category, case.attack_tool) for case in v1_cases
    ]
    assert Counter(case.category for case in v2_cases) == Counter(
        case.category for case in v1_cases
    )


def test_v2_exposes_segments_but_not_directive_objects() -> None:
    v1 = generate_cases()[0]
    v2 = convert_cases()[0]

    assert [segment for segment in v2.visible] == [item.segment for item in v1.visible]
    assert all(not hasattr(segment, "directive") for segment in v2.visible)
    assert v2.intent.authorized_tools == v1.user_task.user_authorized_tools.union(
        {v1.user_task.tool}
    )
    assert v2.intent.explicit_recipients == v1.user_task.user_explicit_recipients


def test_every_v2_case_authorizes_its_user_task_tool() -> None:
    assert all(case.user_task_tool in case.intent.authorized_tools for case in convert_cases())


def test_benign_confusing_user_read_task_has_full_c3_utility() -> None:
    case = next(case for case in convert_cases() if case.category == "benign_confusing")
    proposal = ToolCallProposal(
        "read_file",
        {"path": case.user_task_args["path"]},
    )

    result = run_llm_benchmark(
        [case],
        lambda condition, input_case: FakeLLMClient(
            [
                LLMResponse(tool_calls=[proposal]),
                LLMResponse(text="The requested file was read."),
            ]
        ),
        conditions=("C3",),
    )

    assert result["conditions"]["C3"]["utility"] == 1.0
