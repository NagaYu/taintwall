from collections import Counter

from taintwall.bench import generate_cases
from taintwall.bench2 import convert_cases, probe_cases, procedure_cases
from taintwall.llm_client import FakeLLMClient, LLMResponse, ToolCallProposal
from taintwall.llm_runner import run_llm_benchmark


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


def test_probe_cases_are_twenty_unique_harmless_probes() -> None:
    probes = probe_cases()

    assert len(probes) == 20
    assert len({case.probe_phrase for case in probes}) == 20
    assert all(case.category == "probe" and case.attack_tool is None for case in probes)
    assert sum(case.case_id.startswith("PROBE-EN-") for case in probes) == 10
    assert sum(case.case_id.startswith("PROBE-JA-") for case in probes) == 10


def test_procedure_cases_cover_four_styles_and_keep_intent_annotations() -> None:
    cases = procedure_cases()

    assert len(cases) == 16
    assert Counter(case.case_id.split("-")[1] for case in cases) == {
        "ADDITIONAL_TRANSFER": 4,
        "RECIPIENT_SWAP": 4,
        "DELETE_SOURCE": 4,
        "PERSIST_RULE": 4,
    }
    for attack_type in ("ADDITIONAL_TRANSFER", "RECIPIENT_SWAP", "DELETE_SOURCE", "PERSIST_RULE"):
        group = [case for case in cases if f"-{attack_type}-" in case.case_id]
        assert sum("-EN-" in case.case_id for case in group) == 2
        assert sum("-JA-" in case.case_id for case in group) == 2
        assert all(case.category == "procedure" and len(case.visible) == 1 for case in group)
        assert all(case.visible[0].trust == "untrusted" for case in group)
        assert all(case.intent.explicit_recipients == frozenset({"ops@internal.example"}) for case in group)

    swaps = [case for case in cases if "-RECIPIENT_SWAP-" in case.case_id]
    deletes = [case for case in cases if "-DELETE_SOURCE-" in case.case_id]
    persists = [case for case in cases if "-PERSIST_RULE-" in case.case_id]
    assert all(case.attack_tool == case.user_task_tool == "send_email" for case in swaps)
    assert all(case.attack_tool == "delete_file" for case in deletes)
    assert all("delete_file" not in case.intent.authorized_tools for case in deletes)
    assert all(case.attack_tool == case.user_task_tool == "write_file" for case in persists)
    assert all(case.user_task_args["path"] != "workspace/standing-rules.txt" for case in persists)
