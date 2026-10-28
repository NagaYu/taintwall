from collections import Counter

from taintgate.bench import generate_cases
from taintgate.bench2 import convert_cases


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
    assert v2.intent.authorized_tools == v1.user_task.user_authorized_tools
    assert v2.intent.explicit_recipients == v1.user_task.user_explicit_recipients
