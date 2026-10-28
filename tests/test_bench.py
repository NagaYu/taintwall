"""SIMULATED bench-generation tests validate fixtures, not LLM robustness."""

import json
from collections import Counter
from pathlib import Path

from taintgate.bench import CATEGORY_COUNTS, generate_cases, write_cases


def test_simulated_bench_has_exact_total_and_category_counts() -> None:
    cases = generate_cases()

    assert len(cases) == 200
    assert Counter(case.category for case in cases) == CATEGORY_COUNTS


def test_simulated_bench_generation_is_seeded_and_changes_with_seed() -> None:
    first = generate_cases(seed=42)
    repeated = generate_cases(seed=42)
    different = generate_cases(seed=43)

    assert first == repeated
    assert any(left != right for left, right in zip(first, different))


def test_simulated_attacks_have_matching_untrusted_directives() -> None:
    attacks = [case for case in generate_cases() if case.attack_tool is not None]

    assert len(attacks) == 120
    for case in attacks:
        assert any(
            content.directive is not None
            and content.directive.tool == case.attack_tool
            and content.segment.trust == "untrusted"
            for content in case.visible
        ), case.case_id


def test_simulated_confusing_benign_directives_are_not_user_authorized() -> None:
    confusing = [case for case in generate_cases() if case.category == "benign_confusing"]

    assert len(confusing) == 30
    for case in confusing:
        assert any(content.directive is not None for content in case.visible)
        assert all(
            content.directive is None
            or content.directive.tool not in case.user_task.user_authorized_tools
            for content in case.visible
        )


def test_simulated_bench_case_ids_are_unique() -> None:
    case_ids = [case.case_id for case in generate_cases()]

    assert len(case_ids) == len(set(case_ids))


def test_simulated_write_cases_emits_two_hundred_auditable_cases(tmp_path: Path) -> None:
    output_path = tmp_path / "dev_cases.json"

    write_cases(output_path)

    cases = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(cases) == 200
    assert all("case_id" in case and "category" in case for case in cases)
    assert all("user_task" in case and "visible" in case for case in cases)
    assert all("segment" in case["visible"][0] for case in cases)
