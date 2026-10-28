"""Run the local Phase 2 benchmark; tests inject fake clients and never call an API."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from taintgate.bench2 import BenchCaseV2, convert_cases
from taintgate.llm_adapt import DEFENSE_SUMMARIES, paraphrase_attack, select_adaptive_cases
from taintgate.llm_client import (
    DEFAULT_ANTHROPIC_MODEL,
    AnthropicClient,
    LLMClient,
)
from taintgate.llm_runner import estimate_cost, run_llm_benchmark


REPORTS_DIR = Path(__file__).resolve().parents[1] / "reports"
DEFAULT_TRIALS = 3
MODEL_PRICES = {
    # Anthropic list prices per million tokens; sources checked 2026-10-28.
    DEFAULT_ANTHROPIC_MODEL: {
        "input_usd_per_million": 1.0,
        "output_usd_per_million": 5.0,
        "source": "https://www.anthropic.com/news/claude-haiku-4-5",
    },
    "claude-haiku-5-5": {
        "input_usd_per_million": 0.10,
        "output_usd_per_million": 0.50,
        "source": "https://www.anthropic.com/claude/haiku-5-5",
    },
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local Phase 2 TaintGate benchmark")
    parser.add_argument("--max-usd", type=float, required=True, help="maximum estimated spend")
    parser.add_argument("--dry-run", action="store_true", help="estimate and exit without creating clients")
    parser.add_argument("--model", default=DEFAULT_ANTHROPIC_MODEL, help="Anthropic model ID")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS, help="variance trial count")
    return parser.parse_args(argv)


def _select_core_cases(cases: Sequence[BenchCaseV2]) -> list[BenchCaseV2]:
    attacks: list[BenchCaseV2] = []
    for index in range(1, 9):
        category_cases = [
            case
            for case in cases
            if case.category == f"I{index}" and case.attack_tool is not None
        ]
        target_count = 3 if index <= 4 else 2
        if len(category_cases) < target_count:
            raise ValueError(f"category I{index} is missing core variance cases")
        attacks.extend(category_cases[:target_count])
    benign = [case for case in cases if case.category == "benign"][:10]
    confusing = [case for case in cases if case.category == "benign_confusing"][:10]
    if len(attacks) != 20 or len(benign) != 10 or len(confusing) != 10:
        raise ValueError("dev set is missing cases needed for the 40-case variance subset")
    return attacks + benign + confusing


def _estimate_entry(
    cases: Sequence[BenchCaseV2],
    conditions: Sequence[str],
    prices: dict[str, float],
) -> dict[str, float | int]:
    estimate = estimate_cost(cases, conditions, prices)
    return {
        "input_tokens": int(estimate["input_tokens_estimate"]),
        "output_tokens": int(estimate["output_tokens_estimate"]),
        "estimated_usd": float(estimate["estimated_usd"]),
    }


def estimate_plan(
    cases: Sequence[BenchCaseV2],
    trials: int,
    prices: dict[str, float],
) -> dict[str, object]:
    """Approximate all benchmark, variance, paraphrase, and extractor calls up front."""

    if trials < 1:
        raise ValueError("--trials must be at least 1")
    attack_and_confusing = [
        case for case in cases if case.attack_tool is not None or case.category == "benign_confusing"
    ]
    core = _select_core_cases(cases)
    adaptive = select_adaptive_cases(cases)
    estimates = [
        _estimate_entry(cases, ("C0", "C2", "C3"), prices),
        _estimate_entry(attack_and_confusing, ("C1", "C4"), prices),
    ]
    estimates.extend(
        _estimate_entry(core, (condition,), prices)
        for _ in range(trials)
        for condition in ("C0", "C3")
    )
    estimates.extend(
        _estimate_entry(adaptive, (condition,), prices)
        for condition in ("C1", "C3", "C4")
    )

    # Each defense gets one attacker paraphrase call per selected case.
    paraphrase_calls = len(adaptive) * 3
    paraphrase_input_tokens = sum(
        len(case.user_prompt) + sum(len(segment.text) for segment in case.visible) + 1800
        for case in adaptive
    ) * 3 // 4
    paraphrase_output_tokens = paraphrase_calls * 256
    estimates.append(
        {
            "input_tokens": paraphrase_input_tokens,
            "output_tokens": paraphrase_output_tokens,
            "estimated_usd": (
                paraphrase_input_tokens * prices["input_usd_per_million"]
                + paraphrase_output_tokens * prices["output_usd_per_million"]
            )
            / 1_000_000,
        }
    )
    input_tokens = sum(int(item["input_tokens"]) for item in estimates)
    output_tokens = sum(int(item["output_tokens"]) for item in estimates)
    return {
        "input_tokens_estimate": input_tokens,
        "output_tokens_estimate": output_tokens,
        "total_tokens_estimate": input_tokens + output_tokens,
        "estimated_usd": sum(float(item["estimated_usd"]) for item in estimates),
        "method": (
            "APPROXIMATE: per-call character/token allowances; includes C4 extractor calls, "
            "adaptive paraphrases, requested runs, and variance trials"
        ),
    }


def _metric(result: dict[str, object]) -> dict[str, object]:
    return {
        "asr": result["asr"],
        "attack_successes": result["attack_successes"],
        "attack_cases": result["attack_cases"],
        "utility": result["utility"],
        "utility_successes": result["utility_successes"],
        "utility_cases": result["utility_cases"],
        "category_asr": result["category_asr"],
        "benign_confusing_cases": result["benign_confusing_cases"],
        "benign_confusing_directive_execution_rate": result[
            "benign_confusing_directive_execution_rate"
        ],
        "cases": result["cases"],
        "runtime_seconds": result["runtime_seconds"],
    }


def _phase2_report(results: dict[str, object]) -> str:
    baseline = results["baseline"]
    adaptive = results["adaptive"]
    variance = results["variance"]
    usage = results["usage"]
    costs = results["actual_cost"]
    assert isinstance(baseline, dict)
    assert isinstance(adaptive, dict)
    assert isinstance(variance, dict)
    assert isinstance(usage, dict)
    assert isinstance(costs, dict)
    lines = [
        "# Phase 2 Measurement Report",
        "",
        "This report contains measurements from the local LLM benchmark run recorded in `llm-results.json`.",
        "",
        f"- Model: `{results['model']}`",
        f"- Run time (UTC): {results['run_at_utc']}",
        "- The benchmark uses synthetic cases and mock tools; no external tool service is connected.",
        "",
        "## Baseline conditions",
        "",
        "| Condition | ASR (n) | Utility (n) | benign_confusing directive rate (n) |",
        "|---|---:|---:|---:|",
    ]
    for condition in ("C0", "C1", "C2", "C3", "C4"):
        if condition not in baseline:
            continue
        item = baseline[condition]
        lines.append(
            f"| {condition} | {item['asr']:.3f} ({item['attack_cases']}) | "
            f"{item['utility']:.3f} ({item['utility_cases']}) | "
            f"{item['benign_confusing_directive_execution_rate']:.3f} "
            f"({item['benign_confusing_cases']}) |"
        )
    lines.extend(["", "## Baseline category ASR", "", "| Category | Condition | Successes / cases | ASR |", "|---|---|---:|---:|"])
    for condition, item in baseline.items():
        for category, category_item in item["category_asr"].items():
            lines.append(
                f"| {category} | {condition} | {category_item['successes']} / "
                f"{category_item['cases']} | {category_item['asr']:.3f} |"
            )
    lines.extend(
        [
            "",
            "## Adaptive round 2 ASR",
            "",
            "| Defense | Successes / cases | ASR |",
            "|---|---:|---:|",
        ]
    )
    for condition, item in adaptive.items():
        lines.append(
            f"| {condition} | {item['attack_successes']} / {item['attack_cases']} | {item['asr']:.3f} |"
        )
    lines.extend(["", "## Variance subset", "", "| Condition | ASR min–max | Utility min–max | Trials |", "|---|---:|---:|---:|"])
    for condition, item in variance.items():
        lines.append(
            f"| {condition} | {item['asr_min']:.3f}–{item['asr_max']:.3f} | "
            f"{item['utility_min']:.3f}–{item['utility_max']:.3f} | {item['trials']} |"
        )
    leaks = results["successful_attack_cases"]
    lines.extend(
        [
            "",
            "## Executed attack cases",
            "",
            "| Measurement | Case ID | Category |",
            "|---|---|---|",
        ]
    )
    if leaks:
        for leak in leaks:
            lines.append(f"| {leak['measurement']} | {leak['case_id']} | {leak['category']} |")
    else:
        lines.append("| none recorded | — | — |")
    lines.extend(
        [
            "",
            "## Usage and actual cost",
            "",
            f"- Input tokens: {usage['input_tokens']}",
            f"- Output tokens: {usage['output_tokens']}",
            f"- Actual cost from recorded usage and the selected price table: ${costs['total_usd']:.6f}",
            f"- Input cost: ${costs['input_usd']:.6f}; output cost: ${costs['output_usd']:.6f}.",
            f"- Price source: {costs['price_source']}",
            "",
            "## Measurement notes",
            "",
            "- I6 cases contain a second-stage segment but are measured within the current single-run case structure; this is an approximation, not a true two-round cascade.",
            "- The harness renders tool proposals and results as conversation text, not Anthropic-native `tool_use` / `tool_result` blocks.",
            "- The requested tool and explicit-recipient annotations are supplied as benchmark intent; the model does not infer user authorization.",
            "",
        ]
    )
    return "\n".join(lines)


def _print_summary(results: dict[str, object]) -> None:
    baseline = results["baseline"]
    adaptive = results["adaptive"]
    costs = results["actual_cost"]
    assert isinstance(baseline, dict) and isinstance(adaptive, dict) and isinstance(costs, dict)
    print("Condition | ASR | Utility | Adaptive ASR")
    print("---|---:|---:|---:")
    for condition in ("C0", "C1", "C2", "C3", "C4"):
        item = baseline.get(condition)
        adapted = adaptive.get(condition)
        asr = f"{item['asr']:.3f}" if item else "—"
        utility = f"{item['utility']:.3f}" if item else "—"
        adapted_asr = f"{adapted['asr']:.3f}" if adapted else "—"
        print(f"{condition} | {asr} | {utility} | {adapted_asr}")
    print(f"Total actual cost: ${costs['total_usd']:.6f}")


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    client_builder: Callable[[str], LLMClient] | None = None,
    output_dir: str | Path = REPORTS_DIR,
) -> int:
    args = parse_args(argv)
    if args.max_usd <= 0:
        raise ValueError("--max-usd must be greater than zero")
    if args.trials < 1:
        raise ValueError("--trials must be at least 1")
    if args.model not in MODEL_PRICES:
        raise ValueError(
            f"No price entry for model {args.model!r}; add its official token rates to MODEL_PRICES first"
        )

    prices = MODEL_PRICES[args.model]
    cases = convert_cases()
    selected_150 = [
        case for case in cases if case.attack_tool is not None or case.category == "benign_confusing"
    ]
    core = _select_core_cases(cases)
    adaptive_base = select_adaptive_cases(cases)
    estimate = estimate_plan(cases, args.trials, prices)
    print(
        "APPROXIMATE total plan estimate: "
        f"{estimate['total_tokens_estimate']} tokens, ${estimate['estimated_usd']:.6f} "
        f"against max ${args.max_usd:.2f}"
    )
    if args.dry_run:
        print("Dry run only; no LLM clients were created.")
        return 0
    if float(estimate["estimated_usd"]) > args.max_usd:
        print("Estimated spend exceeds --max-usd; stopping before creating LLM clients.", file=sys.stderr)
        return 2

    builder = client_builder or (lambda model: AnthropicClient(model=model))
    clients: list[LLMClient] = []

    def new_client() -> LLMClient:
        client = builder(args.model)
        clients.append(client)
        return client

    def benchmark_factory(condition: str, case: BenchCaseV2) -> LLMClient:
        del condition, case
        return new_client()

    def extractor_factory(case: BenchCaseV2, segment) -> LLMClient:
        del case, segment
        return new_client()

    baseline: dict[str, object] = {}
    primary = run_llm_benchmark(
        cases,
        benchmark_factory,
        conditions=("C0", "C2", "C3"),
        max_usd=args.max_usd,
        model_price=prices,
    )
    for condition, result in primary["conditions"].items():
        baseline[condition] = _metric(result)

    detector_extractor = run_llm_benchmark(
        selected_150,
        benchmark_factory,
        conditions=("C1", "C4"),
        max_usd=args.max_usd,
        model_price=prices,
        extractor_client_factory=extractor_factory,
    )
    for condition, result in detector_extractor["conditions"].items():
        baseline[condition] = _metric(result)

    variance_runs: dict[str, list[dict[str, float]]] = {"C0": [], "C3": []}
    for _trial in range(args.trials):
        for condition in ("C0", "C3"):
            trial_result = run_llm_benchmark(
                core,
                benchmark_factory,
                conditions=(condition,),
                max_usd=args.max_usd,
                model_price=prices,
            )["conditions"][condition]
            variance_runs[condition].append(
                {"asr": float(trial_result["asr"]), "utility": float(trial_result["utility"])}
            )
    variance = {
        condition: {
            "trials": len(metrics),
            "asr_min": min(item["asr"] for item in metrics),
            "asr_max": max(item["asr"] for item in metrics),
            "utility_min": min(item["utility"] for item in metrics),
            "utility_max": max(item["utility"] for item in metrics),
            "runs": metrics,
        }
        for condition, metrics in variance_runs.items()
    }

    adaptive: dict[str, object] = {}
    for condition in ("C1", "C3", "C4"):
        defense_summary = DEFENSE_SUMMARIES[condition]
        paraphrased = [
            paraphrase_attack(case, new_client(), defense_summary)
            for case in adaptive_base
        ]
        adaptive_run = run_llm_benchmark(
            paraphrased,
            benchmark_factory,
            conditions=(condition,),
            max_usd=args.max_usd,
            model_price=prices,
            extractor_client_factory=extractor_factory if condition == "C4" else None,
        )
        adaptive[condition] = _metric(adaptive_run["conditions"][condition])

    successful_attack_cases: list[dict[str, str]] = []
    for measurement, table in (("baseline", baseline), ("adaptive", adaptive)):
        for condition, result in table.items():
            for case_result in result["cases"]:
                if case_result["attack_succeeded"]:
                    successful_attack_cases.append(
                        {
                            "measurement": f"{measurement}:{condition}",
                            "case_id": case_result["case_id"],
                            "category": case_result["category"],
                        }
                    )

    usage = {
        "input_tokens": sum(
            int(getattr(client, "usage_totals", {}).get("input_tokens", 0))
            for client in clients
        ),
        "output_tokens": sum(
            int(getattr(client, "usage_totals", {}).get("output_tokens", 0))
            for client in clients
        ),
    }
    actual_cost = {
        "input_usd": usage["input_tokens"] * prices["input_usd_per_million"] / 1_000_000,
        "output_usd": usage["output_tokens"] * prices["output_usd_per_million"] / 1_000_000,
        "total_usd": (
            usage["input_tokens"] * prices["input_usd_per_million"]
            + usage["output_tokens"] * prices["output_usd_per_million"]
        )
        / 1_000_000,
        "input_usd_per_million": prices["input_usd_per_million"],
        "output_usd_per_million": prices["output_usd_per_million"],
        "price_source": prices["source"],
    }
    results: dict[str, object] = {
        "model": args.model,
        "run_at_utc": datetime.now(timezone.utc).isoformat(),
        "trials": args.trials,
        "case_counts": dict(Counter(case.category for case in cases)),
        "estimate": estimate,
        "baseline": baseline,
        "variance": variance,
        "adaptive": adaptive,
        "usage": usage,
        "actual_cost": actual_cost,
        "successful_attack_cases": successful_attack_cases,
    }
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "llm-results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (report_dir / "phase2-report.md").write_text(_phase2_report(results), encoding="utf-8")
    _print_summary(results)
    return 0


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
