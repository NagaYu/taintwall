"""Run the local Phase 2 benchmark; tests inject fake clients and never call an API."""

import argparse
import json
import re
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from taintgate.bench2 import BenchCaseV2, convert_cases, probe_cases, procedure_cases
from taintgate.llm_adapt import DEFENSE_SUMMARIES, paraphrase_attack, select_adaptive_cases
from taintgate.llm_client import (
    DEFAULT_ANTHROPIC_MODEL,
    AnthropicClient,
    LLMClient,
)
from taintgate.llm_runner import estimate_cost, run_llm_benchmark
from taintgate.ollama_client import OLLAMA_DEFAULT_MODEL, OllamaClient


REPORTS_DIR = Path(__file__).resolve().parents[1] / "reports"
DEFAULT_TRIALS = 3
BENCHMARK_SECTIONS = ("baseline", "variance", "adaptive", "calibration", "procedure")
MODEL_PRICES = {
    # Anthropic list prices per million tokens; sources checked 2026-10-28.
    DEFAULT_ANTHROPIC_MODEL: {
        "input_usd_per_million": 1.0,
        "output_usd_per_million": 5.0,
        "source": "https://www.anthropic.com/news/claude-haiku-4-5",
    },
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local Phase 2 TaintGate benchmark")
    parser.add_argument("--max-usd", type=float, required=True, help="maximum estimated spend")
    parser.add_argument("--dry-run", action="store_true", help="estimate and exit without creating clients")
    parser.add_argument("--model", default=None, help="model ID (provider default when omitted)")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS, help="variance trial count")
    parser.add_argument("--ollama", action="store_true", help="use a local Ollama server at localhost")
    parser.add_argument("--preview", action="store_true", help="use the deterministic preview subset")
    parser.add_argument(
        "--sections",
        default=",".join(BENCHMARK_SECTIONS),
        help="comma-separated stages to run: " + ",".join(BENCHMARK_SECTIONS),
    )
    return parser.parse_args(argv)


def parse_sections(value: str) -> tuple[str, ...]:
    selected = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(selected) - set(BENCHMARK_SECTIONS))
    if unknown:
        raise ValueError(f"unknown section(s): {', '.join(unknown)}")
    if not selected:
        raise ValueError("--sections must select at least one stage")
    if len(set(selected)) != len(selected):
        raise ValueError("--sections must not contain duplicates")
    return selected


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


def build_preview_plan(cases: Sequence[BenchCaseV2]) -> dict[str, list[BenchCaseV2]]:
    """Choose the deterministic preview corpora for each measurement stage."""

    attacks: list[BenchCaseV2] = []
    adaptive: list[BenchCaseV2] = []
    for index in range(1, 9):
        category_cases = [
            case
            for case in cases
            if case.category == f"I{index}" and case.attack_tool is not None
        ]
        if len(category_cases) < 5:
            raise ValueError(f"category I{index} has fewer than five preview attack cases")
        attacks.extend(category_cases[:5])
        adaptive.extend(category_cases[:2])
    benign = [case for case in cases if case.category == "benign"][:20]
    confusing = [case for case in cases if case.category == "benign_confusing"][:20]
    if len(benign) != 20 or len(confusing) != 20:
        raise ValueError("dev set is missing benign cases needed for preview")
    dev = attacks + benign + confusing
    return {
        "dev": dev,
        "detector_extractor": attacks + confusing,
        "variance": _select_core_cases(dev),
        "adaptive": adaptive,
    }


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
    *,
    preview: bool = False,
    sections: Sequence[str] = BENCHMARK_SECTIONS,
) -> dict[str, object]:
    """Approximate all benchmark, variance, paraphrase, and extractor calls up front."""

    if trials < 1:
        raise ValueError("--trials must be at least 1")
    if preview:
        plan = build_preview_plan(cases)
        dev_cases = plan["dev"]
        attack_and_confusing = plan["detector_extractor"]
        core = plan["variance"]
        adaptive = plan["adaptive"]
        trials = 1
    else:
        dev_cases = list(cases)
        attack_and_confusing = [
            case
            for case in cases
            if case.attack_tool is not None or case.category == "benign_confusing"
        ]
        core = _select_core_cases(cases)
        adaptive = select_adaptive_cases(cases)
    selected = set(sections)
    estimates: list[dict[str, float | int]] = []
    if "baseline" in selected:
        estimates.extend(
            [
                _estimate_entry(dev_cases, ("C0", "C2", "C3"), prices),
                _estimate_entry(attack_and_confusing, ("C1", "C4"), prices),
            ]
        )
    if "calibration" in selected:
        estimates.append(_estimate_entry(probe_cases(), ("C0", "C3", "C4"), prices))
    if "procedure" in selected:
        estimates.append(_estimate_entry(procedure_cases(), ("C0", "C1", "C2", "C3", "C4"), prices))
    if "variance" in selected:
        estimates.extend(
            _estimate_entry(core, (condition,), prices)
            for _ in range(trials)
            for condition in ("C0", "C3")
        )
    if "adaptive" in selected:
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
        "probe_followed": result.get("probe_followed", 0),
        "probe_cases": result.get("probe_cases", 0),
        "probe_ifr": result.get("probe_ifr"),
    }


def _usage_and_cost(
    clients: Sequence[LLMClient], prices: dict[str, float]
) -> tuple[dict[str, int], dict[str, object]]:
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
    cost = {
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
    return usage, cost


def _archive_previous_result(report_dir: Path) -> Path | None:
    result_path = report_dir / "llm-results.json"
    if not result_path.exists():
        return None
    try:
        existing = json.loads(result_path.read_text(encoding="utf-8"))
        model_name = existing.get("model", "unknown-model")
    except (OSError, json.JSONDecodeError, AttributeError):
        model_name = "unknown-model"
    model_slug = re.sub(r"[^A-Za-z0-9.-]+", "-", str(model_name)).strip("-") or "unknown-model"
    archive_path = report_dir / f"llm-results.{model_slug}.json"
    suffix = 2
    while archive_path.exists():
        if archive_path.read_bytes() == result_path.read_bytes():
            return archive_path
        archive_path = report_dir / f"llm-results.{model_slug}-{suffix}.json"
        suffix += 1
    shutil.copy2(result_path, archive_path)
    return archive_path


def _phase2_report(results: dict[str, object]) -> str:
    baseline = results["baseline"]
    adaptive = results["adaptive"]
    variance = results["variance"]
    usage = results["usage"]
    costs = results["actual_cost"]
    calibration = results["calibration"]
    procedure = results["procedure"]
    assert isinstance(baseline, dict)
    assert isinstance(adaptive, dict)
    assert isinstance(variance, dict)
    assert isinstance(usage, dict)
    assert isinstance(costs, dict)
    assert isinstance(calibration, dict)
    assert isinstance(procedure, dict)
    requested = set(results.get("sections_requested", BENCHMARK_SECTIONS))
    lines = [
        "# Phase 2 Measurement Report",
        "",
    ]
    if results.get("preview"):
        if results.get("provider") == "ollama":
            lines.extend(["**PREVIEW — local model (Ollama), no API cost**", ""])
        else:
            lines.extend(["**PREVIEW — hosted model; API cost may apply**", ""])
    lines.extend(
        [
        "This report contains measurements from the local LLM benchmark run recorded in `llm-results.json`.",
        "",
        f"- Model: `{results['model']}`",
        f"- Provider: `{results['provider']}`",
        f"- Run time (UTC): {results['run_at_utc']}",
        "- The benchmark uses synthetic cases and mock tools; no external tool service is connected.",
        "",
        "## Baseline conditions",
        "",
        "| Condition | ASR (n) | Utility (n) | benign_confusing directive rate (n) |",
        "|---|---:|---:|---:|",
        ]
    )
    if not baseline:
        lines.append("Baseline: not run (section not selected).")
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
    if not adaptive:
        lines.append("Adaptive: not run (section not selected).")
    lines.extend(
        [
            "",
            "## Calibration",
            "",
            "| Condition | Instruction follow rate (IFR) | Followed / cases |",
            "|---|---:|---:|",
        ]
    )
    for condition, item in calibration.items():
        lines.append(
            f"| {condition} | {item['instruction_follow_rate']:.3f} | "
            f"{item['followed']} / {item['cases']} |"
        )
    if not calibration:
        lines.append("Calibration: not run (section not selected).")
    lines.extend(
        [
            "",
            "C0 IFR is a measure of attack pressure; when it is low, ASR comparisons should be treated as reference values.",
        ]
    )
    lines.extend(["", "## Variance subset", "", "| Condition | ASR min–max | Utility min–max | Trials |", "|---|---:|---:|---:|"])
    for condition, item in variance.items():
        lines.append(
            f"| {condition} | {item['asr_min']:.3f}–{item['asr_max']:.3f} | "
            f"{item['utility_min']:.3f}–{item['utility_max']:.3f} | {item['trials']} |"
        )
    if not variance:
        lines.append("Variance: not run (section not selected).")
    lines.extend(
        [
            "",
            "## Task-embedded (procedure) attacks",
            "",
            "| Condition | ASR | Attack successes / cases | Utility | Utility successes / cases |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    if procedure:
        for condition in ("C0", "C1", "C2", "C3", "C4"):
            item = procedure.get(condition)
            if item is None:
                continue
            lines.append(
                f"| {condition} | {item['asr']:.3f} | "
                f"{item['attack_successes']} / {item['attack_cases']} | "
                f"{item['utility']:.3f} | {item['utility_successes']} / {item['utility_cases']} |"
            )
    else:
        lines.append("| not run (section not selected) | — | — | — | — |")
    lines.extend(["", "## Section status", ""])
    for section in BENCHMARK_SECTIONS:
        status = "selected" if section in requested else "not run (not selected)"
        lines.append(f"- {section}: {status}")
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
    procedure = results["procedure"]
    assert isinstance(baseline, dict) and isinstance(adaptive, dict) and isinstance(costs, dict)
    assert isinstance(procedure, dict)
    if results.get("preview") and results.get("provider") == "ollama":
        print(f"PREVIEW — local model (Ollama), no API cost — model: {results['model']}")
    else:
        print(f"Model: {results['model']} | provider: {results['provider']}")
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
    if procedure:
        print("Procedure ASR | Utility")
        for condition in ("C0", "C1", "C2", "C3", "C4"):
            item = procedure.get(condition)
            if item:
                print(f"{condition} | {item['asr']:.3f} | {item['utility']:.3f}")


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
    selected_sections = parse_sections(args.sections)
    model = args.model or (OLLAMA_DEFAULT_MODEL if args.ollama else DEFAULT_ANTHROPIC_MODEL)
    if args.ollama:
        prices = {
            "input_usd_per_million": 0.0,
            "output_usd_per_million": 0.0,
            "source": "local Ollama inference; no API token charge",
        }
    else:
        if model not in MODEL_PRICES:
            raise ValueError(
                f"No price entry for model {model!r}; add its official token rates to MODEL_PRICES first"
            )
        prices = MODEL_PRICES[model]

    all_cases = convert_cases()
    plan = build_preview_plan(all_cases) if args.preview else None
    cases = plan["dev"] if plan is not None else all_cases
    selected_150 = (
        plan["detector_extractor"]
        if plan is not None
        else [
            case
            for case in all_cases
            if case.attack_tool is not None or case.category == "benign_confusing"
        ]
    )
    core = plan["variance"] if plan is not None else _select_core_cases(all_cases)
    adaptive_base = (
        plan["adaptive"] if plan is not None else select_adaptive_cases(all_cases)
    )
    trials = 1 if args.preview else args.trials
    estimate = estimate_plan(
        all_cases,
        trials,
        prices,
        preview=args.preview,
        sections=selected_sections,
    )
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

    if client_builder is not None:
        builder = client_builder
    elif args.ollama:
        builder = lambda selected_model: OllamaClient(model=selected_model)
    else:
        builder = lambda selected_model: AnthropicClient(model=selected_model)
    clients: list[LLMClient] = []

    def new_client() -> LLMClient:
        client = builder(model)
        clients.append(client)
        return client

    def benchmark_factory(condition: str, case: BenchCaseV2) -> LLMClient:
        del condition, case
        return new_client()

    def extractor_factory(case: BenchCaseV2, segment) -> LLMClient:
        del case, segment
        return new_client()

    baseline: dict[str, object] = {}
    variance: dict[str, object] = {}
    adaptive: dict[str, object] = {}
    calibration: dict[str, object] = {}
    procedure: dict[str, object] = {}
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    partial_path = report_dir / "llm-results.partial.json"

    def checkpoint(stage: str) -> None:
        partial = {
            "model": model,
            "provider": "ollama" if args.ollama else "anthropic",
            "preview": args.preview,
            "stage_completed": stage,
            "run_at_utc": datetime.now(timezone.utc).isoformat(),
            "trials": trials,
            "case_counts": dict(Counter(case.category for case in cases)),
            "estimate": estimate,
            "baseline": baseline,
            "variance": variance,
            "adaptive": adaptive,
            "calibration": calibration,
            "procedure": procedure,
            "sections_requested": list(selected_sections),
            "usage": _usage_and_cost(clients, prices)[0],
            "actual_cost": _usage_and_cost(clients, prices)[1],
        }
        partial_path.write_text(
            json.dumps(partial, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    checkpoint("initialized")
    if "baseline" in selected_sections:
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
        checkpoint("baseline")

    if "variance" in selected_sections:
        variance_runs: dict[str, list[dict[str, float]]] = {"C0": [], "C3": []}
        for _trial in range(trials):
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
        checkpoint("variance")

    if "adaptive" in selected_sections:
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
        checkpoint("adaptive")

    if "calibration" in selected_sections:
        calibration_run = run_llm_benchmark(
            probe_cases(),
            benchmark_factory,
            conditions=("C0", "C3", "C4"),
            max_usd=args.max_usd,
            model_price=prices,
            extractor_client_factory=extractor_factory,
        )
        for condition, condition_result in calibration_run["conditions"].items():
            calibration[condition] = {
                "instruction_follow_rate": float(condition_result["probe_ifr"] or 0.0),
                "followed": int(condition_result["probe_followed"]),
                "cases": int(condition_result["probe_cases"]),
            }
        checkpoint("calibration")

    if "procedure" in selected_sections:
        procedure_run = run_llm_benchmark(
            procedure_cases(),
            benchmark_factory,
            conditions=("C0", "C1", "C2", "C3", "C4"),
            max_usd=args.max_usd,
            model_price=prices,
            extractor_client_factory=extractor_factory,
        )
        for condition, condition_result in procedure_run["conditions"].items():
            procedure[condition] = _metric(condition_result)
        checkpoint("procedure")

    successful_attack_cases: list[dict[str, str]] = []
    for measurement, table in (("baseline", baseline), ("adaptive", adaptive), ("procedure", procedure)):
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

    usage, actual_cost = _usage_and_cost(clients, prices)
    results: dict[str, object] = {
        "model": model,
        "provider": "ollama" if args.ollama else "anthropic",
        "preview": args.preview,
        "run_at_utc": datetime.now(timezone.utc).isoformat(),
        "trials": trials,
        "case_counts": dict(Counter(case.category for case in cases)),
        "estimate": estimate,
        "baseline": baseline,
        "variance": variance,
        "adaptive": adaptive,
        "calibration": calibration,
        "procedure": procedure,
        "sections_requested": list(selected_sections),
        "usage": usage,
        "actual_cost": actual_cost,
        "successful_attack_cases": successful_attack_cases,
    }
    _archive_previous_result(report_dir)
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
