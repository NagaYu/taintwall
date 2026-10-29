#!/usr/bin/env python3
"""Generate and run the offline SIMULATED Phase 1 benchmark."""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from taintwall.bench import DEFAULT_SEED, write_cases  # noqa: E402
from taintwall.runner import render_gate, render_report, run_benchmark  # noqa: E402


def main() -> None:
    benchmarks_dir = ROOT / "benchmarks"
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_cases(benchmarks_dir / "dev_cases.json", seed=DEFAULT_SEED)
    results = run_benchmark(seed=DEFAULT_SEED)
    (reports_dir / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (reports_dir / "phase1-report.md").write_text(render_report(results), encoding="utf-8")
    (ROOT / "GATE.md").write_text(render_gate(results), encoding="utf-8")
    print(f"Wrote {benchmarks_dir / 'dev_cases.json'}")
    print(f"Wrote {reports_dir / 'results.json'}")
    print(f"Wrote {reports_dir / 'phase1-report.md'}")
    print(f"Wrote {ROOT / 'GATE.md'}")


if __name__ == "__main__":
    main()
