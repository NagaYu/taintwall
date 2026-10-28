# TaintGate

TaintGate is an offline prototype of a runtime firewall for AI agents. It tracks content provenance and applies deterministic policies at the tool boundary to limit indirect prompt injection from untrusted content.

## Phase 1 scope

Phase 1 is a SIMULATED, offline measurement using synthetic fixtures and a deterministic ScriptedAgent. It measures policy enforcement against scripted tool proposals; it does not call a real LLM and does not measure LLM robustness. Results and the gate verdict are provisional until rerun locally.

The current provisional GATE is PASS: adapted ASR is C1 100.0% versus C3 0.0%, and C3 utility is 100.0% versus C0 utility of 100.0%. See GATE.md and reports/phase1-report.md for sample sizes, category results, limitations, and the provisional status.

## Run locally

Use Python 3.11 or newer:

~~~sh
python -m pip install -e ".[dev]"
python scripts/run_bench.py
python -m pytest -q
~~~

The benchmark command writes benchmarks/dev_cases.json, reports/results.json, reports/phase1-report.md, and GATE.md. All tools and fixtures are in-memory and synthetic. The exec mock only records command text and never runs it.

## License and transfer

License availability and transfer terms are a placeholder and remain to be confirmed.

## Contact

https://nagayu-portfolio.nagayu.workers.dev/en
