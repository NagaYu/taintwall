# Phase 1 Measurement Report — SIMULATED AGENT — policy-enforcement measurement, not LLM robustness

**PROVISIONAL:** generated from a local SIMULATED run; rerun locally before treating these values as final.

This benchmark measures deterministic policy enforcement against scripted proposals. It does not measure real LLM robustness.

Seed: 20261028. Fixed corpus: 200 cases, including attack n=120.

## Overall results

| Condition | Fixed ASR (n=120) | Utility (n=200) | Adapted ASR (n=120) | Benign-confusing directive execution (n=30) | Tool-output FPR |
|---|---:|---:|---:|---:|---:|
| C0 raw | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% (n=18) |
| C1 detector-only | 9.2% | 100.0% | 100.0% | 66.7% | 100.0% (n=18) |
| C2 spotlighting-only | 0.0% | 100.0% | 0.0% | 0.0% | 0.0% (n=18) |
| C3 taintgate | 0.0% | 100.0% | 0.0% | 0.0% | 0.0% (n=18) |

## Category ASR

Fixed payload (n per category as shown):

| Category | n | C0 | C1 | C2 | C3 |
|---|---:|---:|---:|---:|---:|
| I1 | 20 | 100.0% | 25.0% | 0.0% | 0.0% |
| I2 | 25 | 100.0% | 0.0% | 0.0% | 0.0% |
| I3 | 20 | 100.0% | 0.0% | 0.0% | 0.0% |
| I4 | 15 | 100.0% | 0.0% | 0.0% | 0.0% |
| I5 | 10 | 100.0% | 0.0% | 0.0% | 0.0% |
| I6 | 10 | 100.0% | 0.0% | 0.0% | 0.0% |
| I7 | 10 | 100.0% | 60.0% | 0.0% | 0.0% |
| I8 | 10 | 100.0% | 0.0% | 0.0% | 0.0% |

Adapted payload (n per category as shown):

| Category | n | C0 | C1 | C2 | C3 |
|---|---:|---:|---:|---:|---:|
| I1 | 20 | 100.0% | 100.0% | 0.0% | 0.0% |
| I2 | 25 | 100.0% | 100.0% | 0.0% | 0.0% |
| I3 | 20 | 100.0% | 100.0% | 0.0% | 0.0% |
| I4 | 15 | 100.0% | 100.0% | 0.0% | 0.0% |
| I5 | 10 | 100.0% | 100.0% | 0.0% | 0.0% |
| I6 | 10 | 100.0% | 100.0% | 0.0% | 0.0% |
| I7 | 10 | 100.0% | 100.0% | 0.0% | 0.0% |
| I8 | 10 | 100.0% | 100.0% | 0.0% | 0.0% |

## Policy fires

Fixed-payload policy ID fire counts:

| Condition | P1 | P2 | P3 | P4 | P5 | P6 |
|---|---:|---:|---:|---:|---:|---:|
| C0 | 0 | 0 | 0 | 0 | 0 | 0 |
| C1 | 0 | 0 | 0 | 0 | 0 | 0 |
| C2 | 0 | 0 | 0 | 0 | 0 | 0 |
| C3 | 135 | 86 | 76 | 23 | 31 | 0 |

Tool-output FPR is measured over benign cases whose visible content has origin tool_output. C1 counts detector hits in that subset; C0/C2/C3 have no detector-hit FPs under this metric.

## Notes and limitations

- I6 includes its second-stage content in the case and is measured in one proposal/execution pass; this approximates a two-round cascade rather than running an adaptive multi-round agent.
- The corpus uses synthetic, hand-authored templates. Template diversity is limited and does not establish coverage of real attacks.
- ScriptedAgent is SIMULATED; no real LLM is called, so these numbers do not establish model robustness.
- C3 may block benign-confusing directives because their tools or values are untrusted. This is a measured over-blocking cost; the table reports how often those directives executed.
- Local per-condition runtimes (seconds): C0 0.0025, C1 0.0096, C2 0.0012, C3 0.0747.
- Total runner runtime: 0.2374 seconds.
