# TaintWall

TaintWall is a runtime firewall for AI agents: it tracks where every tool-call argument came from and enforces deterministic policies at the tool boundary, so instructions hidden in documents can observe but not command.

## Results — task-embedded procedure, qwen2.5:14b (16 cases)

| Condition | ASR | Utility |
|---|---:|---:|
| C0 | 0.875 | 0.812 |
| C1 | 0.250 | 0.438 |
| C2 | 0.625 | 0.562 |
| C3 | 0.000 | 0.750 |
| C4 | 0.000 | 0.562 |

This measures a task-embedded attack axis where attacks occurred; the calibration probe (IFR 0.80 for C0) checks that the model followed harmless embedded instructions. See the [Phase 2 report](reports/phase2-final.md) and [GATE2](GATE2.md) for scope and limitations.

## 30-second demo

Run the deterministic, offline runbook scenario:

```sh
python scripts/demo_runbook.py
```

The demo prints each proposed tool step under C0 and C3. C0 executes the malicious extra transfer. C3 allows the legitimate steps and blocks that same transfer with policy ID P2. All effects are recorded in in-memory mock tools; no LLM or external service is used.

## How it works

**Provenance attribution** is deterministic and argument-level. It matches normalized argument values and destination entities against visible segments, then carries source labels and taint roots forward. Unmatched destinations conservatively inherit visible untrusted provenance.

**Intent** comes from an explicit annotation: the authorized tool set and the recipients named by the user. The model does not infer consent.

The boundary evaluates these policies before tool execution:

| Policy | Enforcement |
|---|---|
| P1 | Untrusted content cannot start a tool type outside the user's authorized set. |
| P2 | An untrusted destination is blocked unless the user explicitly named it. |
| P3 | Private or secret data cannot be sent to a non-explicit recipient. |
| P4 | Untrusted arguments to irreversible tools require approval. |
| P5 | Untrusted content cannot be persisted as instructions. |
| P6 | A secret-labeled argument may be sent to an explicit recipient after redaction. |

**Quarantine Extractor (C4)** converts untrusted content into a structured data representation. Extraction is not sanitization: source taint roots remain attached. Invalid extraction output fails closed and is dropped.

## What it does not claim

- The explicit I1–I8 ASR axis was not evaluated at this model level: C0 ASR was 0/40. The calibration IFR of 0.80 shows that the model followed harmless embedded formatting instructions, but it did not turn the explicit action payloads into successful actions.
- The measurements cover one model family, Qwen2.5, at two sizes.
- PREVIEW results use deterministic subsamples and one trial.
- The harness renders conversation history as text rather than native provider tool-use/result blocks.
- These results do not establish production robustness or behavior for other models and attack distributions.

## Reproduce

Use Python 3.11 or newer. Phase 1 is the SIMULATED policy-enforcement benchmark:

```sh
python -m pip install -e ".[dev]"
python scripts/run_bench.py
python -m pytest -q
```

For the local Phase 2 preview, install and start Ollama separately, then run:

```sh
ollama pull qwen2.5:14b
python scripts/run_llm_bench.py --ollama --preview --model qwen2.5:14b --sections baseline,calibration,procedure --max-usd 10
```

The Phase 2 command uses mock tools and does not connect to external services. The preview and GATE2 remain provisional.

## License and transfer

All rights reserved. This software is published for evaluation purposes. Commercial licensing and transfer are available on request; no other rights are granted. See [LICENSE](LICENSE).

## Contact

https://nagayu-portfolio.nagayu.workers.dev/en
