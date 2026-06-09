# ATT&CKLens — Extended Security Notes

This document expands on `SECURITY.md` with implementation detail and the threat
model for the tool itself. ATT&CKLens is defensive, offline, and processes
untrusted text.

## Threat model

| Threat | Mitigation |
| --- | --- |
| **Prompt injection** ("ignore previous instructions", "reveal the system prompt") | `safety.detect_prompt_injection` matches override/exfiltration phrasings; input is refused and never treated as instructions. No internal charter is ever echoed. |
| **Offensive-use solicitation** ("write me an exploit", "how to evade EDR") | `safety.detect_offensive_request` detects and refuses; the engine only emits defensive guidance. |
| **Hallucinated / fabricated mappings** | Evidence is quoted verbatim from input; no match → `null` mapping with `why_not`. Confidence never `high` without ≥2 indicators. |
| **Crash on malformed input** | `safety.is_empty` guards empty/short input; `analyze_input` always returns a schema-complete dict and never raises on user input. |
| **Data leakage / persistence** | Input is processed in memory only. No disk writes, no network calls, no telemetry. |
| **Dependency / supply-chain risk** | Minimal dependencies (`gradio`, `pytest`); no offensive libraries, no remote model calls. |

## Why a deterministic engine is safer here

- **No model = no model-level jailbreaks.** The MVP cannot be coerced into
  generating novel offensive content because it does not generate free-form text;
  it selects from curated, reviewed defensive guidance.
- **Auditable.** Every possible output originates from `src/patterns.py` or a
  small set of fixed strings in `src/core.py`, all human-reviewable.
- **Reproducible.** Identical input → identical output, which matters for a fair
  benchmark and for incident documentation.

## Known limitations & residual risk

- **Pattern coverage is finite.** Novel phrasings of injection or offensive
  requests may not match the current regex lists. The lists in `src/safety.py`
  are easy to extend; new bypasses found during evaluation should be added there.
- **Heuristic confidence.** Confidence reflects indicator count, not true
  likelihood. Analysts must apply judgement.
- **Not a detection control.** Detection ideas are conceptual query descriptions,
  not validated rules; test before deploying anything derived from them.

## Operational guidance

- Run only on synthetic or explicitly authorised lab data.
- Do not paste real secrets, credentials, PII, or production logs.
- Treat all output as a starting hypothesis for investigation.
