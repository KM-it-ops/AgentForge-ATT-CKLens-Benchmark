# Architecture

## Overview

ATT&CKLens is a single-process Python application with two layers:

1. **UI** — `app.py` (Gradio)
2. **Core** — `src/` (deterministic analysis)

No database, authentication, or external API calls.

## Data flow

```
User text
   │
   ▼
app.run_analysis()
   │
   ▼
src.core.analyse_input()
   │
   ├─► src.safety  (empty check, prompt injection, weak-evidence hints)
   │
   ├─► src.patterns (first matching MappingRule)
   │
   └─► default no-mapping result
   │
   ▼
src.core.format_result()  →  Gradio text output
```

## Modules

| Module | Responsibility |
| --- | --- |
| `app.py` | Gradio layout, wires submit to `analyse_input` |
| `src/core.py` | Public API, result schema, formatting |
| `src/patterns.py` | Curated `MappingRule` definitions |
| `src/safety.py` | Input normalisation, injection/weak-evidence detection |

## Mapping rules

Each `MappingRule` defines:

- A matcher function (keyword/regex heuristics on normalised text)
- ATT&CK tactic and technique ID
- Confidence level
- Defensive fields (detection, remediation, analyst questions)
- Keywords used to extract **quoted evidence lines** from the input

Rules are evaluated **in order**; the first match wins. If none match, a low-confidence null mapping is returned.

## Output schema

All results include the keys defined in `expected_behaviors/expected_output_schema.json`. Values may be `null` where the spec allows.

## Extension points

- Add rules in `src/patterns.py` (preferred for MVP scope).
- Expand `src/safety.py` patterns for additional injection phrases.
- Add pytest cases mirroring new rules in `tests/test_core.py`.

Avoid adding LLM calls, databases, or network fetches without revisiting `SPEC.md` and `SAFETY_RULES.md`.

## Deployment

- **Local:** `python app.py`
- **Hugging Face Spaces:** CPU Python space with `requirements.txt`; entry file `app.py`
