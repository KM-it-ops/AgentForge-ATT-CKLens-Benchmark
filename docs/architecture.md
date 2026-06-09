# ATT&CKLens Architecture

## Goals

- Map one security observation to a likely MITRE ATT&CK tactic/technique.
- Be **deterministic, offline, and dependency-light** (no LLM, no network, no
  paid APIs, CPU-only, Hugging Face Spaces compatible).
- Keep UI, orchestration, data, and safety concerns separate.

## Component overview

```
┌────────────┐      ┌──────────────────┐      ┌────────────────┐
│  app.py    │────▶ │  src/core.py     │────▶ │ src/patterns.py│
│  (Gradio)  │      │  analyze_input   │      │  SIGNATURES +  │
│  thin UI   │◀──── │  orchestration   │◀──── │  match()       │
└────────────┘      └───────┬──────────┘      └────────────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │  src/safety.py │
                    │  validate +    │
                    │  injection /   │
                    │  offensive     │
                    └────────────────┘
```

## Data flow

1. **UI** (`app.py`) collects text and calls `analyze_input`. It renders the
   result twice: a human-readable Markdown view and the raw JSON object. It holds
   no analysis logic.
2. **Validation** (`safety.is_empty`): empty/too-short input returns a clear
   "no analysable input" result — never an exception.
3. **Safety screens** (`safety.detect_prompt_injection`,
   `safety.detect_offensive_request`): hostile or offensive input is refused with
   a safe, schema-complete result before any mapping is attempted.
4. **Matching** (`patterns.match`): the input is tested against each `Signature`'s
   regex indicators. Each hit yields a verbatim evidence fragment and increments
   the signature's score. Results are sorted by score (table order breaks ties).
5. **Assembly** (`core._mapped_result` / `core._no_mapping_result`): the top
   match becomes the mapping; confidence is derived from the indicator count;
   `why_not` records competing techniques or weak-evidence caveats. If nothing
   matches, a `null` mapping with an explanatory `why_not` is returned.

## Key design decisions

- **Rule engine, not an LLM.** The spec forbids network/paid APIs and permits
  embedded technique IDs, so a curated regex signature table is the right fit. It
  is deterministic (reproducible benchmark runs) and fully auditable.
- **Small, curated signature table.** `src/patterns.py` covers a handful of
  common techniques (T1110, T1059.001, T1046, T1071.004, T1003, T1566). This is a
  deliberate reading of "don't hard-code the full MITRE matrix": signatures are
  curated, not a bulk dump. Inputs outside the table return *no mapping* rather
  than a guess.
- **Schema completeness by construction.** `core.build_result` is the single
  place a result is created; every path returns all ten schema keys, so the UI
  and tests never see a missing field.
- **Confidence from evidence count.** `>=2` distinct indicators → `high`, exactly
  `1` → `medium`, none → `low`. Simple, explainable, and conservative.
- **Evidence is quoted verbatim.** `patterns._find_evidence` returns the matched
  substring from the original text, so the tool cannot fabricate wording.

## Extensibility

- Add a technique by appending a `Signature` to `SIGNATURES` — no other code
  changes required.
- An LLM backend could later sit behind the same `prompts/system_prompt.txt`
  charter and reuse `safety.py` and the result schema unchanged.

## Testing

`tests/test_core.py` exercises the five acceptance scenarios plus empty input,
offensive requests, schema completeness, and the "no fabricated evidence"
guarantee. Run with `python -m pytest -q`.
