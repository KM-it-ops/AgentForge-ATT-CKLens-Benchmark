# ATT&CKLens — Cursor Agent State

**Packet:** 1 — Build Brief  
**Status:** Planning complete; no app code written yet.

## Requirements Summary

Build **ATT&CKLens**, a local Python/Gradio MVP that:

- Accepts **one plain-text security observation** per run (logs, alerts, scan summaries, network notes, narrative).
- Returns a **JSON-serialisable dict** with: `summary`, `tactic`, `technique_id`, `evidence`, `confidence`, `why_not`, `detection_idea`, `network_investigation`, `remediation`, `analyst_questions`.
- Maps to MITRE ATT&CK **only when evidence supports it**; otherwise `tactic`/`technique_id` = `null` with `why_not`.
- Cites **quoted input fragments** in `evidence`; no fabricated details.
- Uses **high/medium/low** confidence honestly.
- Runs via `python app.py`, CPU-only, minimal deps, Hugging Face Space–compatible.
- Handles empty/unparseable input with clear errors (no crash).

**Out of scope:** PCAP upload, live Splunk, live ATT&CK fetch, persistence, paid APIs, auth/DB.

## Proposed File Structure

```
app.py                    # Gradio UI entry point
requirements.txt          # gradio, pytest (minimal)
src/
  __init__.py
  core.py                 # analyse_input(), output schema assembly
  patterns.py             # Small curated evidence → ATT&CK pattern rules
  safety.py               # Input validation, prompt-injection handling
prompts/
  system_prompt.txt       # Defensive analysis instructions (reference for logic/docs)
tests/
  test_core.py            # Acceptance tests from ACCEPTANCE_TESTS.md
docs/
  architecture.md         # Data flow, module roles
  security-notes.md       # Safety design notes
STATE.md
README.md                 # (packet 4)
SECURITY.md               # (packet 4)
```

## Implementation Plan

| Step | Deliverable |
| --- | --- |
| 1 | `STATE.md` plan (this file) |
| 2 | `requirements.txt`, `src/safety.py`, `src/patterns.py`, `src/core.py` |
| 3 | `app.py` — Gradio textbox → analyse → formatted JSON + readable summary |
| 4 | `tests/test_core.py` — SSH brute force, ambiguous input, injection, DNS network case, empty input |
| 5 | Fix failures only; run `pytest` |
| 6 | `README.md`, `SECURITY.md`, `docs/*` |

**Core API:** `analyse_input(text: str) -> dict` — single entry for UI and tests.

**Mapping approach:** Rule-based pattern matching on keywords/phrases (no paid LLM, no external fetch). Small curated rules for acceptance-test scenarios plus a safe default that returns `null` mappings when no rule matches.

**UI:** Gradio `Blocks` — input textarea, Submit, output area showing structured result.

## Safety Constraints

- **Defensive only** — detection, investigation, remediation; never exploit/bypass/evasion guidance.
- **No real data** — lab/synthetic inputs only.
- **Prompt injection** — treat input as untrusted; detect override/reveal-prompt attempts; refuse without leaking `prompts/system_prompt.txt` or internal logic.
- **Honest nulls** — vague input → `tactic`/`technique_id` null, `confidence` low, `why_not` explains gap.
- **Evidence discipline** — quote only substrings present in input.
- **No harmful remediation** — e.g. do not suggest disabling MFA or security tools.

## Assumptions

- **Heuristic core** (not an LLM call) satisfies “no paid APIs” and HF CPU deployment; patterns cover MVP acceptance tests, not full ATT&CK coverage.
- Python **3.9+**; Gradio **4.x** (latest stable compatible with HF Spaces).
- `technique_id` may include human-readable name in parentheses when known (per SPEC).
- `prompts/system_prompt.txt` documents intent; runtime logic enforces the same rules in code.
- Tests run headless against `analyse_input()`; Gradio launch verified manually or via import smoke test.

## Next Step

Implement **packet 2**: create `requirements.txt`, `src/safety.py`, `src/patterns.py`, `src/core.py`, and `app.py` with minimal Gradio shell wired to `analyse_input()`.
