# ATT&CKLens — Cursor Agent State

**Packet:** 2 — Implementation  
**Status:** MVP implemented; tests passing.

## Completed

| Item | Notes |
| --- | --- |
| `app.py` | Gradio Blocks UI → `analyse_input()` → formatted output |
| `requirements.txt` | `gradio`, `pytest` only |
| `src/core.py` | `analyse_input()`, `format_result()`, schema helpers |
| `src/patterns.py` | Rules: SSH brute force, DNS C2, PowerShell, Nmap scan |
| `src/safety.py` | Empty input, prompt injection, weak-evidence detection |
| `tests/test_core.py` | Acceptance tests from `ACCEPTANCE_TESTS.md` |
| `README.md`, `SECURITY.md` | Usage and safety docs |
| `docs/architecture.md`, `docs/security-notes.md` | Design notes |
| `prompts/system_prompt.txt` | Reference prompt (not sent to paid API) |

## Architecture

- **Deterministic rule engine** — no LLM, no paid APIs, CPU-only.
- **First-match rules** in `src/patterns.py`; default null mapping when no rule fits.
- **Evidence** extracted as literal lines/substrings from input.

## Known limitations

- Small curated rule set; most real-world TTPs will return null mapping.
- Prompt-injection detection is phrase-based, not comprehensive.
- Gradio launch not automated in CI (import smoke test only).

## Test results

Run: `pytest -q`

Expected: all tests in `tests/test_core.py` pass.

Manual: `python app.py` → UI with text box and Analyse button.

## Next step (packet 3)

- Debug any failing acceptance checks from manual Gradio testing.
- Optional: expand rules for remaining `sample_inputs/` files.

## Issues

- None at implementation time.
