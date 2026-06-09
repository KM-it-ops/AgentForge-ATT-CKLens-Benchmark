# STATE — ATT&CKLens (Claude Code attempt)

_Last updated: 2026-06-08 · Packet 2 (Implementation) — MVP complete_

## Current branch
`agent/claude-code-attacklens`

## Status: MVP implemented and tested ✅
- 12/12 unit tests pass (`python -m pytest -q`, 0.05s).
- `python -c "import app; app.build_demo()"` builds the Gradio UI cleanly (Gradio 5.50).
- Deterministic, offline rule engine — no LLM, no network, no paid APIs, CPU-only.

## Requirements summary
- Map ONE security observation → likely MITRE ATT&CK tactic/technique with structured
  defensive output. Inputs: log/alert/scan/packet-note/narrative as plain text.
- Output dict (all 10 keys): `summary`, `tactic`, `technique_id`, `evidence[]`,
  `confidence` (high|medium|low), `why_not`, `detection_idea`, `network_investigation`,
  `remediation`, `analyst_questions[]`.
- No forced mapping; quote evidence verbatim; calibrated confidence; defensive-only;
  prompt-injection resistant; no persistence; Gradio UI launched via `python app.py`.

## Architecture (as built)
Clean UI / orchestration / data / safety separation:
- `app.py` — Gradio UI only; calls `core.analyze_input`; renders readable Markdown + raw JSON.
- `src/core.py` — `analyze_input(text)` orchestrator. Pipeline: validate → injection screen
  → offensive screen → `patterns.match` → confidence scoring → `build_result` (guarantees
  all 10 schema keys). Never raises on user input.
- `src/patterns.py` — `Signature` dataclass + curated `SIGNATURES` table (6 techniques:
  T1110, T1059.001, T1046, T1071.004, T1003, T1566) + `match()` (verbatim evidence, scored).
- `src/safety.py` — `is_empty`, `detect_prompt_injection`, `detect_offensive_request`,
  safe refusal summaries. Untrusted-input handling; never leaks the charter.
- `prompts/system_prompt.txt` — defensive operating charter (audit trail; no LLM in MVP).

Confidence rule: ≥2 distinct indicators → high, 1 → medium, 0 → low (no-mapping path).

## Files created/updated this packet
- `app.py`, `requirements.txt` (gradio, pytest)
- `src/__init__.py`, `src/core.py`, `src/patterns.py`, `src/safety.py`
- `tests/__init__.py`, `tests/test_core.py`
- `prompts/system_prompt.txt`, `examples/sample_inputs.txt`
- `README.md` (replaced benchmark README with ATT&CKLens app README; benchmark README
  preserved on `main`/git history), `SECURITY.md`
- `docs/architecture.md`, `docs/security-notes.md`
- `STATE.md` (this file)

## Acceptance test coverage (ACCEPTANCE_TESTS.md → tests/test_core.py)
1. Successful launch — verified via `import app; build_demo()` (no crash).
2. Basic mapping — failed SSH → `Credential Access` / `T1110`, evidence quotes
   "Failed SSH login", confidence medium, MFA remediation. ✅
3. No clear mapping — "system seemed slow" → null/null, low, `why_not` set. ✅
4. Prompt injection — refused; no internal prompt leaked. ✅
5. Network investigation — DNS beacon → `network_investigation` with DNS guidance,
   `Command and Control` / `T1071.004`. ✅
   Plus: PowerShell T1059.001, Nmap T1046, empty input (parametrized), offensive
   refusal, schema completeness, no-fabricated-evidence.

## Safety constraints (enforced)
- Defensive only; offensive/evasion requests refused (`detect_offensive_request`).
- Input untrusted; injection refused; charter never revealed.
- Honest limitations (null + `why_not`); evidence quoted verbatim only.
- Calibrated confidence; never high on vague input.
- Best-practice remediation only; no control-weakening advice.
- No persistence/transmission; fully local.

## Assumptions (confirmed during build)
1. Deterministic rule engine satisfies the spec (no API/network permitted). ✅
2. Small curated signature table = correct reading of "don't hard-code MITRE lists". ✅
3. System prompt embedded as a file for auditability though no LLM is used. ✅
4. README decision (Packet-1 open item): replaced root README with the app README;
   benchmark README remains on `main`. ✅
5. Python 3.9+ compatible (uses `from __future__ import annotations`; local env 3.14). ✅

## Next step
Packet 3+ (optional): self-review against EVAL_RUBRIC.md; expand signature/guard lists
if evaluation surfaces gaps; consider score-ranked multi-candidate output. Otherwise the
MVP is feature-complete and ready to run via `python app.py`.
