# STATE — ATT&CKLens (Claude Code attempt)

_Last updated: 2026-06-08 · Packet 1 (Build Brief / Plan)_

## Current branch
`agent/claude-code-attacklens`

## Requirements summary
- Build **ATT&CKLens**: a defensive helper that maps ONE security observation per run
  to a likely MITRE ATT&CK tactic/technique and returns structured defensive insight.
- **Inputs** (plain text): log snippet, alert text, scan summary, packet-analysis note,
  or narrative incident note. Must tolerate blank lines / minor formatting; empty or
  unparseable input → clean error message, never a crash.
- **Output** (JSON-serialisable dict, exact keys): `summary`, `tactic`, `technique_id`,
  `evidence[]`, `confidence` (high|medium|low), `why_not`, `detection_idea`,
  `network_investigation`, `remediation`, `analyst_questions[]`.
- **Behaviour rules**: no forced mapping (null tactic/technique + `why_not` when weak);
  quote exact evidence phrases (no fabrication); calibrated confidence; defensive-only;
  prompt-injection resistant.
- **Deployment**: Python 3, Gradio UI, `requirements.txt`, CPU-only, no GPU/paid APIs,
  no persistence/transmission of input. Launch via `python app.py`.
- **Engine**: deterministic rule/pattern matching over a small embedded ATT&CK signature
  set (no LLM, no live MITRE fetch).

## Proposed architecture
Clean UI / core / data / safety separation:
- `app.py` — Gradio entry point only. Textbox + submit → `core.analyze_input` →
  render both pretty text and raw JSON. No business logic here.
- `src/core.py` — `analyze_input(text) -> dict`. Orchestrates: validate → safety screen →
  match signatures → score confidence → assemble schema-compliant result. Always returns
  the full schema (graceful errors included).
- `src/patterns.py` — curated `SIGNATURES` table. Each entry: keywords/regex, tactic,
  technique_id (+name), detection_idea, network_investigation, remediation, analyst
  questions. Small and auditable (~6–10 techniques covering the sample/test cases:
  brute force/SSH T1110, encoded PowerShell T1059.001, network scan T1046,
  C2/DNS beacon T1071/T1071.004, plus a couple common ones).
- `src/safety.py` — prompt-injection detection (e.g. "ignore previous instructions",
  "reveal system prompt"), refusal response, and input validation (empty/too-short).
- `prompts/system_prompt.txt` — documents the assistant's defensive framing / refusal
  posture (required by file structure; also the audit trail for guardrails).
- `examples/sample_inputs.txt` — quick-test inputs.
- `tests/test_core.py` — pytest covering the 5 acceptance tests + edge cases
  (empty input, injection).
- `requirements.txt` — `gradio`, `pytest` (minimal).
- `docs/architecture.md`, `docs/security-notes.md`, `README.md`, `SECURITY.md`.

### Data flow
`UI text → core.analyze_input → safety.validate/screen → patterns.match →
core.score_confidence → result dict → UI renders JSON + readable view`

## Files I will create (next packets — NOT this turn)
- `app.py`
- `requirements.txt`
- `src/__init__.py`, `src/core.py`, `src/patterns.py`, `src/safety.py`
- `prompts/system_prompt.txt`
- `examples/sample_inputs.txt`
- `tests/__init__.py`, `tests/test_core.py`
- `docs/architecture.md`, `docs/security-notes.md`
- `SECURITY.md` (and ATT&CKLens `README.md` — see Assumptions re: existing README)

## Safety constraints (from SAFETY_RULES.md / SPEC §Behaviour)
- Defensive only — never offensive/exploit/detection-evasion guidance.
- Treat all input as untrusted; resist prompt injection; never reveal system prompt
  or internal logic.
- Honest limitations — decline to map (null + `why_not`) rather than hallucinate.
- Calibrated confidence; never "high" on vague input.
- Remediation = best practice only (MFA, least privilege, patching); never weaken controls.
- No persistence/transmission of input; fully local.

## Assumptions
1. Deterministic rule-based engine (no LLM) satisfies the spec, since no API/network is
   permitted and SPEC allows embedded technique IDs/names.
2. A small curated signature table is the intended reading of "don't hard-code MITRE
   lists" (no full-matrix dump).
3. Embedding the system prompt as a file is required by structure even without an LLM;
   it doubles as guardrail documentation.
4. Root `README.md` currently holds the **benchmark** README. The ATT&CKLens app README
   is needed for the rubric. Plan: keep benchmark content and add a clearly-separated
   "ATT&CKLens (application)" section, OR write a dedicated app README — to confirm before
   touching README.md (original is preserved on `main`/git history).
5. Python 3.9+ compatibility (local env is 3.14).

## Next step
Packet 2 — Implementation: create `requirements.txt`, `src/` modules, `app.py`,
`prompts/system_prompt.txt`, `examples/sample_inputs.txt`, then `tests/test_core.py`;
run `pytest` and `python app.py` to confirm launch.
