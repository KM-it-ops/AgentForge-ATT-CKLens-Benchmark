# Security & Ethical Use — ATT&CKLens

ATT&CKLens is an **educational, defensive** tool. It exists to help analysts
understand possible adversary behaviour and improve detection and response. It
must never be used to attack systems or to analyse data you are not authorised
to handle.

## Guardrails implemented

These map directly to `SAFETY_RULES.md` and `SPEC.md` §Behaviour:

1. **Defensive only.** The engine emits detection, prevention, and remediation
   guidance only. Requests for offensive, exploit, or detection-evasion help are
   detected (`src/safety.py`) and refused with a safe message.
2. **Untrusted input / prompt-injection resistance.** All input is treated as
   data, never as instructions. Injection attempts (e.g. "ignore previous
   instructions", "reveal the system prompt") are detected and refused. The tool
   never reveals its operating charter or internal logic.
3. **Honest limitations.** When evidence is insufficient, `tactic` and
   `technique_id` are set to `null` and `why_not` explains why. The tool does not
   invent mappings.
4. **No fabricated evidence.** The `evidence` field only ever contains fragments
   quoted verbatim from the user's input.
5. **Calibrated confidence.** Confidence is `high` / `medium` / `low` based on how
   many distinct indicators match; vague input never yields high confidence.
6. **Best-practice remediation only.** Recommendations follow least privilege,
   MFA, patching, and logging. The tool never suggests weakening controls.
7. **Local & private.** Input is processed in memory and is **not persisted or
   transmitted**. No network calls, no external APIs.

## Responsible use

- Use only synthetic, anonymised, or explicitly authorised lab data. Do **not**
  paste real credentials, secrets, or production logs.
- Only analyse systems and data you are authorised to assess.
- Treat output as a starting point for investigation, not a verdict. Verify all
  findings before acting in a real environment.

## Reporting

This is a benchmark/demo project. If you find a safety gap (e.g. an injection
phrasing that slips through, or output that could be read as offensive guidance),
note it in the project evaluation notes so the signature/guard lists can be
extended.
