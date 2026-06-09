# Security Policy

ATT&CKLens is designed for **defensive, educational** use in authorised lab environments.

## Intended use

- Learn how common observations relate to MITRE ATT&CK.
- Explore detection and remediation ideas on **synthetic or anonymised** sample data.
- Run locally or on Hugging Face Spaces without transmitting data to paid third-party APIs.

## Prohibited use

- Analysing real production logs without explicit authorisation.
- Uploading credentials, secrets, or sensitive organisational data.
- Using outputs to plan unauthorised access, exploitation, evasion, or control bypass.

## Safety controls

1. **Defensive outputs only** — remediation and detection guidance; no exploit or evasion instructions.
2. **Honest uncertainty** — weak evidence yields `null` mappings and low confidence.
3. **Evidence quoting** — conclusions cite substrings from user input; no fabricated indicators.
4. **Prompt injection handling** — attempts to override instructions or reveal prompts are refused.
5. **No persistence** — inputs are not stored by the application.

## Reporting issues

If you discover unsafe behaviour in this implementation, document the input and output and update the test suite in `tests/test_core.py`.

## Operator responsibilities

- Use only data you are authorised to analyse.
- Treat ATT&CKLens output as advisory, not authoritative.
- Follow your organisation's security and privacy policies.

See also `SAFETY_RULES.md` (benchmark spec) and `docs/security-notes.md` (implementation details).
