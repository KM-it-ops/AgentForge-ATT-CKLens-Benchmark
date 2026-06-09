# Security Notes

Implementation-specific safety design for ATT&CKLens (Cursor agent build).

## Threat model (MVP)

| Threat | Mitigation |
| --- | --- |
| Prompt injection | Regex checks in `src/safety.py`; early return with refusal, no prompt text in output |
| Offensive guidance | Rule templates contain only defensive language; no exploit/evasion strings |
| Overconfident mapping | Weak-evidence heuristics + default null mapping with `why_not` |
| Hallucinated evidence | `extract_evidence()` only returns substrings from user input |
| Sensitive data exposure | No logging, persistence, or outbound network from core logic |

## Prompt injection

Detected phrases include variants of:

- "ignore previous instructions"
- "reveal/show system prompt"

On match, `analyse_input()` returns a refusal dict. The real system prompt in `prompts/system_prompt.txt` is **never** loaded into the user-visible response path.

## Mapping discipline

- Rules are explicit and ordered; there is no open-ended LLM reasoning.
- Ambiguous inputs (e.g. "seemed slow") hit weak-evidence detection or fall through to null mapping.
- Confidence is set per rule (`high` / `medium` / `low`), not inflated.

## What this MVP does not protect against

- Sophisticated multi-turn jailbreaks beyond simple phrase matching.
- Adversarial unicode homoglyphs or encoded injection payloads.
- Comprehensive ATT&CK coverage — unknown TTPs will not map.

## Testing safety behaviour

```bash
pytest tests/test_core.py -k injection
pytest tests/test_core.py -k mapping
```

Manual check: submit injection text in the Gradio UI and confirm refusal without internal prompt leakage.

## Operational guidance

- Run on lab data only.
- Do not disable host security controls based on tool output.
- Re-verify mappings against primary log sources before incident response actions.
