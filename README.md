# ATT&CKLens

ATT&CKLens is a defensive Python/Gradio tool that maps **sample security observations** to MITRE ATT&CK tactics and techniques. It is intended for **educational use in lab environments** with synthetic or anonymised data.

## Features

- Accepts one text observation per run (logs, alerts, scan summaries, network notes).
- Returns structured JSON fields: summary, tactic, technique, evidence, confidence, detection ideas, remediation, and analyst questions.
- Uses **local deterministic rules** — no paid APIs, GPU, database, or login.
- Declines to map when evidence is weak and explains why.
- Resists basic prompt-injection attempts.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
python app.py
```

Open the Gradio URL shown in the terminal (typically `http://127.0.0.1:7860`).

## Usage

1. Paste a single observation into the text box.
2. Click **Analyse** (or press Enter).
3. Review the human-readable summary and JSON output.

### Example inputs

| Input | Expected behaviour |
| --- | --- |
| `Failed SSH login from 10.0.0.5 for user root` | Maps to Credential Access / T1110 (Brute Force) |
| `User reported that the system seemed slow yesterday.` | No mapping; low confidence |
| `Repeated DNS requests to suspicious-domain.com every minute from 192.168.1.42` | Command and Control; network investigation guidance |
| Prompt injection text | Refusal; no system prompt leakage |

Sample files are in `sample_inputs/`.

## Testing

```bash
pytest -q
```

Manual smoke test:

```bash
python app.py
```

Confirm the UI loads with a text box and **Analyse** button.

## Project layout

```
app.py              # Gradio entry point
requirements.txt
src/
  core.py           # analyse_input(), formatting
  patterns.py       # Curated mapping rules
  safety.py         # Validation and injection detection
tests/test_core.py
prompts/system_prompt.txt
docs/
```

## Limitations

- Rule-based mapping covers a **small curated set** of patterns, not the full ATT&CK framework.
- Outputs are heuristic suggestions, not professional incident conclusions.
- Do not upload real organisational logs or secrets.

## Deployment (Hugging Face Spaces)

- Runtime: Python 3.9+
- Entry: `python app.py` or configure Gradio app as `app.py`
- Dependencies: `requirements.txt` only
- CPU-only; no secrets required

## Security

See `SECURITY.md` and `docs/security-notes.md`.

## Licence / disclaimer

Educational and defensive use only. Verify all findings before acting in production environments.
