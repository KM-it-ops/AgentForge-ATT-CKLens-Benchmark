# ATT&CKLens

ATT&CKLens is a small defensive Python/Gradio application for mapping synthetic security observations to MITRE ATT&CK-style tactics, techniques, evidence, detection ideas, remediation, and analyst follow-up questions.

The project is designed for the AgentForge benchmark. This Codex branch contains a deterministic local MVP with no paid APIs, no GPU requirement, and no live data fetching.

## Features

- Accepts one plain-text security observation at a time.
- Returns the JSON-serializable schema required by `SPEC.md`.
- Quotes supporting evidence from the input.
- Declines to map vague or insufficient evidence.
- Refuses prompt-injection attempts that ask for hidden prompts or internal instructions.
- Provides defensive detection, remediation, and network investigation guidance when applicable.

## Setup

Create and activate a virtual environment:

```powershell
python3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the App

```powershell
python app.py
```

Gradio will print a local URL. Open it in a browser and paste one of the examples from `sample_inputs/`.

## Run Tests

```powershell
pytest
```

The tests cover the benchmark sample inputs, schema shape, no-clear-mapping behavior, empty input handling, and prompt-injection refusal.

## Project Structure

```text
app.py
requirements.txt
src/
  __init__.py
  core.py
tests/
  test_core.py
prompts/
  system_prompt.txt
examples/
  sample_inputs.txt
docs/
  architecture.md
SECURITY.md
STATE.md
```

## Supported MVP Scenarios

- Failed SSH login bursts: `Credential Access`, `T1110 (Brute Force)`.
- Suspicious encoded PowerShell: `Execution`, `T1059.001 (PowerShell)`.
- Repeated suspicious DNS requests: `Command and Control`, `T1071.004 (Application Layer Protocol: DNS)`.
- Nmap-style port scan summaries: `Discovery`, `T1046 (Network Service Discovery)`.
- Ambiguous observations: no mapping with low confidence and follow-up questions.

## Safety and Limitations

Use only synthetic, anonymised, or authorised lab data. ATT&CKLens does not replace professional analysis and does not include a complete ATT&CK knowledge base. It avoids offensive guidance and returns no mapping when evidence is too weak.
