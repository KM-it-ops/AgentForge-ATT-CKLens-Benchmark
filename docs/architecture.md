# ATT&CKLens Architecture

ATT&CKLens is intentionally small and deterministic. It runs locally, accepts one synthetic security observation, and returns a JSON-serializable defensive analysis.

## Components

- `src/core.py` contains all mapping behavior. It exposes `analyse_input` for structured output and `format_analysis` for Markdown rendering.
- `app.py` builds the Gradio UI and delegates analysis to `src/core.py`.
- `tests/test_core.py` validates the sample inputs, output schema, no-map behavior, and prompt-injection refusal.
- `prompts/system_prompt.txt` documents the safety posture even though the MVP does not call an LLM.

## Data Flow

1. A user enters one synthetic observation into the Gradio text box.
2. `app.py` calls `analyse_input`.
3. `src/core.py` checks empty input, prompt-injection patterns, and a small set of defensive mapping rules.
4. The result is returned as a dictionary with the fields required by `SPEC.md`.
5. The UI renders both readable Markdown and the structured JSON object.

## Mapping Strategy

The MVP uses narrow evidence patterns for the benchmark scenarios:

- Failed SSH authentication maps to `T1110 (Brute Force)`.
- Encoded PowerShell usage maps to `T1059.001 (PowerShell)`.
- Repeated suspicious DNS requests map to `T1071.004 (Application Layer Protocol: DNS)`.
- Port scan summaries map to `T1046 (Network Service Discovery)`.

Inputs that do not match observable security behavior return `null` for `tactic` and `technique_id`.

## Limitations

- This is not a complete ATT&CK knowledge base.
- It does not fetch live MITRE data or call paid APIs.
- It does not process real PCAP files, binary data, or production telemetry.
- Findings are educational hints and must be verified by an analyst.
