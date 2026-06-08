# Agent Instructions

This file contains general instructions that should be supplied to all AI coding agents taking part in the ATT&CKLens build experiment.  Each agent will receive the specification, safety rules and budget described elsewhere in this repository.  These instructions set baseline expectations and provide guidance on how to approach the task.

## What You Are Building

You are tasked with building **ATT&CKLens**, a simple Python application that helps map sample security observations to MITRE ATT&CK tactics and techniques.  The full specification is in `SPEC.md`.  Read it carefully and do not implement features outside the MVP scope.

## Constraints

* **Ethical Behaviour** – Follow all safety rules in `SAFETY_RULES.md`.  Do not provide offensive or exploitative advice.  Decline to map when evidence is insufficient.
* **Environment** – Use Python 3 and Gradio for the user interface.  Do not rely on paid APIs.  The application must run locally and on Hugging Face Spaces without GPU.
* **Modularity** – Keep your code organised.  Separate the core logic from the UI.  Do not write everything in a single monolithic function.
* **Documentation** – Produce a comprehensive `README.md` that answers the questions listed in the project overview.  Include a `SECURITY.md` explaining safety considerations.
* **State Tracking** – Maintain a `STATE.md` file in your branch that summarises changes after each step.  This allows the controlling user to resume sessions without reloading the full context.

## File Structure

When implementing the MVP, adhere to the following structure:

```
app.py                  # Entry point launching the Gradio app
requirements.txt        # Python dependencies
src/
    core.py            # Core logic functions (analyse_input, map_attack, etc.)
prompts/
    system_prompt.txt  # System prompt used by any language model calls
examples/
    sample_inputs.txt  # Sample inputs for quick testing
docs/
    architecture.md    # Description of the architecture, data flow and design
    security-notes.md  # Extended security considerations
STATE.md               # Summary of current state after each prompt
README.md              # Project overview and usage instructions
SECURITY.md            # Reiteration of safety rules and ethical use
```

Feel free to adjust file names as needed, but maintain a similar level of organisation.

## Working Procedure

1. **Read the Spec** – Start by reading `SPEC.md`, `SAFETY_RULES.md` and `TOKEN_BUDGET.md`.  Confirm your understanding in `STATE.md`.
2. **Plan** – Outline your design and file structure.  Describe modules and functions you intend to implement.  Record this plan in `STATE.md`.
3. **Implement** – Write code according to your plan.  Generate only the files relevant to the MVP.  Run acceptance tests to verify functionality.
4. **Debug** – If tests fail, fix only the failing parts.  Do not rewrite the entire project.  Document fixes and remaining issues in `STATE.md`.
5. **Document** – Write `README.md`, `SECURITY.md` and any additional docs.  Ensure they reflect the implemented code and mention limitations.
6. **Self‑Review** – Evaluate your work against the acceptance tests and rubric.  Highlight strengths and weaknesses in `STATE.md`.

## Dos and Don’ts

**Do**

* Follow the spec exactly; ask for clarification if something is unclear.
* Keep outputs deterministic and structured.
* Admit uncertainty where appropriate.
* Handle bad input gracefully.
* Remain within the token budget and summarise state after each prompt.

**Don’t**

* Do not hard‑code MITRE ATT&CK lists or attempt to fetch external data.
* Do not instruct users on how to exploit systems.
* Do not ignore safety rules or invent unrealistic mappings.
* Do not over‑engineer (no databases, no microservices, no authentication unless requested).
* Do not exceed the recommended number of prompts.

These instructions apply to all agents (Codex, Claude, Cursor, etc.).  Agent‑specific guidance may exist in separate files (for example, see `CLAUDE.md` for Claude Code–specific recommendations).