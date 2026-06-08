# Claude Code Specific Guidance

This document provides additional recommendations for the **Claude Code** agent participating in the ATT&CKLens build experiment.  Claude Code has special capabilities such as reading multiple files at once, executing commands and integrating with an IDE.  The following guidelines help ensure a fair comparison.

## Use Provided Files Only

* At the start of each session, instruct Claude Code to read only `SPEC.md`, `SAFETY_RULES.md`, `TOKEN_BUDGET.md` and this `CLAUDE.md` file.  Do **not** ask it to scan the entire repository, as that wastes tokens.
* Ask Claude Code to summarise these files in its own words to verify understanding.

## Architecture Planning

Claude Code is strong at reasoning about architecture.  Encourage it to outline the file structure, functions and data flow in `STATE.md` before writing code.  Remind it that the MVP should remain simple: a core analysis module, a Gradio interface and documentation.

## Command Execution

Claude Code can run shell commands.  Use this to your advantage for running `pytest` or executing `python app.py`.  However, avoid allowing it to install arbitrary packages or access external networks.  Limit command execution to local operations within the project directory.

## Self‑Review

After code is written and tests run, instruct Claude Code to perform a self‑review.  It should check for compliance with safety rules, adherence to the spec and clarity of documentation.  Any discovered shortcomings should be noted in `STATE.md` along with proposed fixes.

## Common Pitfalls

Claude Code may sometimes hallucinate additional features or restructure the project unexpectedly.  To prevent this:

* Remind it that the MVP is intentionally small and should not include features beyond those listed in `SPEC.md`.
* Ask it to confirm that it has not added unnecessary modules or complex infrastructure.
* Instruct it to consult the acceptance tests in `ACCEPTANCE_TESTS.md` when debugging.

## Token Management

To avoid hitting context limits:

* After each session, summarise progress and outstanding tasks in `STATE.md`.
* When resuming, provide only `STATE.md` and the next specific task instead of re‑sending the entire spec.
* Avoid verbose restatements of prompts or copying large files into the conversation unless strictly necessary.

By following these guidelines, the Claude Code agent should produce a clean, functional implementation of ATT&CKLens within the same constraints as other agents.