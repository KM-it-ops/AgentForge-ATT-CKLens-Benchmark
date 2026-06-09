# Codex ATT&CKLens Run State

## Understanding

- Build a local Python 3 and Gradio MVP for defensive ATT&CK-style analysis.
- Use `SPEC.md` as the source of truth and follow `SAFETY_RULES.md`.
- Keep the implementation deterministic, local, and free of paid APIs or live data fetching.
- Use the starter-kit folders `sample_inputs/` and `expected_behaviors/` as fixtures for behavior and tests.

## Plan

- Put core mapping and refusal logic in `src/core.py`.
- Keep UI wiring in `app.py`.
- Add pytest tests for schema, sample inputs, no-map behavior, prompt-injection refusal, and empty input handling.
- Add `requirements.txt`, `SECURITY.md`, docs, prompt notes, and examples.

## Changes Made

- Added deterministic ATT&CKLens core logic.
- Added a Gradio app entrypoint.
- Added tests based on the provided sample inputs.
- Added project documentation and security notes.

## Known Issues

- The mapper is intentionally narrow and not a full ATT&CK knowledge base.
- The project does not fetch live MITRE data.
- Analysts must validate outputs before using them in real environments.
- On this Windows workspace, pip dependency commands should run with `PIP_NO_CACHE_DIR=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` to avoid a local pip cache deserialization stall.
- Gradio launch verification should use the in-process non-blocking launch plus HTTP probe pattern; hidden PowerShell `Start-Process` attempts did not bind reliably.

## Verification

- Created `.venv` with Python 3.14.2.
- Installed dependencies from `requirements.txt`.
- Ran `python -m pytest -q`: 7 tests passed.
- Ran a non-server launch check: `from app import build_app; build_app()` returned a Gradio `Blocks` object.
- Ran an in-process Gradio launch and requested `http://127.0.0.1:7860/`: returned HTTP 200.

## Next Steps

- Run `python app.py` when an interactive local Gradio server is needed.
- Commit the Codex branch changes when reviewed.
