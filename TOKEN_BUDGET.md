# Token and Session Budget Guidance

To ensure fair comparison between AI coding agents, each agent should operate within a fixed interaction budget.  This section outlines recommended limits and best practices for structuring agent conversations to avoid exceeding context or token ceilings.

## Prompt Packets

Divide the development workflow into discrete **packets** of prompts.  Each packet should be concise, focused on a single objective, and no longer than about 1 500–2 000 words.  Suggested packets:

1. **Build Brief** – Provide the agent with the high‑level goal, specification (copied from `SPEC.md`) and safety rules.  Ask it to outline its plan and confirm its understanding.  (1 prompt)
2. **Implementation** – Instruct the agent to write the initial version of the code, following the spec and file structure.  Remind it to update a `STATE.md` file listing what was created, known issues and next steps.  (2 prompts)
3. **Debug and Test** – Supply error messages or failing test results only.  Ask the agent to fix the issues without rewriting everything from scratch.  (2 prompts)
4. **Documentation** – Ask the agent to produce `README.md`, `SECURITY.md` and any other required documentation based on the built project.  (1 prompt)
5. **Self‑Review** – Request the agent to evaluate its own work against the acceptance tests and rubric.  (1 prompt)

This yields **7 prompts** per agent run.  Resist the urge to ask additional questions or to revisit previous prompts unless critical.

## Conversation Limits

* Keep each prompt under **1 500–2 000 words** to avoid hitting context limits.
* Encourage the agent to reference only the relevant spec and instructions; do not allow it to load the entire repository unless necessary.
* At the end of each packet, ask the agent to summarise its changes in `STATE.md`.  In subsequent sessions, provide only `STATE.md` and the new task rather than the full history.  This reduces the token footprint for both the agent and the controlling user.

## Token Efficiency Tips

* Use bullet points instead of paragraphs when outlining requirements.
* Reuse common instructions via copy/paste rather than rephrasing them.
* When feeding back errors, include only the error messages and stack traces relevant to the issue.  Avoid echoing the entire file contents unless requested.
* Remind the agent to avoid repeating the entire specification back to you.  It should focus on the requested action.

By adhering to these guidelines, you can run multiple agent sessions without exceeding typical token limits and ensure a fair, reproducible comparison.