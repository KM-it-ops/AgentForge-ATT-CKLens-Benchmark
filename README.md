# AgentForge: ATT&CKLens Benchmark

This repository contains everything you need to run a controlled build experiment comparing multiple AI coding agents on the same defensive cybersecurity application.  The target project, **ATT&CKLens**, is a simple Python/Gradio application that accepts sample security observations and maps them to MITRE ATT&CK tactics and techniques.  Each agent receives the same specification, safety rules and budget, and the results are recorded for later comparison.

## Overview

The primary goal of this repository is to allow you to evaluate how different AI coding agents (Codex, Cursor, Claude Code, Hermes + Nemotron 3 Ultra, Mistral Vibe, Lovable, etc.) interpret and implement the same requirements.  By keeping the specification, tests and safety constraints identical across all runs, you can focus on differences in planning, code quality, documentation and overall safety.

The project is organised as follows:

```
agentforge-attacklens-benchmark/
├── README.md              # This file
├── SPEC.md                # Detailed specification of ATT&CKLens
├── SAFETY_RULES.md        # List of ethical and security constraints
├── TOKEN_BUDGET.md        # Guidance on prompt/session budgets
├── ACCEPTANCE_TESTS.md    # Basic acceptance tests for the MVP
├── EVAL_RUBRIC.md         # Scoring rubric for comparing agents
├── AGENTS.md              # Instructions for how agents should work
├── CLAUDE.md              # Additional instructions specific to Claude Code
├── .cursor/rules          # Cursor-specific rules
├── sample_inputs/         # Toy logs and inputs for testing
├── expected_behaviors/    # Example outputs and schemas
├── agent_runs/            # Directories where agent outputs will live
├── evaluations/
│   ├── scorecards/        # Scoring sheets for each agent
│   └── notes/             # Observations during review
├── final_report/          # A place to put final write‑ups
└── bootstrap_scripts/
    └── setup.sh          # Optional helper script for dependency installation
```

There is no working application in this repository—only the scaffolding for the experiment.  Each AI agent will be asked to populate a branch with its own implementation of ATT&CKLens using the files provided here as starting points.

## Instructions

1. Read through `SPEC.md`, `SAFETY_RULES.md`, and `TOKEN_BUDGET.md` to understand the core requirements, constraints and limits for the project.
2. Copy the contents of `SPEC.md` and `SAFETY_RULES.md` into your agent prompts when starting an AI session.  Remind the agent not to look at anything outside these documents until instructed.
3. Ask the agent to write its code in a branch named after the agent.  For example, use `agent/codex-attacklens` for the Codex run.  This repository is initialised with a `main` branch that contains only the spec and supporting files.
4. After the agent produces code, run the acceptance tests in `ACCEPTANCE_TESTS.md` manually or via a test harness of your choice to verify basic functionality.  Record results in `evaluations/scorecards` and `evaluations/notes`.
5. Compare the agents using the rubric in `EVAL_RUBRIC.md` and summarise your findings in `final_report/`.

## Disclaimer

All projects built from this repository must adhere to the ethical constraints defined in `SAFETY_RULES.md`.  Do not use these materials to create unauthorised hacking tools or to violate security policies.  The purpose of ATT&CKLens is educational and defensive only.

## Benchmark Results

Final results are available in:

evaluations/final/final-report.md

Scorecards are available in:

evaluations/scorecards/