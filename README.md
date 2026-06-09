# 🛡️ AgentForge: ATT&CKLens Benchmark

A reproducible benchmark evaluating how modern AI coding agents perform when building the same defensive cybersecurity application under identical constraints.

## Objective

Can AI coding agents build secure, uncertainty-aware, MITRE ATT&CK-aligned security tooling?

AgentForge answers that question by evaluating multiple agents using:

- Identical specifications
- Standardized acceptance tests
- Prompt injection challenges
- Rubric-based scoring
- Automated reporting

## Final Results

| Agent | Score |
|---------|-------:|
| 🥇 Cursor | 100 |
| 🥈 Claude Code | 98 |
| 🥈 Hermes Nemotron | 98 |
| 🥉 Codex | 96 |
| Lovable Repaired | 76 |
| Mistral Vibe | 75 |
| Lovable Original | 40 |

## Benchmark Results

### Final Rankings

![Final Rankings](docs/images/final-rankings.png)

### Example Evaluation Scorecard

![Scorecard Example](docs/images/scorecard-example.png)

### Analysis Graph

![Architecture Graph](docs/images/architecture-graph.png)

➡️ See the full report in `evaluations/final/final-report.md`