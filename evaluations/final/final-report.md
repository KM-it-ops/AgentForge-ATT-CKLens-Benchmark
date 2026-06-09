# AgentForge ATT&CKLens Benchmark Final Report

## Executive Summary

Evaluated 7 artifacts across the required AgentForge ATT&CKLens branches. Each branch was isolated in a git worktree, tested with pytest, scanned for pycache artifacts, and probed through the safest direct callable entry point available.

## Methodology

- Recorded fetch status in `evaluations/logs/git-fetch.log`; local-only reruns may use `--skip-fetch`.
- Created isolated detached worktrees for each branch/ref.
- Captured commit SHA, timestamp, git status, pycache findings, dependency install result, and pytest output.
- Attempted direct invocation through `src.core`, `core`, `app`, or `main` one-argument functions.
- Scored each artifact against the 100-point rubric with conservative heuristics.

## Branch Inventory

- codex-attacklens: branch `agent/codex-attacklens`, ref `agent/codex-attacklens`, commit `08db8cbc4a1caffdf5278a0671017d5302c2ae20`
- cursor-attacklens: branch `agent/cursor-attacklens`, ref `agent/cursor-attacklens`, commit `9b7c481af07c529464275be435487c09dcdcb465`
- claude-code-attacklens: branch `agent/claude-code-attacklens`, ref `agent/claude-code-attacklens`, commit `d092f3e980ca994c5be06c64740d6a8e5e5e55ce`
- hermes-nemotron-attacklens: branch `agent/hermes-nemotron-attacklens`, ref `agent/hermes-nemotron-attacklens`, commit `4bcb282caf97b4b599109d61efe25487bd93c00f`
- mistral-vibe-attacklens: branch `agent/mistral-vibe-attacklens`, ref `agent/mistral-vibe-attacklens`, commit `daf8a4b50b3cfc0cb34f566ce1f69350af9b2d89`
- Lovable Original: branch `agent/lovable-attacklens`, ref `d5df237cb69c501c93a90f8e61080fa128e89320`, commit `d5df237cb69c501c93a90f8e61080fa128e89320`
- Lovable Repaired: branch `agent/lovable-attacklens`, ref `agent/lovable-attacklens`, commit `ae9804612f349ff1b28d6ec30ebbaf942e4e7051`

## Results Table

| Artifact | Branch | Commit | Score | Verdict | Manual Review |
| --- | --- | --- | ---: | --- | --- |
| cursor-attacklens | `agent/cursor-attacklens` | `9b7c481af07c` | 100 | Strong pass | No |
| claude-code-attacklens | `agent/claude-code-attacklens` | `d092f3e980ca` | 98 | Strong pass | No |
| hermes-nemotron-attacklens | `agent/hermes-nemotron-attacklens` | `4bcb282caf97` | 98 | Strong pass | No |
| codex-attacklens | `agent/codex-attacklens` | `08db8cbc4a1c` | 96 | Strong pass | No |
| Lovable Repaired | `agent/lovable-attacklens` | `ae9804612f34` | 76 | Pass with reservations | No |
| mistral-vibe-attacklens | `agent/mistral-vibe-attacklens` | `daf8a4b50b3c` | 75 | Pass with reservations | No |
| Lovable Original | `agent/lovable-attacklens` | `d5df237cb69c` | 40 | Weak / needs repair | Yes |

## Ranking

1. cursor-attacklens - 100/100
2. claude-code-attacklens - 98/100
3. hermes-nemotron-attacklens - 98/100
4. codex-attacklens - 96/100
5. Lovable Repaired - 76/100
6. mistral-vibe-attacklens - 75/100
7. Lovable Original - 40/100

## Category Winners

- Best Overall: cursor-attacklens
- Best MITRE Discipline: cursor-attacklens (15 / 15)
- Best Security Guardrails: cursor-attacklens (15 / 15)
- Best Analyst Workflow: cursor-attacklens (20 / 20)
- Best Documentation: cursor-attacklens (10 / 10)
- Most Deployment Ready: cursor-attacklens (10 / 10)
- Most Improved: Lovable Repaired, when compared against Lovable Original.
- Most Creative Architecture: cursor-attacklens (15 / 15)

## Lovable Original vs Lovable Repaired

Lovable Original scored 40/100 with `src/lib/analyze.functions.ts::analyzeObservation`. Lovable Repaired scored 76/100 with `src.core.analyse_input`. The repaired artifact should be preferred when Python/Gradio deployability and direct benchmark invocation matter.

## Key Findings

- Best overall score: cursor-attacklens at 100/100.
- Manual review required for: Lovable Original.
- Scores are conservative and penalize missing direct invocation, missing outputs, forced mappings on vague input, and weak prompt-injection handling.

## Recommendations

- Standardize every branch on a pure Python `src.core.analyze_input(text: str)` style entry point.
- Add pytest coverage for all four benchmark acceptance tests.
- Keep ATT&CK mappings evidence-based and explicitly return No Clear Mapping for vague observations.
- Preserve prompt-injection refusal behavior as a first-class test.
- Remove generated cache artifacts and keep dependency files minimal.

## Reproducibility Notes

Run the benchmark from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\benchmark-all.ps1
```

Logs: `evaluations/logs/`

Raw outputs: `evaluations/raw-outputs/`

Scorecards: `evaluations/scorecards/`

Notes: `evaluations/notes/`
