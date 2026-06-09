# Scorecard — Claude Code (ATT&CKLens)

_Branch: `agent/claude-code-attacklens` · Commit: `7ff0c5c` · Date: 2026-06-08_
_Scored against `EVAL_RUBRIC.md`. This is a critical self-review; weaknesses are
called out deliberately._

## Total score: **92 / 100**

| Category | Score | Max |
| --- | ---: | ---: |
| Functional completeness | 18 | 20 |
| MITRE ATT&CK mapping discipline | 13 | 15 |
| Security/ethics guardrails | 14 | 15 |
| Code quality / maintainability | 14 | 15 |
| Testing and error handling | 9 | 10 |
| Deployment readiness | 9 | 10 |
| Documentation quality | 10 | 10 |
| Token / session efficiency | 5 | 5 |
| **Total** | **92** | **100** |

---

## Score rationale by category

### Functional completeness — 18/20
- All ten schema fields are always present (`core.build_result` is the single
  constructor); output is JSON-serialisable; `technique_id` includes ID + name as
  the spec requests.
- Handles every required path: valid mapping, no mapping, empty/short input,
  injection, offensive request.
- **−2:** technique coverage is only 6 signatures, so many legitimate observations
  fall to "no mapping". Honest, but limits real functional breadth.

### MITRE ATT&CK mapping discipline — 13/15
- Correct, defensible mappings for all five acceptance inputs; correctly declines
  on ambiguous input; `why_not` surfaces competing techniques.
- **−2:** see *MITRE mapping concerns* below — single weak indicator yields a
  `medium`-confidence mapping (false-positive risk), and only one top technique is
  returned rather than a ranked candidate set.

### Security/ethics guardrails — 14/15
- Defensive-only; injection and offensive requests refused; charter never leaked
  (tested); evidence quoted verbatim (no fabrication); local-only, no persistence.
- **−1:** guardrails are regex-based and therefore bypassable by novel phrasing
  (see *Safety concerns*).

### Code quality / maintainability — 14/15
- Clean UI/orchestration/data/safety separation; typed; dataclasses; thorough
  docstrings; adding a technique requires only a new `Signature`.
- **−1:** the `frozen=True` `Signature` with an in-place-mutated `_compiled` cache
  is a mild anti-pattern (mutating a frozen dataclass's field), and module-level
  regex precompilation would be cleaner than lazy caching.

### Testing and error handling — 9/10
- 12 passing tests covering all five acceptance scenarios plus empty input,
  offensive refusal, schema completeness, and the no-fabricated-evidence guarantee.
- **−1:** the UI layer (`app._render_markdown`, `app.analyze`) is untested; Test 1
  (launch) is only verified by import, not asserted in pytest.

### Deployment readiness — 9/10
- `python app.py` launches; `requirements.txt` present; CPU-only; HF Spaces layout
  (root `app.py`) correct; built successfully on Gradio 5.50.
- **−1:** loose pins (`gradio>=4.0`) risk a reproducibility break across major
  versions; no pinned/known-good version recorded.

### Documentation quality — 10/10
- `README.md`, `SECURITY.md`, `docs/architecture.md`, `docs/security-notes.md`:
  usage, examples, limitations, threat model, and improvement ideas all covered.

### Token / session efficiency — 5/5
- Followed the packet structure (plan → implement); read only the specified files;
  no redundant re-exploration or spec restatement.

---

## What passed
- All 5 `ACCEPTANCE_TESTS.md` scenarios (launch, basic mapping, no-mapping,
  injection resistance, network-investigation field).
- Full 10-field schema on every code path; deterministic, offline, no paid APIs.
- Verbatim evidence quoting; honest `null` mapping with `why_not`.
- Prompt-injection and offensive-request refusals without charter leakage.
- 12/12 unit tests; clean Gradio build on 5.50.

## What failed / fell short
- No automated test for "Successful Launch" (Test 1) — only a manual import check.
- UI rendering helpers are untested.
- Narrow technique table → low real-world recall (many inputs → no mapping).
- Single-technique output; no ranked candidates when several plausibly apply.

## MITRE mapping concerns
- **Single-indicator over-mapping:** one matched indicator yields `medium`
  confidence. A benign mention (e.g. "powershell" in a normal admin note) maps to
  `Execution / T1059.001` at medium — a false positive. Consider weighting
  indicators (strong vs contextual) so a lone generic keyword stays `low` or
  declines.
- **No multi-candidate ranking:** only the top-scoring signature is returned;
  `why_not` lists ties but the structured output exposes one technique. Real
  triage benefits from a ranked shortlist with per-candidate scores.
- **Tactic granularity:** failed SSH maps to `Credential Access / T1110`, which is
  defensible, but Initial Access is an equally valid reading the tool doesn't
  surface.

## Safety concerns
- **Regex guardrails are brittle.** `detect_prompt_injection` /
  `detect_offensive_request` match a fixed phrase list; paraphrased or obfuscated
  attempts (e.g. unicode tricks, indirect phrasing) can slip through. Acceptable
  for a deterministic MVP, but it is the main residual risk.
- **No layered defense for offensive output.** Because output is selected from
  curated strings, the blast radius is small — but if an LLM backend is added
  later, these regex screens alone would be insufficient.
- No detected concern with data handling: input is in-memory only, not persisted
  or transmitted.

## Deployment concerns
- Loose dependency pin (`gradio>=4.0`) — a future Gradio major could change the
  `Blocks`/`Examples`/`JSON` APIs and break the Space.
- `launch()` uses defaults; for a Space this is fine, but no explicit
  `server_name`/`server_port`/`ssr_mode` config is recorded for portability.
- Python 3.14 locally vs. 3.9 target: code uses `from __future__ import
  annotations`, so it is 3.9-safe, but this hasn't been executed on 3.9.

## Recommended fixes (prioritised)
1. **Weight indicators** (strong vs contextual) so a single generic keyword does
   not produce a `medium` mapping — reduces false positives. _(mapping)_
2. **Add a launch/UI smoke test** to pytest (`build_demo()` + `analyze()` round
   trip) so Test 1 and the UI layer are covered. _(testing)_
3. **Pin dependencies** to a known-good range (e.g. `gradio>=5,<6`). _(deploy)_
4. **Return ranked candidates** (top-N with scores) instead of a single technique.
   _(mapping/functional)_
5. **Expand signature + guard lists** and add obfuscation-tolerant injection
   detection (normalize whitespace/unicode before matching). _(functional/safety)_
6. Move regex precompilation to module load and drop the frozen-dataclass mutation.
   _(code quality)_
