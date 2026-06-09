# Graph Report - agentforge-attacklens-benchmark  (2026-06-08)

## Corpus Check
- 4 files · ~5,927 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 35 nodes · 65 edges · 9 communities detected
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 9 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]

## God Nodes (most connected - your core abstractions)
1. `analyse_input()` - 17 edges
2. `assert_schema()` - 8 edges
3. `_collect_evidence()` - 6 edges
4. `load_sample()` - 6 edges
5. `_result_from_rule()` - 5 edges
6. `analyze_for_ui()` - 4 edges
7. `_first_nonempty_lines()` - 4 edges
8. `test_failed_ssh_login_maps_to_bruteforce()` - 4 edges
9. `test_ambiguous_event_declines_mapping()` - 4 edges
10. `test_suspicious_dns_includes_network_guidance()` - 4 edges

## Surprising Connections (you probably didn't know these)
- `analyze_for_ui()` --calls--> `analyse_input()`  [INFERRED]
  app.py → src\core.py
- `analyse_input()` --calls--> `test_failed_ssh_login_maps_to_bruteforce()`  [INFERRED]
  src\core.py → tests\test_core.py
- `analyse_input()` --calls--> `test_ambiguous_event_declines_mapping()`  [INFERRED]
  src\core.py → tests\test_core.py
- `analyse_input()` --calls--> `test_prompt_injection_refuses_internal_prompt_request()`  [INFERRED]
  src\core.py → tests\test_core.py
- `analyse_input()` --calls--> `test_suspicious_dns_includes_network_guidance()`  [INFERRED]
  src\core.py → tests\test_core.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.47
Nodes (9): assert_schema(), load_sample(), test_ambiguous_event_declines_mapping(), test_empty_input_returns_graceful_error_result(), test_failed_ssh_login_maps_to_bruteforce(), test_nmap_summary_maps_to_discovery(), test_powershell_alert_maps_to_execution(), test_prompt_injection_refuses_internal_prompt_request() (+1 more)

### Community 1 - "Community 1"
Cohesion: 0.29
Nodes (5): analyze_for_ui(), Gradio entrypoint for ATT&CKLens., Return both readable Markdown and the structured JSON result., format_analysis(), Render an analysis dictionary into concise human-readable Markdown.

### Community 2 - "Community 2"
Cohesion: 0.67
Nodes (3): _no_mapping(), Deterministic defensive mapping logic for ATT&CKLens., _with_required_fields()

### Community 3 - "Community 3"
Cohesion: 0.67
Nodes (2): MappingRule, A small defensive rule for one ATT&CKLens MVP scenario.

### Community 4 - "Community 4"
Cohesion: 0.67
Nodes (3): _collect_evidence(), _deduplicate(), _normalize()

### Community 5 - "Community 5"
Cohesion: 0.67
Nodes (3): analyse_input(), _contains_prompt_injection(), Analyze one security observation and return a JSON-serializable result.

### Community 6 - "Community 6"
Cohesion: 1.0
Nodes (2): _first_nonempty_lines(), _result_from_rule()

### Community 7 - "Community 7"
Cohesion: 1.0
Nodes (1): ATT&CKLens core package.

### Community 8 - "Community 8"
Cohesion: 1.0
Nodes (1): Return both readable Markdown and the structured JSON result.

## Knowledge Gaps
- **8 isolated node(s):** `Gradio entrypoint for ATT&CKLens.`, `Return both readable Markdown and the structured JSON result.`, `Deterministic defensive mapping logic for ATT&CKLens.`, `A small defensive rule for one ATT&CKLens MVP scenario.`, `Analyze one security observation and return a JSON-serializable result.` (+3 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 3`** (3 nodes): `MappingRule`, `.matches()`, `A small defensive rule for one ATT&CKLens MVP scenario.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 6`** (2 nodes): `_first_nonempty_lines()`, `_result_from_rule()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 7`** (2 nodes): `__init__.py`, `ATT&CKLens core package.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 8`** (1 nodes): `Return both readable Markdown and the structured JSON result.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `analyse_input()` connect `Community 5` to `Community 0`, `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 6`?**
  _High betweenness centrality (0.543) - this node is a cross-community bridge._
- **Why does `analyze_for_ui()` connect `Community 1` to `Community 5`?**
  _High betweenness centrality (0.220) - this node is a cross-community bridge._
- **Why does `format_analysis()` connect `Community 1` to `Community 2`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `analyse_input()` (e.g. with `analyze_for_ui()` and `test_failed_ssh_login_maps_to_bruteforce()`) actually correct?**
  _`analyse_input()` has 8 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Gradio entrypoint for ATT&CKLens.`, `Return both readable Markdown and the structured JSON result.`, `Deterministic defensive mapping logic for ATT&CKLens.` to the rest of the system?**
  _8 weakly-connected nodes found - possible documentation gaps or missing edges._