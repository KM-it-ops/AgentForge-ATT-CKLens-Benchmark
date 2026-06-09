# Architecture & Data Flow

## Overview

ATT&CKLens follows a simple modular architecture separating the web interface (Gradio) from the core analysis logic. The MVP uses keyword-based heuristic mapping with embedded MITRE ATT&CK data — no external APIs, LLMs, or databases.

## High-Level Data Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   User      │────▶│  Gradio UI   │────▶│  Core Analysis  │────▶│  Formatted   │
│   Input     │     │  (app.py)    │     │  (core.py)      │     │  Output      │
└─────────────┘     └──────────────┘     └────────┬────────┘     └──────────────┘
                                                   │
                                                   ▼
                                            ┌──────────────┐
                                            │ Attack Data  │
                                            │ (attack_     │
                                            │  _data.py)   │
                                            └──────────────┘
```

## Components

### 1. Gradio Interface (`app.py`)

**Responsibilities:**
- Web UI rendering (textbox, buttons, output display)
- Request/response handling
- Input validation (empty check)
- Sample input loading
- Output formatting (text and JSON views)

**Key Functions:**
- `analyze(text)` → formatted text output
- `analyze_json(text)` → JSON output
- Event handlers for buttons

### 2. Core Analysis (`src/core.py`)

**Responsibilities:**
- Input sanitization and validation
- Prompt injection detection
- Keyword matching against ATT&CK mappings
- Evidence extraction (quoting input)
- Confidence assessment
- Output field generation (all 10 fields)
- Structured output serialization

**Key Functions:**
- `analyse_input(text)` → `AttackLensOutput` dataclass
- `format_output(output)` → human-readable string
- `detect_prompt_injection(text)` → bool
- `extract_evidence(text, keywords)` → list of quoted strings
- `generate_*` functions for each output field

### 3. Attack Data (`src/attack_data.py`)

**Responsibilities:**
- Embedded keyword→ATT&CK tactic/technique mappings
- Lookup and ranking functions
- No external dependencies

**Data Structure:**
```python
ATTACK_MAPPINGS: Dict[str, Tuple[tactic, technique_id, technique_name, confidence_boost]]
```
~150+ keywords covering all 14 MITRE ATT&CK tactics.

**Key Functions:**
- `get_attack_mapping(keyword)` → single best match
- `find_all_mappings(text)` → all matches in text
- `rank_mappings(matches)` → sorted by confidence + tactic priority

## Data Structures

### AttackLensOutput (dataclass)

```python
@dataclass
class AttackLensOutput:
    summary: str                    # One-sentence summary
    tactic: Optional[str]           # MITRE tactic name or None
    technique_id: Optional[str]     # "T1110.001 (Name)" or None
    evidence: List[str]             # Quoted input fragments
    confidence: str                 # "high" | "medium" | "low"
    why_not: Optional[str]          # Uncertainty explanation
    detection_idea: Optional[str]   # SIEM query suggestion
    network_investigation: Optional[str]  # PCAP/Wireshark guidance
    remediation: str                # Defensive recommendations
    analyst_questions: List[str]    # Follow-up questions
```

### Mapping Entry

```python
# In ATTACK_MAPPINGS
"keyword": ("Tactic Name", "TXXXX.XXX", "Technique Name", "high|medium|low")
```

## Processing Pipeline

```
Input Text
    │
    ▼
┌─────────────────────────────────────┐
│ 1. Validate Input                   │
│    - Empty? → Error output          │
│    - Prompt injection? → Refusal    │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│ 2. Keyword Matching                 │
│    - find_all_mappings(text)        │
│    - Returns all keyword matches    │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│ 3. Rank Matches                     │
│    - rank_mappings(matches)         │
│    - By confidence, then tactic     │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│ 4. Extract Evidence                 │
│    - extract_evidence(text, kws)    │
│    - Quotes exact input phrases     │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│ 5. Generate Output Fields           │
│    - summary, tactic, technique_id  │
│    - confidence, why_not            │
│    - detection_idea                 │
│    - network_investigation          │
│    - remediation                    │
│    - analyst_questions              │
└─────────────────────────────────────┘
    │
    ▼
AttackLensOutput → JSON / Formatted Text
```

## Design Decisions

### Keyword-Based Heuristic (Not LLM)

**Rationale:**
- Zero external dependencies (no API keys, no model hosting)
- Deterministic, reproducible results
- Fast (<100ms per analysis)
- Runs on CPU-only environments (HF Spaces free tier)
- Transparent logic — easy to audit and extend

**Trade-offs:**
- Limited context understanding
- No semantic similarity (exact/partial keyword match only)
- Fixed technique coverage (embedded dictionary)
- English-only

### Embedded ATT&CK Data

**Rationale:**
- No network calls for MITRE data
- Version-locked to known-good mappings
- Extensible via code edits

**Trade-offs:**
- Manual updates needed for new techniques
- Subset of full ATT&CK matrix (~150 keywords vs 500+ techniques)

### Single Observation Per Run

**Rationale:**
- Matches SPEC.md requirement
- Simplifies state management
- Clear input/output contract

### Output as Dataclass + JSON

**Rationale:**
- Type safety via dataclass
- Easy serialization for API/UI
- Structured for downstream consumers

## Extensibility Points

| Extension | Location | Effort |
|-----------|----------|--------|
| Add keywords | `src/attack_data.py` | Low |
| New output field | `AttackLensOutput` + `core.py` | Medium |
| LLM integration | New `src/llm.py` + `core.py` | High |
| Batch processing | `app.py` + `core.py` | Medium |
| History/persistence | New `src/storage.py` | Medium |
| Multi-language | `attack_data.py` + tokenizer | High |

## Deployment Architecture

### Local / HF Spaces

```
┌─────────────────────────────────────┐
│       Gradio Server (Python)        │
│  ┌─────────┐  ┌─────────────────┐  │
│  │ app.py  │──│ src/core.py     │  │
│  └─────────┘  │ src/attack_data │  │
│               └─────────────────┘  │
└─────────────────────────────────────┘
          │
          ▼
    Browser (HTTP)
```

- Single process, single thread (Gradio default)
- Stateless — no session data stored
- Port 7860 (configurable)

## Performance

| Metric | Typical Value |
|--------|--------------|
| Cold start | ~2s (Gradio import) |
| Analysis latency | <50ms |
| Memory usage | ~50MB |
| CPU | Single core, minimal |

## Security Architecture

```
User Input
    │
    ▼
┌─────────────────────┐
│ Prompt Injection    │───▶ Reject if detected
│ Detection (regex)   │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│ Keyword Matching    │───▶ No external calls
│ (local dictionary)  │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│ Output Generation   │───▶ Defensive-only templates
│ (template-based)    │
└─────────────────────┘
    │
    ▼
User Output (no logging, no persistence)
```

No authentication, no authorization, no encryption needed — tool is stateless and processes only user-provided text.