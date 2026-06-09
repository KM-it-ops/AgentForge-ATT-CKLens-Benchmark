# ATT&CKLens - State Document

## Requirement Summary

### Purpose
Build **ATT&CKLens**, a defensive cybersecurity helper that maps sample security observations to MITRE ATT&CK tactics and techniques. The tool is for educational use in controlled lab environments only.

### Core Requirements
- **Input**: Accept one piece of evidence per run (log snippets, alert text, scan summaries, packet-analysis notes, narrative incident notes)
- **Output**: Return a JSON-serializable dictionary with these fields:
  - `summary`: One-sentence summary of input
  - `tactic`: MITRE ATT&CK tactic name or `null`
  - `technique_id`: Technique ID (e.g., `T1059.001`) with name in parentheses, or `null`
  - `evidence`: List of quoted fragments from input supporting the mapping
  - `confidence`: `high`, `medium`, or `low`
  - `why_not`: Explanation when mapping is uncertain or multiple interpretations exist
  - `detection_idea`: One-sentence SIEM/Splunk query suggestion or `null`
  - `network_investigation`: Brief note on packet capture analysis or `null`
  - `remediation`: Defensive actions in plain English
  - `analyst_questions`: List of questions for further context

### Key Behaviors
1. **No forced mapping**: Return `null` for tactic/technique_id when evidence is insufficient
2. **Evidence citation**: Quote exact phrases from input in `evidence` field
3. **Confidence assessment**: Use `medium`/`low` when mapping is speculative
4. **Safety**: Never include offensive/exploit instructions; refuse prompt injection
5. **Prompt injection resistance**: Treat user input as untrusted

### Deployment Constraints
- Python 3 + Gradio UI
- No GPU acceleration or paid APIs
- All dependencies in `requirements.txt`
- Must run in Hugging Face Space environment (CPU only)
- No persistence or transmission of inputs

### Non-Requirements
- No PCAP file uploads or binary parsing
- No live Splunk integration
- No live MITRE ATT&CK data fetching
- No databases, microservices, or authentication

## Safety Rules

1. **No Offensive Guidance**: Never provide instructions for exploiting systems, bypassing security, or evading detection
2. **No Real Data**: Use only synthetic/anonymized data for testing
3. **Prompt Injection Resistance**: Treat user input as untrusted; never reveal system prompts
4. **Honest Limitations**: State clearly when mapping is uncertain; never hallucinate
5. **Avoid Harmful Advice**: Recommendations must follow best practices (least privilege, MFA, patching)
6. **Transparent Confidence**: Always indicate confidence levels accurately
7. **Respect Legal Boundaries**: Only use in authorized lab environments
8. **Educational Purpose**: Outputs are for learning; users must verify before real-world use

## Implementation Plan

### Phase 1: Core Logic (src/core.py)
- Implement `analyse_input()`: Main function to process evidence and return structured output
- Implement `map_to_attack()`: Map evidence to MITRE ATT&CK tactics/techniques using pattern matching
- Implement `generate_detection_idea()`: Create SIEM query suggestions
- Implement `generate_network_investigation()`: Create packet analysis guidance
- Implement `generate_remediation()`: Create defensive action recommendations
- Implement `generate_analyst_questions()`: Create follow-up questions
- Embed known MITRE ATT&CK technique mappings as static dictionaries

### Phase 2: User Interface (app.py)
- Create Gradio interface with text input box
- Connect core logic to UI
- Format output for human-readable display
- Handle errors gracefully

### Phase 3: Testing
- Implement acceptance tests from ACCEPTANCE_TESTS.md
- Test edge cases (empty input, prompt injection, ambiguous input)

### Phase 4: Documentation
- Create README.md with usage instructions
- Create SECURITY.md with safety considerations
- Create docs/architecture.md with design overview

## Planned File Tree

```
.
├── app.py                      # Gradio entry point
├── requirements.txt            # Python dependencies (gradio)
├── STATE.md                    # This file - current state
├── README.md                   # Project overview and usage
├── SECURITY.md                 # Safety rules and ethical use
├── src/
│   └── core.py                # Core analysis logic
├── prompts/
│   └── system_prompt.txt       # System prompt for LLM calls (if used)
├── examples/
│   └── sample_inputs.txt       # Test input examples
├── docs/
│   ├── architecture.md        # Design and data flow
│   └── security-notes.md       # Extended security considerations
└── tests/
    └── test_core.py           # Unit tests for core logic
```

## Assumptions

1. **No LLM Dependency**: The MVP can be implemented with deterministic pattern matching against known MITRE ATT&CK techniques without requiring an LLM
2. **Static Technique Data**: A sufficient subset of MITRE ATT&CK techniques can be embedded as static data structures
3. **Gradio Version**: Using Gradio 4.x which is compatible with Hugging Face Spaces
4. **Python Version**: Targeting Python 3.9+ as specified in acceptance tests
5. **Pattern Matching Approach**: Using keyword and regex pattern matching to identify techniques from input text
6. **Single Input Processing**: Processing one evidence input at a time (no batch processing required)
7. **No External APIs**: All processing happens locally without network calls
8. **Minimal Dependencies**: Only Gradio is strictly required; standard library for everything else

## Current Status

- **Phase**: Implementation complete
- **Next Step**: None - MVP is complete and ready for evaluation
- **Files Created**: All files per planned file tree
- **Files Pending**: None

## Known Issues

- None - All acceptance tests pass

## Completion Summary

✅ **Core Logic (src/core.py)**: Implemented with embedded MITRE ATT&CK framework and pattern matching
✅ **User Interface (app.py)**: Gradio-based web interface with proper formatting
✅ **Testing (tests/test_core.py)**: 17 unit tests covering all acceptance criteria
✅ **Documentation**: README.md, SECURITY.md, STATE.md all complete
✅ **Configuration**: requirements.txt, .gitignore properly configured
✅ **Examples**: Sample inputs provided for testing
✅ **Safety**: All safety rules implemented and enforced

## Test Results

All 17 unit tests pass:
- Basic mapping functionality
- No clear mapping handling
- Prompt injection resistance
- Network investigation field
- Edge cases and error handling
- Output structure validation
- Specific technique mappings
- Confidence level assignment

## Deployment Ready

The ATT&CKLens MVP is ready for deployment on Hugging Face Spaces or local execution.
Run with: `python app.py`
Test with: `pytest tests/test_core.py -v`

## Notes

- Will use deterministic pattern matching with embedded MITRE ATT&CK technique data
- Error handling will be implemented for empty/unparseable inputs
- All safety rules will be enforced in code logic
- Output will be validated to ensure all required fields are present
