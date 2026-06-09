# Security Considerations & Ethical Use

## Purpose

ATT&CKLens is designed for **educational and defensive cybersecurity purposes only**. This document reiterates the safety rules from `SAFETY_RULES.md` and explains how they are implemented in the code.

## Safety Rules Implementation

### 1. No Offensive Guidance

**Rule:** Under no circumstances should the tool provide instructions for exploiting systems, bypassing security controls, evading detection, conducting unauthorized penetration tests, or any other offensive security activities.

**Implementation:**
- All `remediation` output frames advice around detection, prevention, and remediation
- No exploit code, bypass techniques, or evasion methods are included
- Technique descriptions are limited to defensive context (what to detect, not how to execute)
- Output never includes commands to run attacks

### 2. No Real Data

**Rule:** Use only synthetic, anonymized, or publicly available data when testing or demonstrating the application.

**Implementation:**
- The tool processes only the single text input provided at runtime
- No data persistence, logging, or transmission occurs
- Sample inputs in `examples/sample_inputs.txt` are synthetic
- No integration with live systems or real organizational data

### 3. Prompt Injection Resistance

**Rule:** The application must treat user input as untrusted. Do not let user-provided text override system instructions.

**Implementation:**
- `detect_prompt_injection()` in `src/core.py` scans for injection patterns:
  - "ignore previous instructions"
  - "reveal hidden/system prompt"
  - "override system/safety rules"
  - Roleplay/pretend directives
  - System prompt delimiters
- Detected injections return a refusal response with `tactic: null`, `technique_id: null`
- System prompt (`prompts/system_prompt.txt`) is never revealed in output
- Internal logic and variables are not exposed

### 4. Honest Limitations

**Rule:** If the tool cannot confidently map input to a specific MITRE ATT&CK technique or tactic, it must state so clearly.

**Implementation:**
- Returns `tactic: null` and `technique_id: null` when no keyword matches found
- `confidence: "low"` for ambiguous/insufficient input
- `why_not` field explains the reasoning (e.g., "Input does not contain recognizable security event keywords...")
- Multiple possible mappings trigger uncertainty explanation

### 5. Avoid Harmful Advice

**Rule:** Remediation and detection recommendations should follow best practices (least privilege, MFA, patching). Do not suggest disabling security tools or weakening controls.

**Implementation:**
- `generate_remediation()` only recommends defensive best practices:
  - Enable MFA, not disable it
  - Patch systems, not ignore vulnerabilities
  - Restrict privileges, not expand them
  - Enable logging/monitoring, not disable it
  - Use LAPS, Credential Guard, Tamper Protection
- No recommendations to disable Defender, AV, firewalls, or logging

### 6. Transparent Confidence

**Rule:** Always indicate confidence levels (`high`, `medium`, `low`) based on clarity of evidence.

**Implementation:**
- `assess_confidence()` considers:
  - Keyword match strength (exact vs partial)
  - Input length (very short = lower confidence)
  - Number of competing mappings
- Confidence explicitly shown in all output formats

### 7. Respect Legal Boundaries

**Rule:** Only use this tool in environments where you have explicit authorization.

**Implementation:**
- UI displays warning: "For educational and defensive use only. Do not use on real attack data without authorization."
- No automated scanning, exploitation, or network interaction
- Tool is purely analytical — takes text input, returns text output

### 8. Educational Purpose

**Rule:** Outputs should inform learning and awareness, not substitute professional security analysis.

**Implementation:**
- `analyst_questions` prompt further investigation
- `detection_idea` suggests query types, not production-ready rules
- `network_investigation` suggests what to look for, not automated analysis
- README and UI clearly state limitations

## Data Handling

| Aspect | Behavior |
|--------|----------|
| Input storage | None — processed in memory only |
| Output storage | None — returned to user only |
| Network calls | None — fully offline |
| Telemetry | None |
| Logging | None (Gradio may log access, but not input content) |
| Cookies/tracking | None |

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Prompt injection | Pattern detection + refusal |
| Data exfiltration | No network capability |
| Offensive misuse | Defensive-only output framing |
| Real data exposure | No persistence, user controls input |
| Hallucinated mappings | Keyword-only, evidence citation required |

## Reporting Security Issues

If you discover a safety bypass or security issue in ATT&CKLens:

1. Do not publicly disclose exploit details
2. Report via the repository's security advisory process
3. Include steps to reproduce and impact assessment

## Compliance

This tool is designed to support defensive security operations within authorized environments. Users are responsible for ensuring their use complies with:
- Organizational policies
- Applicable laws and regulations
- Rules of engagement for any assessment

## Version

These security considerations apply to ATT&CKLens MVP (v0.1). Review `SAFETY_RULES.md` for the canonical rule set.