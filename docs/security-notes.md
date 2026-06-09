# Extended Security Notes

This document provides deeper technical details on the security posture of ATT&CKLens, complementing `SECURITY.md` and `SAFETY_RULES.md`.

## Threat Modeling

### Assets to Protect

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| User input (security observations) | Medium — may contain IPs, hostnames, usernames | No persistence, no logging, no network transmission |
| System prompt | Low — defensive guidance only | Never exposed in output |
| Internal logic/mappings | Low — public ATT&CK knowledge | Not secret, but not exposed |
| Output analysis | Medium — defensive recommendations | User-controlled display |

### Attack Surface

| Vector | Mitigation |
|--------|------------|
| Prompt injection via input | Regex detection + hard refusal |
| Data exfiltration | No network capability in code |
| Offensive misuse | Output templates framed defensively only |
| Information disclosure | No internal state exposed |
| DoS via large input | Input length not strictly limited but processing is O(n) |

### Trust Boundaries

```
┌────────────────────────────────────────────────────────────┐
│                      USER SPACE                             │
│  ┌─────────────┐    ┌─────────────────────────────────┐   │
│  │  Browser    │◀──▶│  Gradio Server (app.py)        │   │
│  │  (untrusted)│    │  ┌─────────────────────────┐   │   │
│  └─────────────┘    │  │ Core Logic (core.py)    │   │   │
│                     │  │  - Input validation     │   │   │
│                     │  │  - Injection detection  │   │   │
│                     │  │  - Keyword matching     │   │   │
│                     │  │  - Output generation    │   │   │
│                     │  └─────────────────────────┘   │   │
│                     └─────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
                   NO EXTERNAL CALLS
                   NO PERSISTENCE
                   NO NETWORK I/O
```

## Prompt Injection Defense

### Detection Patterns

Located in `src/core.py` — `INJECTION_PATTERNS` list:

```python
INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+instructions?",
    r"reveal\s+(the\s+)?(hidden|system|secret)\s+prompt",
    r"override\s+(system|safety|security)\s+(rules|instructions?)",
    r"you\s+are\s+now\s+(a|an)\s+\w+",
    r"pretend\s+to\s+be",
    r"roleplay\s+as",
    # ... more patterns
]
```

### Response to Detection

When injection detected, returns:

```json
{
  "summary": "Input rejected: potential prompt injection attempt detected.",
  "tactic": null,
  "technique_id": null,
  "evidence": [],
  "confidence": "low",
  "why_not": "Input contains patterns consistent with prompt injection attempts. For safety, the request is declined.",
  "detection_idea": null,
  "network_investigation": null,
  "remediation": "Ensure inputs are genuine security observations. Do not attempt to override system instructions.",
  "analyst_questions": []
}
```

### Limitations

- Regex-based; sophisticated obfuscation may bypass
- No semantic analysis of intent
- False positives possible (security text mentioning "ignore" legitimately)
- Mitigation: Patterns tuned for common injection syntax, not general words

## Output Safety Guarantees

### Defensive-Only Templates

All generated advice uses pre-defined templates in `core.py`:

- `generate_remediation()` — Only recommends: MFA, patching, monitoring, least privilege, network segmentation, backups, encryption
- `generate_detection_idea()` — Only suggests: SIEM query patterns, log sources, alert thresholds
- `generate_network_investigation()` — Only suggests: What to capture, where to look, protocol analysis
- `generate_analyst_questions()` — Only asks: Context gathering, verification steps

### No Offensive Content

| Offensive Category | Prevented By |
|-------------------|--------------|
| Exploit code | Not in templates, not in mappings |
| Bypass techniques | Not described; only detection of bypasses |
| Evasion methods | Not described; only detection of evasion |
| Credential theft | Not described; only detection of dumping |
| Malware usage | Not described; only detection of indicators |
| C2 setup | Not described; only beacon detection |

### Technique Descriptions

Technique names from ATT&CK are included (e.g., "Brute Force: Password Guessing") but:
- No execution steps
- No tool usage instructions
- No parameter details
- Context: "what to detect" not "how to do"

## Data Privacy

### No Data Collection

| Data Type | Collected? | Where Stored |
|-----------|------------|--------------|
| User input | No | Memory only, discarded after response |
| Analysis output | No | Returned to user only |
| Usage metrics | No | None |
| Error logs | No | Stdout only (Gradio default) |
| Session IDs | No | None |

### Deployment Implications

- Safe for air-gapped environments
- No telemetry to vendor
- No account creation
- No cookies or localStorage (Gradio defaults)

## Secure Deployment Checklist

### Local Development

- [ ] Run in isolated environment (venv)
- [ ] No `.env` files with secrets needed
- [ ] `requirements.txt` pinned versions
- [ ] No sudo/root required

### Hugging Face Spaces

- [ ] Public Space — no secrets in repo
- [ ] `requirements.txt` only contains `gradio`
- [ ] No `app.py` modifications for auth needed
- [ ] CPU-only, no GPU secrets

### Enterprise/Internal

- [ ] Deploy behind corporate proxy if needed
- [ ] Add auth layer (Gradio supports `auth=` parameter)
- [ ] Consider rate limiting (Gradio `queue()`)
- [ ] Monitor for injection attempts in logs

## Incident Response

### If Safety Bypass Found

1. **Reproduce** — Document exact input that bypassed controls
2. **Assess** — Determine what was exposed (prompt? logic? data?)
3. **Patch** — Add pattern to `INJECTION_PATTERNS` or harden logic
4. **Test** — Verify fix blocks the bypass
5. **Deploy** — Update all environments

### If Offensive Output Generated

1. **Capture** — Save the exact input and output
2. **Analyze** — Which template/mapping produced it?
3. **Fix** — Modify template or add keyword exclusion
4. **Regression test** — Run acceptance test suite

## Compliance References

| Standard | Relevance |
|----------|-----------|
| NIST CSF | Supports ID.DETECT, PR.AC, PR.IP, DE.CM |
| MITRE ATT&CK | Core mapping framework (defensive use) |
| ISO 27001 | Aligns with A.12.4 (logging), A.16.1 (incident response) |
| CIS Controls | Supports CIS 8 (audit log mgmt), 16 (app security) |

## Version History

| Version | Security Changes |
|---------|------------------|
| v0.1 (MVP) | Initial injection detection, defensive templates, no persistence |

## Contact

For security issues with ATT&CKLens itself, use the repository's security advisory process. For questions about defensive use of this tool, consult your organization's security team.