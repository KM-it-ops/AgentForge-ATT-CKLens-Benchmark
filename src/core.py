"""
Core analysis logic for ATT&CKLens.

This module contains the main functions for analyzing security observations
and mapping them to MITRE ATT&CK tactics and techniques using keyword-based
heuristics. No external APIs or LLMs required.
"""

import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

from .attack_data import find_all_mappings, rank_mappings, TACTIC_ORDER


@dataclass
class AttackLensOutput:
    """Structured output for ATT&CKLens analysis."""
    summary: str
    tactic: Optional[str]
    technique_id: Optional[str]
    evidence: List[str]
    confidence: str  # "high", "medium", "low"
    why_not: Optional[str]
    detection_idea: Optional[str]
    network_investigation: Optional[str]
    remediation: str
    analyst_questions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values for optional fields."""
        result = asdict(self)
        # Keep null values for tactic and technique_id as per spec
        return result

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


# Prompt injection detection patterns
INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+instructions?",
    r"reveal\s+(the\s+)?(hidden|system|secret)\s+prompt",
    r"show\s+me\s+(the\s+)?(system|hidden)\s+prompt",
    r"override\s+(system|safety|security)\s+(rules|instructions?)",
    r"you\s+are\s+now\s+(a|an)\s+\w+",
    r"pretend\s+to\s+be",
    r"roleplay\s+as",
    r"disregard\s+(previous|all)\s+(instructions?|prompts?)",
    r"forget\s+(everything|all\s+previous)",
    r"new\s+instructions?:",
    r"system\s+prompt\s*[:=]",
    r"<\s*system\s*>",
    r"<\s*prompt\s*>",
]


def detect_prompt_injection(text: str) -> bool:
    """
    Check if input contains potential prompt injection attempts.

    Returns True if injection detected, False otherwise.
    """
    text_lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True
    return False


def extract_evidence(text: str, matched_keywords: List[str]) -> List[str]:
    """
    Extract quoted evidence fragments from input text that match keywords.

    Returns list of exact quoted phrases from the input.
    """
    evidence = []
    text_lower = text.lower()

    for keyword in matched_keywords:
        # Find the keyword in the original text (case-insensitive)
        pattern = re.escape(keyword)
        matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))

        for match in matches:
            start, end = match.span()
            # Get surrounding context (up to 100 chars before and after)
            context_start = max(0, start - 100)
            context_end = min(len(text), end + 100)
            context = text[context_start:context_end].strip()

            # Try to extract a sentence or phrase containing the keyword
            # Look for sentence boundaries
            sentences = re.split(r'[.!?]\s+', context)
            for sent in sentences:
                if keyword.lower() in sent.lower():
                    sent = sent.strip()
                    if sent and sent not in evidence:
                        evidence.append(sent)
                    break
            else:
                # Fallback: use the context snippet
                if context and context not in evidence:
                    evidence.append(context)

    # Limit evidence to top 5 most relevant pieces
    return evidence[:5]


def generate_summary(text: str, tactic: Optional[str], technique_name: Optional[str]) -> str:
    """Generate a one-sentence summary of the input."""
    # Truncate input for summary if too long
    truncated = text[:200] + "..." if len(text) > 200 else text

    if tactic and technique_name:
        return f"Observation suggests {tactic.lower()} activity ({technique_name}): {truncated}"
    elif tactic:
        return f"Observation suggests {tactic.lower()} activity: {truncated}"
    else:
        return f"Observation does not clearly map to a specific MITRE ATT&CK technique: {truncated}"


def assess_confidence(matches: List[tuple], text_length: int) -> str:
    """
    Assess confidence level based on match quality and input clarity.

    Returns "high", "medium", or "low".
    """
    if not matches:
        return "low"

    # Get confidence from best match
    best_confidence = matches[0][4]  # confidence from ranked matches

    # Adjust based on input length (very short inputs are less reliable)
    if text_length < 20:
        if best_confidence == "high":
            return "medium"
        elif best_confidence == "medium":
            return "low"

    return best_confidence


def generate_why_not(matches: List[tuple], text: str) -> Optional[str]:
    """Generate explanation when mapping is uncertain or multiple interpretations exist."""
    if not matches:
        return "Input does not contain recognizable security event keywords that map to MITRE ATT&CK techniques. The observation may be too generic, lack technical detail, or describe normal system behavior."

    if len(matches) > 1:
        tactics = [m[1] for m in matches[:3]]
        return f"Multiple possible mappings detected ({', '.join(set(tactics))}). The input contains keywords associated with different tactics. Further context is needed to determine the primary technique."

    # Single match but low confidence
    if matches[0][4] == "low":
        return "Keyword match found but confidence is low due to limited context or ambiguous terminology."

    return None


def generate_detection_idea(tactic: Optional[str], technique_id: Optional[str], evidence: List[str]) -> Optional[str]:
    """Generate a SIEM/Splunk query suggestion for detection."""
    if not tactic or not technique_id:
        return None

    detection_templates = {
        "Initial Access": "Search for repeated failed authentication attempts from the same source IP within a short time window (e.g., 5+ failures in 5 minutes).",
        "Execution": "Monitor for suspicious command-line executions (PowerShell encoded commands, WMI, scheduled tasks) from unusual parent processes.",
        "Persistence": "Alert on modifications to auto-start locations (Registry Run keys, Startup folder, scheduled tasks, services) by non-admin accounts.",
        "Privilege Escalation": "Detect UAC bypass attempts, token manipulation, or exploitation of known privilege escalation vulnerabilities.",
        "Defense Evasion": "Monitor for log clearing events (wevtutil, Clear-EventLog), timestomping, or disabling of security tools (Defender, AV).",
        "Credential Access": "Alert on LSASS memory access by non-system processes, SAM/NTDS dumping tools, or Kerberos ticket requests anomalies.",
        "Discovery": "Detect excessive network scanning, AD enumeration (LDAP queries, BloodHound), or system information gathering from unusual sources.",
        "Lateral Movement": "Monitor for SMB/WinRM/SSH connections from unusual internal sources, especially using admin shares or pass-the-hash indicators.",
        "Collection": "Alert on large data staging in unusual locations, archive creation, or clipboard/screen capture by unknown processes.",
        "Command and Control": "Detect beaconing patterns (regular intervals), DNS tunneling, or connections to newly registered/unknown domains.",
        "Exfiltration": "Monitor for large outbound transfers, uploads to cloud storage, or unusual DNS query volumes to external domains.",
        "Impact": "Alert on mass file encryption, service stops, backup deletion, or system shutdown/reboot by unauthorized processes.",
    }

    return detection_templates.get(tactic)


def generate_network_investigation(tactic: Optional[str], technique_id: Optional[str], evidence: List[str]) -> Optional[str]:
    """Generate network investigation guidance for network-related tactics."""
    network_tactics = {
        "Initial Access": "Inspect firewall/VPN logs for the source IP. Check for brute-force patterns against exposed services (SSH, RDP, VPN).",
        "Command and Control": "Capture PCAP for the affected host. Look for beaconing (regular intervals), DNS queries to suspicious domains, or TLS connections to unknown C2 IPs. Check proxy/firewall logs for domain reputation.",
        "Exfiltration": "Analyze netflow/PCAP for large outbound transfers. Check DNS logs for high-volume queries to single domains (tunneling). Review proxy logs for uploads to cloud storage.",
        "Lateral Movement": "Inspect SMB/WinRM/SSH traffic between internal hosts. Look for pass-the-hash (NTLM auth without Kerberos), admin share access (ADMIN$, IPC$), or unusual service creation.",
        "Discovery": "Check for port scans (SYN floods), LDAP query spikes, or unusual DNS enumeration (AXFR, zone transfers).",
        "Credential Access": "Monitor for LSASS memory reads over network (rare), Kerberos anomalies (AS-REQ/AS-REP ratios), or SMB session enumeration.",
    }

    return network_tactics.get(tactic)


def generate_remediation(tactic: Optional[str], technique_id: Optional[str], evidence: List[str]) -> str:
    """Generate defensive remediation recommendations."""
    remediation_templates = {
        "Initial Access": "Enforce multi-factor authentication (MFA) on all remote access (VPN, SSH, RDP). Implement account lockout policies. Block known malicious IPs. Use jump hosts/bastions for admin access.",
        "Execution": "Restrict PowerShell/script execution via AppLocker/WDAC. Enable PowerShell logging (Script Block, Module). Monitor for encoded commands. Disable WMI/DCOM if not needed.",
        "Persistence": "Audit auto-start locations regularly. Use LAPS for local admin passwords. Restrict service creation to admins. Monitor scheduled tasks for unusual creators.",
        "Privilege Escalation": "Patch systems promptly. Enable UAC (highest). Restrict token manipulation via Windows Defender Credential Guard. Monitor for known exploit patterns.",
        "Defense Evasion": "Protect event logs with tamper protection. Enable Windows Defender Tamper Protection. Monitor for log clearing (Event ID 1102). Deploy EDR with kernel-level visibility.",
        "Credential Access": "Enable Credential Guard and LSASS protection (RunAsPPL). Use long, complex passwords. Monitor for LSASS access (Event ID 4688 + 10). Restrict NTLM where possible.",
        "Discovery": "Segment networks to limit scanning. Restrict LDAP/AD enumeration permissions. Monitor for BloodHound/SharpHound indicators. Deploy network detection (Zeek/Suricata).",
        "Lateral Movement": "Disable SMBv1. Restrict admin shares. Enforce Kerberos-only auth (disable NTLM). Use PAWs for admin tasks. Monitor for pass-the-hash (Event ID 4624 logon type 9).",
        "Collection": "DLP for sensitive data. Monitor for large archive creation. Restrict clipboard/screen capture in sensitive contexts. Encrypt data at rest.",
        "Command and Control": "Block known C2 domains/IPs. Inspect TLS traffic (SSL inspection). Deploy DNS filtering. Monitor for beaconing (regular intervals, low entropy). Use threat intel feeds.",
        "Exfiltration": "DLP policies for cloud uploads. Monitor DNS for tunneling (high query volume, long labels). Egress filtering: allow only approved destinations. Encrypt sensitive data.",
        "Impact": "Maintain offline/immutable backups. Test restore procedures. Enable ransomware protection (Controlled Folder Access). Monitor for mass file changes. Have IR plan ready.",
    }

    base = remediation_templates.get(tactic, "Review the observation in context. Apply defense-in-depth: least privilege, network segmentation, monitoring, and patching.")
    return base


def generate_analyst_questions(tactic: Optional[str], technique_id: Optional[str], evidence: List[str]) -> List[str]:
    """Generate follow-up questions for an analyst."""
    base_questions = [
        "What is the source IP/host and is it known/trusted?",
        "What user account was involved and is it a service account or human?",
        "What was the timeline — when did this start and is it ongoing?",
        "Are there related alerts or logs from other systems (firewall, EDR, SIEM)?",
        "What is the business context of the affected system (criticality, data sensitivity)?",
    ]

    tactic_specific = {
        "Initial Access": [
            "Was MFA enforced on the access vector (VPN, SSH, RDP)?",
            "Are there signs of successful authentication after the failures?",
        ],
        "Execution": [
            "What was the parent process of the suspicious command?",
            "Are there child processes or network connections spawned?",
        ],
        "Persistence": [
            "Who created the persistence mechanism and when?",
            "Does the persistence survive reboot (verified)?",
        ],
        "Privilege Escalation": [
            "What privileges were gained (SYSTEM, admin, domain admin)?",
            "Is there evidence of exploit code or known vulnerability usage?",
        ],
        "Defense Evasion": [
            "Which security tools were disabled and how (service stop, registry, GPO)?",
            "Are logs missing for a specific time window?",
        ],
        "Credential Access": [
            "Which credentials were targeted (domain admin, service account, local)?",
            "Is there evidence of credential reuse (pass-the-hash, pass-the-ticket)?",
        ],
        "Discovery": [
            "What was enumerated (users, groups, computers, trusts, shares)?",
            "Was the enumeration from a compromised host or insider?",
        ],
        "Lateral Movement": [
            "What lateral movement protocol was used (SMB, WinRM, SSH, RDP)?",
            "What accounts were used and are they compromised or legitimate?",
        ],
        "Collection": [
            "What data was staged and where (local, network share, cloud)?",
            "Is there evidence of encryption or compression before exfiltration?",
        ],
        "Command and Control": [
            "What C2 protocol (HTTP, DNS, custom) and infrastructure (domains, IPs)?",
            "Is the beaconing pattern regular (jitter, interval)?",
        ],
        "Exfiltration": [
            "What data was exfiltrated (volume, type, sensitivity)?",
            "What egress path (web, DNS, cloud storage, email)?",
        ],
        "Impact": [
            "What systems/data were affected (encryption, deletion, disruption)?",
            "Are backups available and uncompromised?",
        ],
    }

    questions = base_questions[:]
    if tactic and tactic in tactic_specific:
        questions.extend(tactic_specific[tactic])

    return questions[:8]  # Limit to 8 questions


def analyse_input(text: str) -> AttackLensOutput:
    """
    Main analysis function: map input text to MITRE ATT&CK and produce structured output.

    Args:
        text: Security observation input (log snippet, alert, scan summary, etc.)

    Returns:
        AttackLensOutput with all required fields
    """
    # Input validation
    if not text or not text.strip():
        return AttackLensOutput(
            summary="Error: Empty input provided.",
            tactic=None,
            technique_id=None,
            evidence=[],
            confidence="low",
            why_not="Input is empty or whitespace only.",
            detection_idea=None,
            network_investigation=None,
            remediation="Provide a security observation (log snippet, alert, scan summary, etc.) for analysis.",
            analyst_questions=["What security event or observation would you like analyzed?"]
        )

    text = text.strip()

    # Prompt injection check
    if detect_prompt_injection(text):
        return AttackLensOutput(
            summary="Input rejected: potential prompt injection attempt detected.",
            tactic=None,
            technique_id=None,
            evidence=[],
            confidence="low",
            why_not="Input contains patterns consistent with prompt injection attempts. For safety, the request is declined.",
            detection_idea=None,
            network_investigation=None,
            remediation="Ensure inputs are genuine security observations. Do not attempt to override system instructions.",
            analyst_questions=[]
        )

    # Find ATT&CK mappings
    matches = find_all_mappings(text)
    ranked_matches = rank_mappings(matches)

    # Extract evidence from matched keywords
    matched_keywords = [m[0] for m in ranked_matches]
    evidence = extract_evidence(text, matched_keywords)

    # Determine primary tactic/technique
    if ranked_matches:
        best_match = ranked_matches[0]
        _, tactic, technique_id, technique_name, match_confidence = best_match
        confidence = assess_confidence(ranked_matches, len(text))
        why_not = generate_why_not(ranked_matches, text)
    else:
        tactic = None
        technique_id = None
        technique_name = None
        confidence = "low"
        why_not = generate_why_not([], text)

    # Generate all output fields
    summary = generate_summary(text, tactic, technique_name)
    detection_idea = generate_detection_idea(tactic, technique_id, evidence)
    network_investigation = generate_network_investigation(tactic, technique_id, evidence)
    remediation = generate_remediation(tactic, technique_id, evidence)
    analyst_questions = generate_analyst_questions(tactic, technique_id, evidence)

    return AttackLensOutput(
        summary=summary,
        tactic=tactic,
        technique_id=f"{technique_id} ({technique_name})" if technique_id else None,
        evidence=evidence,
        confidence=confidence,
        why_not=why_not,
        detection_idea=detection_idea,
        network_investigation=network_investigation,
        remediation=remediation,
        analyst_questions=analyst_questions
    )


def format_output(output: AttackLensOutput) -> str:
    """Format output as human-readable text for Gradio display."""
    lines = []
    lines.append(f"Summary: {output.summary}")
    lines.append(f"Tactic: {output.tactic or 'None'}")
    lines.append(f"Technique ID: {output.technique_id or 'None'}")
    lines.append(f"Confidence: {output.confidence}")

    if output.evidence:
        lines.append("Evidence:")
        for e in output.evidence:
            lines.append(f"  - \"{e}\"")
    else:
        lines.append("Evidence: None")

    if output.why_not:
        lines.append(f"Why Not: {output.why_not}")

    if output.detection_idea:
        lines.append(f"Detection Idea: {output.detection_idea}")

    if output.network_investigation:
        lines.append(f"Network Investigation: {output.network_investigation}")

    lines.append(f"Remediation: {output.remediation}")

    if output.analyst_questions:
        lines.append("Analyst Questions:")
        for q in output.analyst_questions:
            lines.append(f"  - {q}")

    return "\n".join(lines)