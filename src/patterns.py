"""Curated evidence-to-ATT&CK mapping rules (deterministic, local)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class MappingRule:
    name: str
    matcher: Callable[[str], bool]
    evidence_keywords: tuple[str, ...]
    tactic: str
    technique_id: str
    confidence: str
    summary: str
    detection_idea: Optional[str]
    network_investigation: Optional[str]
    remediation: str
    analyst_questions: tuple[str, ...]
    why_not: Optional[str] = None


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


def _regex_match(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.I) is not None


RULES: tuple[MappingRule, ...] = (
    MappingRule(
        name="ssh_brute_force",
        matcher=lambda t: _contains_any(t, ("failed ssh login", "failed login"))
        and _contains_any(t, ("ssh", "login", "port 22")),
        evidence_keywords=("failed", "login", "ssh"),
        tactic="Credential Access",
        technique_id="T1110 (Brute Force)",
        confidence="high",
        summary="Repeated or failed remote authentication attempts suggest credential guessing against SSH.",
        detection_idea=(
            "Search authentication logs for multiple failed logins to the same account "
            "or source IP within a short time window."
        ),
        network_investigation=None,
        remediation=(
            "Enforce multi-factor authentication, restrict SSH to trusted networks, "
            "use fail2ban or equivalent lockout, and disable direct root login where possible."
        ),
        analyst_questions=(
            "How many failed attempts occurred and from which source IPs?",
            "Was the account eventually compromised?",
            "Are SSH keys or password auth in use?",
        ),
    ),
    MappingRule(
        name="dns_c2",
        matcher=lambda t: _contains_any(t, ("dns request", "dns queries"))
        or (_contains_any(t, ("dns",)) and _contains_any(t, ("suspicious", "repeated", "every minute"))),
        evidence_keywords=("dns", "suspicious", "repeated", "every minute"),
        tactic="Command and Control",
        technique_id="T1071.004 (Application Layer Protocol: DNS)",
        confidence="medium",
        summary="Periodic DNS activity toward a suspicious domain may indicate beaconing or C2 over DNS.",
        detection_idea=(
            "Alert on repeated DNS queries to newly registered or rare domains from the same host."
        ),
        network_investigation=(
            "Inspect DNS query logs and PCAP for query frequency, NXDOMAIN rates, "
            "and outbound connections following DNS lookups to suspicious-domain.com."
        ),
        remediation=(
            "Block or sinkhole the domain at the resolver, review the host for malware, "
            "and enable DNS logging with threat intelligence feeds."
        ),
        analyst_questions=(
            "Is the domain known malicious or newly registered?",
            "Does traffic continue when user applications are closed?",
            "Are other hosts querying the same domain?",
        ),
    ),
    MappingRule(
        name="powershell_encoded",
        matcher=lambda t: _contains_any(t, ("powershell",)) and _contains_any(
            t, ("encoded command", "-enc", "-encodedcommand", "suspicious powershell")
        ),
        evidence_keywords=("powershell", "encoded", "command"),
        tactic="Execution",
        technique_id="T1059.001 (Command and Scripting Interpreter: PowerShell)",
        confidence="high",
        summary="Suspicious PowerShell execution with encoding flags may indicate scripted execution of obfuscated commands.",
        detection_idea=(
            "Detect powershell.exe spawned with -EncodedCommand or unusual parent processes in EDR/SIEM."
        ),
        network_investigation=None,
        remediation=(
            "Enable PowerShell script block logging, constrain execution with AppLocker or WDAC, "
            "and investigate the parent process and user context."
        ),
        analyst_questions=(
            "What was the full command line and parent process?",
            "Was the script signed or downloaded?",
            "Are similar events seen on other endpoints?",
        ),
    ),
    MappingRule(
        name="port_scan",
        matcher=lambda t: _regex_match(t, r"\bnmap\b") or (
            _contains_any(t, ("open", "filtered")) and _contains_any(t, ("port", "/tcp", "scan"))
        ),
        evidence_keywords=("nmap", "open", "port", "scan"),
        tactic="Discovery",
        technique_id="T1046 (Network Service Discovery)",
        confidence="medium",
        summary="Host or port enumeration activity is consistent with network service discovery.",
        detection_idea=(
            "Correlate connection attempts across many ports or IDS alerts for horizontal scanning."
        ),
        network_investigation=(
            "Review firewall and IDS logs for the scanner source and targeted ports; "
            "confirm whether scanning was authorised."
        ),
        remediation=(
            "Restrict internal scanning to approved tools and accounts, segment sensitive networks, "
            "and alert on unauthorised scan patterns."
        ),
        analyst_questions=(
            "Was the scan authorised and from an expected source?",
            "Which services were targeted and are they patched?",
            "Did scanning precede exploitation attempts?",
        ),
    ),
)
