"""Curated MITRE ATT&CK signature table for ATT&CKLens.

This is intentionally a *small, auditable* set of technique signatures — not a
dump of the full ATT&CK matrix. Each :class:`Signature` describes a handful of
regular-expression indicators and the defensive guidance that applies when those
indicators appear in an observation.

The matching engine (see :func:`match`) is deterministic: identical input always
produces identical output. No external data is fetched and no model is invoked.

Technique names/IDs are embedded for human readability per ``SPEC.md`` (the tool
is explicitly *not* required to fetch live MITRE data).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern, Tuple


@dataclass(frozen=True)
class Signature:
    """A single ATT&CK technique signature.

    Attributes:
        technique_id: ATT&CK technique ID (e.g. ``T1110``).
        technique_name: Human-readable technique name.
        tactic: The ATT&CK tactic this technique serves.
        indicators: Regex strings; each match contributes a piece of evidence
            and increases match strength. Compiled case-insensitively.
        detection_idea: One-sentence description of a SIEM/Splunk-style query.
        remediation: Plain-English defensive actions (best practice only).
        analyst_questions: Follow-up questions an analyst should ask.
        network_investigation: Packet/DNS investigation guidance, or ``None``
            when the technique is not network-oriented.
    """

    technique_id: str
    technique_name: str
    tactic: str
    indicators: List[str]
    detection_idea: str
    remediation: str
    analyst_questions: List[str]
    network_investigation: Optional[str] = None
    _compiled: List[Pattern[str]] = field(default_factory=list, compare=False, repr=False)

    def compiled(self) -> List[Pattern[str]]:
        """Return (and lazily cache) the compiled, case-insensitive patterns."""
        if not self._compiled:
            # frozen dataclass: mutate the list in place rather than reassign.
            self._compiled.extend(re.compile(p, re.IGNORECASE) for p in self.indicators)
        return self._compiled


# --- Signature table -------------------------------------------------------
# Ordered by priority; earlier entries win ties in :func:`match`.

SIGNATURES: List[Signature] = [
    Signature(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        indicators=[
            r"failed\s+(?:ssh\s+)?login",
            r"multiple\s+failed\s+login",
            r"failed\s+(?:password|authentication)",
            r"\bbrute[\s-]?force",
            r"repeated\s+login\s+attempts",
        ],
        detection_idea=(
            "Alert when a single source IP or account accumulates many failed "
            "authentication events within a short time window (e.g. >5 failures "
            "in 1 minute), then a success."
        ),
        remediation=(
            "Enforce multi-factor authentication, apply account lockout/backoff "
            "policies, restrict SSH exposure (key-based auth, allow-lists, fail2ban), "
            "and alert on failed-login spikes."
        ),
        analyst_questions=[
            "Did any of the failed attempts eventually succeed?",
            "Is the source IP known/expected, or external and unfamiliar?",
            "Are multiple accounts being targeted (password spraying) or just one?",
        ],
    ),
    Signature(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        indicators=[
            r"powershell(?:\.exe)?",
            r"encoded\s*command",
            r"-enc(?:odedcommand)?\b",
            r"\bIEX\b|invoke-expression",
            r"downloadstring|frombase64string",
        ],
        detection_idea=(
            "Search process-creation logs (e.g. Sysmon Event ID 1 / Windows 4688) "
            "for powershell.exe invoked with -EncodedCommand or obfuscated/base64 "
            "arguments."
        ),
        remediation=(
            "Enable PowerShell script-block and module logging, enforce "
            "Constrained Language Mode and signed-script execution policy, and "
            "apply application control (WDAC/AppLocker) to limit interpreter abuse."
        ),
        analyst_questions=[
            "What was the decoded content of the encoded PowerShell command?",
            "What parent process spawned PowerShell, and was it expected?",
            "Did the command attempt outbound network connections or file writes?",
        ],
    ),
    Signature(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        indicators=[
            r"\bnmap\b",
            r"scan\s+report",
            r"port\s+scan",
            r"\d+/tcp\s+open",
            r"filtered\s+ports",
        ],
        detection_idea=(
            "Detect a single source contacting many distinct ports/hosts in a "
            "short interval (horizontal/vertical scan) via firewall or NetFlow logs."
        ),
        remediation=(
            "Reduce attack surface by closing unused ports, segment the network, "
            "place exposed services behind a firewall/allow-list, and monitor for "
            "scanning patterns."
        ),
        analyst_questions=[
            "Is the scanning source internal or external?",
            "Which services were found open, and are they intended to be exposed?",
            "Was the scan followed by connection attempts to the open services?",
        ],
        network_investigation=(
            "In packet captures, look for many SYN packets to sequential/varied "
            "ports from one source with few completed handshakes; correlate with "
            "firewall deny logs."
        ),
    ),
    Signature(
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        tactic="Command and Control",
        indicators=[
            r"dns\s+request",
            r"dns\s+quer",
            r"every\s+(?:minute|few\s+seconds|\d+\s*(?:s|sec|seconds|m|min))",
            r"beacon",
            r"traffic\s+persists",
            r"suspicious[\s-]?domain",
        ],
        detection_idea=(
            "Flag hosts making regular, periodic DNS queries to rare or newly "
            "registered domains (low-and-slow beaconing) using DNS resolver logs."
        ),
        remediation=(
            "Route DNS through controlled resolvers with logging, block/sinkhole "
            "known-bad and newly registered domains, and alert on beacon-like "
            "periodicity and high-entropy domain names."
        ),
        analyst_questions=[
            "Does the queried domain resolve, and is it newly registered or rare?",
            "Is the query interval regular (a hallmark of automated beaconing)?",
            "Which process on the host is generating the DNS traffic?",
        ],
        network_investigation=(
            "Inspect DNS query logs and packet captures for repeated queries to "
            "the suspicious domain; check for unusually long subdomains (possible "
            "DNS tunnelling) and monitor outbound connections from the host."
        ),
    ),
    Signature(
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        tactic="Credential Access",
        indicators=[
            r"lsass",
            r"mimikatz",
            r"credential\s+dump",
            r"\bsam\b\s+(?:hive|dump)|ntds\.dit",
        ],
        detection_idea=(
            "Alert on suspicious access to LSASS memory or shadow-copy access to "
            "the SAM/NTDS database in EDR/Sysmon logs."
        ),
        remediation=(
            "Enable LSASS protection (RunAsPPL/Credential Guard), restrict "
            "debug/SeDebug privileges, and monitor for unauthorized access to "
            "credential stores."
        ),
        analyst_questions=[
            "Which process accessed the credential store, and with what privileges?",
            "Was this activity performed by an administrator during expected work?",
            "Were any extracted credentials subsequently used elsewhere?",
        ],
    ),
    Signature(
        technique_id="T1566",
        technique_name="Phishing",
        tactic="Initial Access",
        indicators=[
            r"phish",
            r"suspicious\s+(?:email|attachment|link)",
            r"clicked\s+(?:a\s+)?link",
            r"malicious\s+attachment",
        ],
        detection_idea=(
            "Correlate email-gateway verdicts with user click-through and "
            "subsequent process execution to surface successful phishing."
        ),
        remediation=(
            "Deploy email filtering and link rewriting, run user awareness "
            "training, and enable MFA so stolen credentials are less useful."
        ),
        analyst_questions=[
            "Did the user interact with the link or attachment?",
            "What did the attachment or linked page attempt to do?",
            "Were other recipients targeted by the same campaign?",
        ],
    ),
]


# Words that hint at network activity, used to decide whether to add a generic
# network-investigation note even when the matched technique has none.
_NETWORK_HINT = re.compile(
    r"\b(network|dns|ip\b|packet|traffic|outbound|connection|port|domain|udp|tcp)\b",
    re.IGNORECASE,
)


@dataclass
class MatchResult:
    """Outcome of matching one signature against an observation."""

    signature: Signature
    evidence: List[str]
    score: int


def _find_evidence(text: str, signature: Signature) -> Tuple[List[str], int]:
    """Return (deduped evidence fragments, distinct-indicator count) for a signature.

    Evidence fragments are quoted verbatim from ``text`` (original casing) so the
    tool never fabricates wording that is not present in the input.
    """
    seen = set()
    evidence: List[str] = []
    matched_indicators = 0
    for pattern in signature.compiled():
        found = pattern.search(text)
        if found:
            matched_indicators += 1
            fragment = found.group(0).strip()
            key = fragment.lower()
            if key not in seen:
                seen.add(key)
                evidence.append(fragment)
    return evidence, matched_indicators


def match(text: str) -> List[MatchResult]:
    """Match ``text`` against the signature table.

    Returns every signature with at least one indicator hit, sorted by score
    (descending) then by table order (stable), so the strongest, highest-priority
    match is first. An empty list means no technique applies.
    """
    results: List[MatchResult] = []
    for signature in SIGNATURES:
        evidence, score = _find_evidence(text, signature)
        if score > 0:
            results.append(MatchResult(signature=signature, evidence=evidence, score=score))
    # Stable sort preserves table priority for equal scores.
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def looks_network_related(text: str) -> bool:
    """True if the observation mentions network concepts (for generic guidance)."""
    return bool(_NETWORK_HINT.search(text))
