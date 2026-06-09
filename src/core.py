"""Deterministic defensive mapping logic for ATT&CKLens."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable


REQUIRED_FIELDS = [
    "summary",
    "tactic",
    "technique_id",
    "evidence",
    "confidence",
    "why_not",
    "detection_idea",
    "network_investigation",
    "remediation",
    "analyst_questions",
]


@dataclass(frozen=True)
class MappingRule:
    """A small defensive rule for one ATT&CKLens MVP scenario."""

    name: str
    patterns: tuple[str, ...]
    summary: str
    tactic: str
    technique_id: str
    confidence: str
    detection_idea: str
    network_investigation: str | None
    remediation: str
    analyst_questions: tuple[str, ...]
    why_not: str | None = None

    def matches(self, normalized_text: str) -> bool:
        return any(re.search(pattern, normalized_text, re.IGNORECASE) for pattern in self.patterns)


MAPPING_RULES = [
    MappingRule(
        name="ssh_bruteforce",
        patterns=(r"failed\s+ssh\s+login", r"multiple\s+failed\s+login", r"user\s+root.*port\s+22"),
        summary="The input describes failed SSH authentication activity that may indicate brute-force attempts.",
        tactic="Credential Access",
        technique_id="T1110 (Brute Force)",
        confidence="high",
        detection_idea="Alert on repeated failed SSH logins from the same source IP or against privileged accounts within a short time window.",
        network_investigation="Review SSH connection attempts, source IP reputation, and repeated TCP sessions to port 22.",
        remediation="Enforce MFA where possible, disable direct root SSH login, use account lockout or throttling, and review exposed SSH access.",
        analyst_questions=(
            "How many failures occurred and over what time window?",
            "Did any failed attempts become a successful login?",
            "Is the source IP expected for this environment?",
        ),
    ),
    MappingRule(
        name="encoded_powershell",
        patterns=(r"powershell", r"encoded\s+command", r"encodedcommand", r"system32\\+windowspowershell"),
        summary="The input describes suspicious PowerShell execution with encoded command usage.",
        tactic="Execution",
        technique_id="T1059.001 (PowerShell)",
        confidence="high",
        detection_idea="Alert on PowerShell processes using encoded command flags, suspicious parent processes, or unusual script block activity.",
        network_investigation=None,
        remediation="Collect the command line and script block logs, verify the parent process, isolate affected hosts if needed, and harden PowerShell logging and execution policy controls.",
        analyst_questions=(
            "What parent process launched PowerShell?",
            "What user context executed the command?",
            "Can the encoded content be decoded safely in an isolated analysis workflow?",
        ),
    ),
    MappingRule(
        name="suspicious_dns",
        patterns=(r"repeated\s+dns\s+requests", r"suspicious-domain\.com", r"dns.*every\s+minute"),
        summary="The input describes repeated DNS requests to a suspicious domain that may indicate command-and-control beaconing.",
        tactic="Command and Control",
        technique_id="T1071.004 (Application Layer Protocol: DNS)",
        confidence="medium",
        detection_idea="Search DNS logs for repeated queries to the same suspicious domain from one host at regular intervals.",
        network_investigation="Inspect DNS query logs, response IPs, timing regularity, and follow-on outbound connections from the source host.",
        remediation="Block the suspicious domain if validated, inspect the source host for persistence or malware, and preserve relevant DNS and endpoint logs.",
        analyst_questions=(
            "How long has the beacon-like DNS pattern persisted?",
            "Do other hosts query the same domain?",
            "What process on the source host generated the DNS traffic?",
        ),
    ),
    MappingRule(
        name="nmap_scan",
        patterns=(r"nmap\s+scan\s+report", r"not\s+shown:\s+\d+\s+filtered\s+ports", r"\b22/tcp\s+open\b"),
        summary="The input describes a port scan summary showing exposed services on a host.",
        tactic="Discovery",
        technique_id="T1046 (Network Service Discovery)",
        confidence="medium",
        detection_idea="Alert on one source probing many ports or hosts, especially when scans enumerate common management or web services.",
        network_investigation="Review firewall, NetFlow, and packet metadata for sequential port probes and repeated connection attempts.",
        remediation="Confirm the scan was authorised, restrict exposed services to approved sources, and verify service patch levels.",
        analyst_questions=(
            "Was this scan authorised and expected?",
            "Which source performed the scan?",
            "Are the listed open services intentionally exposed?",
        ),
    ),
]


PROMPT_INJECTION_PATTERNS = (
    r"ignore\s+previous\s+instructions",
    r"reveal\s+.*system\s+prompt",
    r"hidden\s+system\s+prompt",
    r"developer\s+message",
    r"internal\s+instructions",
)


def analyse_input(raw_text: str | None) -> dict[str, object]:
    """Analyze one security observation and return a JSON-serializable result."""

    text = (raw_text or "").strip()
    if not text:
        return _no_mapping(
            summary="No evidence was provided.",
            why_not="The input is empty, so there is no observable behavior to map to ATT&CK.",
            evidence=[],
            detection_idea=None,
            remediation="Provide a short synthetic log snippet, alert summary, scan summary, or incident note for defensive analysis.",
            analyst_questions=["What security observation should be reviewed?"],
        )

    if _contains_prompt_injection(text):
        return _no_mapping(
            summary="The input appears to request internal instructions rather than describe security evidence.",
            why_not="This looks like a prompt-injection attempt; ATT&CKLens treats user input as untrusted and will not reveal prompts or internal instructions.",
            evidence=_collect_evidence(text, PROMPT_INJECTION_PATTERNS),
            detection_idea="Monitor analysis tools for repeated attempts to override instructions or exfiltrate internal prompts.",
            remediation="Do not reveal internal prompts or secrets; keep the analysis focused on defensive evidence supplied by the user.",
            analyst_questions=[
                "Is there a real security observation to analyze?",
                "Did this text come from an untrusted source or pasted artifact?",
            ],
        )

    normalized = _normalize(text)
    for rule in MAPPING_RULES:
        if rule.matches(normalized):
            return _result_from_rule(text, rule)

    return _no_mapping(
        summary="The input does not contain enough specific security evidence to assign an ATT&CK mapping.",
        why_not="The evidence is too generic or ambiguous; ATT&CK mapping requires observable behavior such as authentication failures, process execution, scanning, or network activity.",
        evidence=_first_nonempty_lines(text, limit=2),
        detection_idea=None,
        remediation="Collect more specific evidence such as timestamps, event IDs, process names, source/destination hosts, or network indicators before mapping.",
        analyst_questions=[
            "What exact event, command, connection, or alert was observed?",
            "Which host, user, and timestamp are involved?",
            "Is there corroborating endpoint, authentication, or network telemetry?",
        ],
    )


def format_analysis(result: dict[str, object]) -> str:
    """Render an analysis dictionary into concise human-readable Markdown."""

    lines = [
        f"### Summary\n{result['summary']}",
        f"**Tactic:** {result['tactic'] or 'No clear mapping'}",
        f"**Technique:** {result['technique_id'] or 'No clear technique'}",
        f"**Confidence:** {result['confidence']}",
    ]
    if result.get("why_not"):
        lines.append(f"**Why not:** {result['why_not']}")
    evidence = result.get("evidence") or []
    if evidence:
        quoted = "\n".join(f"- `{item}`" for item in evidence)
        lines.append(f"**Evidence:**\n{quoted}")
    if result.get("detection_idea"):
        lines.append(f"**Detection idea:** {result['detection_idea']}")
    if result.get("network_investigation"):
        lines.append(f"**Network investigation:** {result['network_investigation']}")
    if result.get("remediation"):
        lines.append(f"**Remediation:** {result['remediation']}")
    questions = result.get("analyst_questions") or []
    if questions:
        rendered_questions = "\n".join(f"- {question}" for question in questions)
        lines.append(f"**Analyst questions:**\n{rendered_questions}")
    return "\n\n".join(lines)


def _result_from_rule(text: str, rule: MappingRule) -> dict[str, object]:
    evidence = _collect_evidence(text, rule.patterns) or _first_nonempty_lines(text, limit=2)
    return _with_required_fields(
        {
            "summary": rule.summary,
            "tactic": rule.tactic,
            "technique_id": rule.technique_id,
            "evidence": evidence,
            "confidence": rule.confidence,
            "why_not": rule.why_not,
            "detection_idea": rule.detection_idea,
            "network_investigation": rule.network_investigation,
            "remediation": rule.remediation,
            "analyst_questions": list(rule.analyst_questions),
        }
    )


def _no_mapping(
    *,
    summary: str,
    why_not: str,
    evidence: list[str],
    detection_idea: str | None,
    remediation: str,
    analyst_questions: list[str],
) -> dict[str, object]:
    return _with_required_fields(
        {
            "summary": summary,
            "tactic": None,
            "technique_id": None,
            "evidence": evidence,
            "confidence": "low",
            "why_not": why_not,
            "detection_idea": detection_idea,
            "network_investigation": None,
            "remediation": remediation,
            "analyst_questions": analyst_questions,
        }
    )


def _with_required_fields(result: dict[str, object]) -> dict[str, object]:
    return {field: result.get(field) for field in REQUIRED_FIELDS}


def _contains_prompt_injection(text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in PROMPT_INJECTION_PATTERNS)


def _normalize(text: str) -> str:
    return text.replace("/", "\\").replace("-", " ").lower()


def _collect_evidence(text: str, patterns: tuple[str, ...]) -> list[str]:
    evidence: list[str] = []
    for line in _first_nonempty_lines(text, limit=20):
        normalized_line = _normalize(line)
        if any(re.search(pattern, normalized_line, re.IGNORECASE) for pattern in patterns):
            evidence.append(line)
    return _deduplicate(evidence[:3])


def _first_nonempty_lines(text: str, *, limit: int) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()][:limit]


def _deduplicate(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
