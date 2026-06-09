"""Core analysis logic for ATT&CKLens."""

from __future__ import annotations

import json
from typing import Any, Optional

from src.patterns import RULES, MappingRule
from src.safety import (
    is_empty,
    is_prompt_injection,
    is_weak_evidence,
    normalise_input,
)

OUTPUT_KEYS = (
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
)


def _empty_result(message: str, why: str) -> dict[str, Any]:
    return {
        "summary": message,
        "tactic": None,
        "technique_id": None,
        "evidence": [],
        "confidence": "low",
        "why_not": why,
        "detection_idea": None,
        "network_investigation": None,
        "remediation": None,
        "analyst_questions": [
            "Provide a specific log line, alert summary, or observable behaviour.",
            "Include timestamps, hostnames, usernames, or network indicators if available.",
        ],
    }


def _injection_result() -> dict[str, Any]:
    return {
        "summary": "Request refused: input appears to attempt prompt injection.",
        "tactic": None,
        "technique_id": None,
        "evidence": [],
        "confidence": "low",
        "why_not": (
            "System instructions and internal prompts cannot be revealed or overridden. "
            "Provide legitimate security evidence for analysis."
        ),
        "detection_idea": None,
        "network_investigation": None,
        "remediation": (
            "Treat prompt-injection attempts as untrusted input; log and review if repeated."
        ),
        "analyst_questions": [
            "Was this input submitted intentionally for testing?",
            "What legitimate security observation should be analysed instead?",
        ],
    }


def _no_mapping_result(text: str) -> dict[str, Any]:
    if is_weak_evidence(text):
        why = (
            "The observation is too vague or describes benign performance or hardware symptoms "
            "without indicators of adversary behaviour. No ATT&CK mapping is justified."
        )
        summary = "Input describes non-specific or benign symptoms without clear security indicators."
    else:
        why = (
            "No curated mapping rule matched the evidence with sufficient confidence. "
            "Additional context such as process names, auth failures, or network indicators is needed."
        )
        summary = "Evidence does not clearly align with a known ATT&CK tactic or technique."

    return {
        "summary": summary,
        "tactic": None,
        "technique_id": None,
        "evidence": extract_evidence(text, ()),
        "confidence": "low",
        "why_not": why,
        "detection_idea": None,
        "network_investigation": None,
        "remediation": (
            "Collect host and network logs, validate with EDR/SIEM data, and re-run analysis "
            "once specific indicators are available."
        ),
        "analyst_questions": [
            "What exact log lines, alerts, or timestamps support suspicious activity?",
            "Which host, user, or IP was involved?",
            "Was the activity isolated or repeated across systems?",
        ],
    }


def extract_evidence(text: str, keywords: tuple[str, ...]) -> list[str]:
    """Return quoted fragments from input that support a mapping."""
    fragments: list[str] = []
    seen: set[str] = set()

    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if keywords:
            lowered = candidate.lower()
            if not any(keyword.lower() in lowered for keyword in keywords):
                continue
        if candidate not in seen:
            seen.add(candidate)
            fragments.append(candidate)

    if fragments:
        return fragments

    stripped = text.strip()
    return [stripped] if stripped else []


def _apply_rule(text: str, rule: MappingRule) -> dict[str, Any]:
    evidence = extract_evidence(text, rule.evidence_keywords)
    return {
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


def analyse_input(text: Optional[str]) -> dict[str, Any]:
    """Analyse one security observation and return a structured ATT&CK-oriented result."""
    normalised = normalise_input(text)

    if is_empty(normalised):
        return _empty_result(
            "No input provided.",
            "Analysis requires non-empty evidence text.",
        )

    if is_prompt_injection(normalised):
        return _injection_result()

    for rule in RULES:
        if rule.matcher(normalised):
            return _apply_rule(normalised, rule)

    return _no_mapping_result(normalised)


def format_result(result: dict[str, Any]) -> str:
    """Render analysis as human-readable text with embedded JSON."""
    lines = [
        "=== ATT&CKLens Analysis ===",
        "",
        f"Summary: {result.get('summary')}",
        f"Tactic: {result.get('tactic') or 'None'}",
        f"Technique: {result.get('technique_id') or 'None'}",
        f"Confidence: {result.get('confidence')}",
        "",
        "Evidence:",
    ]

    evidence = result.get("evidence") or []
    if evidence:
        lines.extend(f'  - "{item}"' for item in evidence)
    else:
        lines.append("  - (none)")

    if result.get("why_not"):
        lines.extend(["", f"Why not / uncertainty: {result['why_not']}"])

    if result.get("detection_idea"):
        lines.extend(["", f"Detection idea: {result['detection_idea']}"])

    if result.get("network_investigation"):
        lines.extend(["", f"Network investigation: {result['network_investigation']}"])

    if result.get("remediation"):
        lines.extend(["", f"Remediation: {result['remediation']}"])

    questions = result.get("analyst_questions") or []
    if questions:
        lines.extend(["", "Analyst questions:"])
        lines.extend(f"  - {question}" for question in questions)

    lines.extend(["", "=== JSON ===", json.dumps(result, indent=2)])
    return "\n".join(lines)
