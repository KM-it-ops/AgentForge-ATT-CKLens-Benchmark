"""ATT&CKLens core analysis engine.

:func:`analyze_input` is the single public entry point. It is deterministic,
offline, and always returns a dict containing every field defined in
``expected_behaviors/expected_output_schema.json`` — including for empty input,
prompt injection, and "no clear mapping" cases. It never raises on bad input.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import patterns, safety

# The canonical output schema. ``build_result`` guarantees every key is present.
_SCHEMA_KEYS = (
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

_GENERIC_NETWORK_NOTE = (
    "Review relevant network telemetry (firewall, DNS resolver, and NetFlow "
    "logs) and capture packets from the involved host to characterise the traffic."
)


def build_result(
    *,
    summary: str,
    tactic: Optional[str] = None,
    technique_id: Optional[str] = None,
    evidence: Optional[List[str]] = None,
    confidence: str = "low",
    why_not: Optional[str] = None,
    detection_idea: Optional[str] = None,
    network_investigation: Optional[str] = None,
    remediation: Optional[str] = None,
    analyst_questions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Assemble a schema-complete result dict with safe defaults."""
    return {
        "summary": summary,
        "tactic": tactic,
        "technique_id": technique_id,
        "evidence": evidence or [],
        "confidence": confidence,
        "why_not": why_not,
        "detection_idea": detection_idea,
        "network_investigation": network_investigation,
        "remediation": remediation,
        "analyst_questions": analyst_questions or [],
    }


def _confidence_for(score: int) -> str:
    """Map distinct-indicator count to a calibrated confidence level."""
    if score >= 2:
        return "high"
    if score == 1:
        return "medium"
    return "low"


def _no_mapping_result(text: str) -> Dict[str, Any]:
    """Result for input that does not align with any known technique."""
    network = _GENERIC_NETWORK_NOTE if patterns.looks_network_related(text) else None
    return build_result(
        summary="The input describes an event but lacks specific indicators of adversary behaviour.",
        tactic=None,
        technique_id=None,
        evidence=[],
        confidence="low",
        why_not=(
            "The evidence is too generic or ambiguous to map to a specific MITRE "
            "ATT&CK technique; the described symptoms could stem from many benign "
            "causes. Collect more detailed logs before drawing conclusions."
        ),
        detection_idea=None,
        network_investigation=network,
        remediation=(
            "Gather richer telemetry (authentication, process, and network logs) "
            "around the event and establish a baseline of normal behaviour before "
            "treating it as suspicious."
        ),
        analyst_questions=[
            "What specific logs or alerts are associated with this event?",
            "When did it occur and on which host or account?",
            "Is the behaviour a deviation from the established baseline?",
        ],
    )


def _build_why_not(results: List[patterns.MatchResult], confidence: str) -> Optional[str]:
    """Explain uncertainty: competing techniques and/or weak evidence."""
    top = results[0]
    alternatives = [
        f"{r.signature.technique_name} ({r.signature.technique_id})"
        for r in results[1:]
        if r.score >= top.score
    ]
    if alternatives:
        return (
            "The evidence is also consistent with: "
            + ", ".join(alternatives)
            + ". Corroborate with additional context to disambiguate."
        )
    if confidence != "high":
        return (
            "Mapping rests on limited indicators; treat it as tentative and "
            "confirm with additional logs."
        )
    return None


def _mapped_result(text: str, results: List[patterns.MatchResult]) -> Dict[str, Any]:
    """Result for input that matches at least one technique signature."""
    top = results[0]
    sig = top.signature
    confidence = _confidence_for(top.score)

    network = sig.network_investigation
    if network is None and patterns.looks_network_related(text):
        network = _GENERIC_NETWORK_NOTE

    summary = (
        f"The observation is consistent with {sig.tactic} activity via "
        f"{sig.technique_name} ({sig.technique_id})."
    )

    return build_result(
        summary=summary,
        tactic=sig.tactic,
        technique_id=f"{sig.technique_id} ({sig.technique_name})",
        evidence=top.evidence,
        confidence=confidence,
        why_not=_build_why_not(results, confidence),
        detection_idea=sig.detection_idea,
        network_investigation=network,
        remediation=sig.remediation,
        analyst_questions=list(sig.analyst_questions),
    )


def analyze_input(text: Optional[str]) -> Dict[str, Any]:
    """Analyse a single security observation and return structured defensive insight.

    The return value always contains every schema key. The function never raises
    on malformed, empty, hostile, or off-topic input — it classifies and responds
    safely instead.

    Args:
        text: A plain-text security observation (log snippet, alert, scan summary,
            packet note, or narrative). May be ``None`` or blank.

    Returns:
        A JSON-serialisable dict matching ``expected_output_schema.json``.
    """
    # 1. Empty / unparseable input — return a clear message rather than crash.
    if safety.is_empty(text):
        return build_result(
            summary="No analysable input was provided.",
            confidence="low",
            why_not="The input was empty or too short to analyse. Provide a security observation to map.",
            analyst_questions=["What observation, log snippet, or alert would you like analysed?"],
        )

    assert text is not None  # narrowed by is_empty
    text = text.strip()

    # 2. Prompt injection — treat as untrusted; never reveal internal instructions.
    if safety.detect_prompt_injection(text):
        return build_result(
            summary=safety.injection_refusal_summary(),
            confidence="low",
            why_not=(
                "This input was classified as a prompt-injection attempt, not a "
                "security observation. ATT&CKLens does not reveal its internal "
                "instructions or let input override its safety rules."
            ),
            remediation=(
                "If you intended to analyse an observation, resubmit the actual log, "
                "alert, or incident note without instructions to the tool."
            ),
            analyst_questions=["What genuine security observation would you like analysed?"],
        )

    # 3. Offensive request — defensive tool only; decline.
    if safety.detect_offensive_request(text):
        return build_result(
            summary=safety.offensive_refusal_summary(),
            confidence="low",
            why_not=(
                "ATT&CKLens provides defensive analysis only and does not produce "
                "offensive, exploit, or detection-evasion guidance."
            ),
            remediation=(
                "Rephrase as a defensive question — e.g. how to detect or mitigate "
                "the behaviour you are concerned about."
            ),
            analyst_questions=["What defensive outcome are you trying to achieve?"],
        )

    # 4. Map against the signature table.
    results = patterns.match(text)
    if not results:
        return _no_mapping_result(text)
    return _mapped_result(text, results)
