"""Input validation and prompt-injection detection."""

from __future__ import annotations

import re
from typing import Optional

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|system)\s+instructions", re.I),
    re.compile(r"reveal\s+(the\s+)?(hidden\s+)?system\s+prompt", re.I),
    re.compile(r"show\s+(me\s+)?(your\s+)?(hidden\s+)?system\s+prompt", re.I),
    re.compile(r"print\s+(your\s+)?(system\s+)?prompt", re.I),
    re.compile(r"what\s+are\s+your\s+(system\s+)?instructions", re.I),
    re.compile(r"repeat\s+(the\s+)?(system|initial)\s+prompt", re.I),
)

WEAK_EVIDENCE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(seemed|felt)\s+slow\b", re.I),
    re.compile(r"\bperformance\s+(issue|problem)\b", re.I),
    re.compile(r"\bodd\s+noises\b", re.I),
    re.compile(r"\bblinking\s+lights\b", re.I),
    re.compile(r"\bno\s+additional\s+information\b", re.I),
)


def normalise_input(text: Optional[str]) -> str:
    if text is None:
        return ""
    return text.strip()


def is_empty(text: str) -> bool:
    return not normalise_input(text)


def is_prompt_injection(text: str) -> bool:
    return any(pattern.search(text) for pattern in INJECTION_PATTERNS)


def is_weak_evidence(text: str) -> bool:
    return any(pattern.search(text) for pattern in WEAK_EVIDENCE_PATTERNS)
