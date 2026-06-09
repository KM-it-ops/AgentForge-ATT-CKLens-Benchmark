"""Safety layer for ATT&CKLens: input validation and prompt-injection handling.

All user input is treated as untrusted. This module never reveals internal
instructions and never emits offensive guidance — it only classifies input and
produces safe, defensive responses.
"""

from __future__ import annotations

import re
from typing import Optional

# Minimum number of non-whitespace characters for an observation to be analysable.
MIN_LENGTH = 3

# Phrases that indicate an attempt to override instructions or exfiltrate the
# system prompt. Matched case-insensitively against the raw input.
_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(?:all\s+)?(?:previous|prior|above|the)\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?(?:hidden\s+)?(?:system\s+)?prompt",
    r"show\s+(?:me\s+)?(?:the\s+)?(?:system\s+)?prompt",
    r"what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions)",
    r"print\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)",
    r"forget\s+(?:everything|all|your)\s+(?:instructions|rules)",
    r"you\s+are\s+now\s+(?:a|an|in)\b",
    r"act\s+as\s+(?:if|though|a)\b",
    r"bypass\s+(?:your\s+)?(?:safety|security|rules|filters)",
    r"developer\s+mode|jailbreak|DAN\s+mode",
    r"override\s+(?:your\s+)?(?:safety|instructions|rules)",
]

_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

# Phrases requesting offensive / exploit assistance. ATT&CKLens is defensive
# only and must decline these.
_OFFENSIVE_PATTERNS = [
    r"how\s+(?:do\s+i|to|can\s+i)\s+(?:exploit|hack|attack|compromise|breach)",
    r"write\s+(?:me\s+)?(?:an?\s+)?(?:exploit|malware|ransomware|payload|virus)",
    r"how\s+to\s+(?:evade|bypass|disable|defeat)\s+(?:detection|edr|antivirus|av|logging|the\s+siem)",
    r"help\s+me\s+(?:exploit|hack|attack|break\s+into)",
    r"generate\s+(?:a\s+)?(?:reverse\s+shell|payload|exploit)",
]

_OFFENSIVE_RE = [re.compile(p, re.IGNORECASE) for p in _OFFENSIVE_PATTERNS]


def is_empty(text: Optional[str]) -> bool:
    """True if the input is missing, blank, or shorter than :data:`MIN_LENGTH`."""
    if not text:
        return True
    return len(text.strip()) < MIN_LENGTH


def detect_prompt_injection(text: str) -> bool:
    """True if the input appears to be a prompt-injection / instruction-override attempt."""
    return any(rx.search(text) for rx in _INJECTION_RE)


def detect_offensive_request(text: str) -> bool:
    """True if the input is asking for offensive/exploit assistance."""
    return any(rx.search(text) for rx in _OFFENSIVE_RE)


def injection_refusal_summary() -> str:
    """Safe one-line summary returned when prompt injection is detected."""
    return (
        "The input appears to be an attempt to override the tool's instructions "
        "rather than a security observation; it was treated as untrusted and not acted upon."
    )


def offensive_refusal_summary() -> str:
    """Safe one-line summary returned when offensive guidance is requested."""
    return (
        "The input requests offensive or exploit guidance, which ATT&CKLens does "
        "not provide; only defensive analysis is supported."
    )
