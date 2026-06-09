"""ATT&CKLens core package.

A small, deterministic, offline engine that maps a single defensive security
observation to a likely MITRE ATT&CK tactic/technique and produces structured
defensive analysis. No language model, no network calls, no paid APIs.
"""

from .core import analyze_input

__all__ = ["analyze_input"]
