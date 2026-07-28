"""Prompt-injection detection heuristics.

Scope and honest limitations (read before deploying):

  * This is a *pre-filter*, not a control. It raises the cost of the easy 80% of
    injection attempts. It will not stop a motivated adversary who has read this file,
    and it is trivially evadable by paraphrase.
  * Any architecture that relies on detection alone is broken. Detection belongs
    behind the structural controls in docs/mitigations.md (privilege separation,
    untrusted-content fencing, output-side authorisation), never instead of them.
  * Tuned for precision over recall. In a SOC pipeline the cost of drowning an analyst
    in false positives is higher than the cost of missing a low-signal attempt, because
    a noisy detector gets switched off.

Zero dependencies, stdlib only, so it can be dropped into any pipeline or called
from an n8n Execute Command / Code node.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# (weight, technique, compiled pattern)
_RULES: list[tuple[float, str, re.Pattern]] = []


def _rule(weight: float, technique: str, pattern: str) -> None:
    _RULES.append((weight, technique, re.compile(pattern, re.IGNORECASE)))


# --- instruction override -------------------------------------------------------
_rule(4.0, "direct-override", r"\bignore (?:all |any |the )?(?:previous|prior|above|earlier)\b")
_rule(4.0, "direct-override", r"\bdisregard (?:all |any |the )?(?:previous|prior|above|earlier)\b")
_rule(2.5, "direct-override", r"\bforget (?:everything|all)\b.{0,30}\b(?:told|said|instruct)")
_rule(2.5, "direct-override", r"\boverrid(?:e|ing) (?:your |the )?(?:rules|instructions|prompt|guidelines)\b")
_rule(2.0, "direct-override", r"\b(?:new|updated) (?:instructions?|rules?|directives?)\s*[:\-]")

# --- authority spoofing ---------------------------------------------------------
_rule(3.0, "authority-spoof", r"<\/?(?:system|system_update|admin|developer|operator)[^>]*>")
_rule(2.5, "authority-spoof", r"^\s*(?:system|assistant|developer)\s*:", )
_rule(2.5, "authority-spoof", r"\[(?:system|admin|developer|operator)(?:\s+message)?\]")
_rule(2.0, "authority-spoof", r"\bthis is (?:your |the )?(?:developer|administrator|operator|safety team)\b")
_rule(2.0, "authority-spoof", r"\b(?:maintenance|diagnostic|debug) mode (?:is )?(?:active|enabled|on)\b")

# --- policy / persona subversion ------------------------------------------------
_rule(2.5, "role-frame", r"\byou are (?:now|no longer)\b.{0,40}\b(?:unrestricted|unfiltered|uncensored|free)\b")
_rule(2.0, "role-frame", r"\b(?:developer|god|debug|dan|jailbreak) mode\b")
_rule(1.5, "role-frame", r"\bpretend (?:that )?you (?:are|have no)\b")
_rule(1.5, "role-frame", r"\bwithout (?:any )?(?:restrictions|filters|limitations|censorship)\b")
_rule(1.5, "role-frame", r"\bhypothetically,? if you (?:could|had no)\b")

# --- disclosure targeting -------------------------------------------------------
_rule(2.5, "system-prompt-extraction", r"\b(?:repeat|print|show|reveal|output|display|echo)\b.{0,40}\b(?:system prompt|initial instructions|your instructions|your rules)\b")
_rule(2.0, "system-prompt-extraction", r"\bwhat (?:were|are) your (?:original |initial )?instructions\b")
_rule(2.0, "system-prompt-extraction", r"\beverything above this (?:line|message|point)\b")

# --- indirect / tool-boundary ---------------------------------------------------
_rule(3.0, "indirect-injection", r"\bnote to (?:the )?(?:assistant|ai|model|llm|agent)\b")
_rule(2.5, "indirect-injection", r"\b(?:assistant|ai|model|agent)[:,]?\s+(?:you must|you should|please)\b.{0,60}\b(?:before|instead of) (?:answering|summaris|summariz|respond)")
_rule(2.0, "indirect-injection", r"\bif you are (?:an? )?(?:ai|llm|assistant|reading this)\b")
_rule(2.0, "tool-output-trust", r"\[/?tool_(?:result|call|output)[^\]]*\]")

# --- obfuscation ----------------------------------------------------------------
_rule(1.5, "encoding-indirection", r"\b(?:base64|rot13|hex|morse|leetspeak)\b.{0,40}\b(?:decode|encode|output|respond|answer)\b")
_rule(1.5, "encoding-indirection", r"\brespond (?:only )?in (?:base64|rot13|hex)\b")

# Calibrated so that one canonical, unambiguous override phrase reaches "high" on its
# own, while any single weaker indicator cannot. Retune against your own traffic before
# wiring this to a blocking action — see docs/mitigations.md.
_SEVERITY_BANDS = ((4.0, "high"), (2.0, "medium"), (1.0, "low"))

# Zero-width and bidi-control characters: near-zero legitimate use in user input,
# and a standard way to hide instructions from human reviewers while keeping them
# visible to the tokeniser.
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")


@dataclass
class Signal:
    technique: str
    weight: float
    excerpt: str


@dataclass
class Detection:
    score: float
    severity: str
    signals: list[Signal] = field(default_factory=list)
    normalised_changed: bool = False

    @property
    def flagged(self) -> bool:
        return self.severity != "none"

    @property
    def techniques(self) -> list[str]:
        return sorted({s.technique for s in self.signals})

    def to_dict(self) -> dict:
        return {
            "flagged": self.flagged,
            "score": round(self.score, 2),
            "severity": self.severity,
            "techniques": self.techniques,
            "signals": [
                {"technique": s.technique, "weight": s.weight, "excerpt": s.excerpt}
                for s in self.signals
            ],
            "obfuscation_normalised": self.normalised_changed,
        }


def _normalise(text: str) -> tuple[str, bool]:
    """Fold Unicode confusables and strip invisibles before matching.

    Without this step every rule above is defeated by a homoglyph or a zero-width
    space, which is the first thing an evader tries.
    """
    stripped = _INVISIBLE.sub("", text)
    folded = unicodedata.normalize("NFKC", stripped)
    return folded, folded != text


def _decoded_candidates(text: str) -> list[str]:
    """Surface plausible base64 blobs so hidden instructions get scanned too."""
    out: list[str] = []
    for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if sum(ch.isprintable() for ch in decoded) > 0.8 * max(len(decoded), 1):
            out.append(decoded)
    return out


def scan(text: str, *, scan_encoded: bool = True) -> Detection:
    """Score `text` for prompt-injection indicators."""
    if not text:
        return Detection(score=0.0, severity="none")

    normalised, changed = _normalise(text)
    haystacks = [normalised]
    if scan_encoded:
        haystacks.extend(_decoded_candidates(normalised))

    signals: list[Signal] = []
    seen: set[tuple[str, str]] = set()
    for haystack in haystacks:
        for weight, technique, pattern in _RULES:
            match = pattern.search(haystack)
            if not match:
                continue
            excerpt = haystack[max(0, match.start() - 20): match.end() + 40].strip()
            key = (technique, excerpt)
            if key in seen:
                continue
            seen.add(key)
            signals.append(Signal(technique=technique, weight=weight, excerpt=excerpt))

    score = sum(s.weight for s in signals)
    if changed:
        # Obfuscation is itself evidence, but only alongside a substantive hit —
        # otherwise every emoji-heavy message trips the detector.
        score += 1.5 if signals else 0.0

    severity = "none"
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            severity = label
            break

    return Detection(score=score, severity=severity, signals=signals, normalised_changed=changed)
