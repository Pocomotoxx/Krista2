"""Deterministic redaction and secret detection for records.

Enforced records are metadata: they carry references and locators, not raw content
or credentials. This module keeps that promise checkable. `find_secrets` reports the
credential- and endpoint-shaped values in a string; `redact` masks them while
retaining semantic context. Both are deterministic and dependency-free, so the same
input always yields the same result.

The detection is a *heuristic*: it recognises known secret shapes, so it can miss a
novel one (false negative) and it can trip on a benign look-alike (false positive).
Two things make that heuristic honest rather than magical: a measured fixture corpus
(scripts/tests/fixtures/redaction_corpus.json, exercised by the tests) pins recall
on known secrets and guards against known false positives, and an allowlist scrubs a
small set of shapes that look secret-like but are safe (a content digest, an explicit
redaction marker). See runtime/RECORD_HYGIENE_POLICY.md for the known-limit classes.

Ported from the FRR standalone system (Pocomotoxx/frr), which adapts the redaction
discipline of the PhyAgentOS embodied-agent OS.
"""

from __future__ import annotations

import re

# Benign shapes that look secret-like but are safe to carry: a content digest and an
# explicit redaction marker. Scrubbed before detection so they never raise a false
# positive. NOTE: reserved example domains (example.com/org) are deliberately NOT
# allowlisted — a live URL of any host is still an endpoint a record must not embed.
_ALLOW: list["re.Pattern[str]"] = [
    re.compile(r"\b(?:sha1|sha224|sha256|sha384|sha512|md5|blake2[bs]):[0-9a-f]{6,}", re.IGNORECASE),
    re.compile(r"\[REDACTED_[A-Z]+\]"),
]

# (category, pattern, replacement) — ordered; endpoint/credential/path shapes.
_RULES: list[tuple[str, "re.Pattern[str]", str]] = [
    # --- endpoints ---
    ("endpoint", re.compile(r"\b(?:https?|wss?)://[^\s<>()]+", re.IGNORECASE), "[REDACTED_ENDPOINT]"),
    # a connection string carrying inline credentials: scheme://user:pass@host
    ("credential", re.compile(r"(?<![a-z0-9])[a-z][a-z0-9+.\-]{0,31}://[^\s:@/]{1,256}:[^\s:@/]{1,256}@[^\s]+", re.IGNORECASE), "[REDACTED_CREDENTIAL]"),
    # --- credentials / tokens ---
    ("credential", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE), "Bearer [REDACTED_CREDENTIAL]"),
    ("credential", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b"), "[REDACTED_CREDENTIAL]"),  # Stripe
    ("credential", re.compile(r"\b(?:sk|pk|ghp|gho|ghu|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE), "[REDACTED_CREDENTIAL]"),
    ("credential", re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b"), "[REDACTED_CREDENTIAL]"),  # Google API key
    ("credential", re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b"), "[REDACTED_CREDENTIAL]"),  # Google OAuth token
    ("credential", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_CREDENTIAL]"),  # AWS access key id
    ("credential", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b"), "[REDACTED_CREDENTIAL]"),  # JWT
    ("credential", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), "[REDACTED_CREDENTIAL]"),  # PEM private key
    (
        "secret_assignment",
        re.compile(
            r"\b(?:api[_ -]?key|apikey|password|passwd|pwd|secret|client[_ -]?secret|"
            r"access[_ -]?token|refresh[_ -]?token|private[_ -]?key|token)"
            r"\s*[:=]\s*[^\s,;}]+",
            re.IGNORECASE,
        ),
        "[REDACTED_SECRET]",
    ),
    # --- absolute filesystem paths ---
    ("path", re.compile(r"(?<![\w.])/(?:etc|home|root|data|var|opt|srv|tmp|Users)(?:/[^\s`]+)+"), "[REDACTED_PATH]"),
    ("path", re.compile(r"\b[A-Za-z]:\\(?:[^\s`]+\\)*[^\s`]+"), "[REDACTED_PATH]"),
]


def _scrub_allowlisted(text: str) -> str:
    """Blank out allowlisted (benign but secret-like) spans before detection."""
    for pattern in _ALLOW:
        text = pattern.sub(" ", text)
    return text


def find_secrets(value: object) -> list[str]:
    """Return the sorted, de-duplicated categories of secret/endpoint shapes in `value`."""
    text = _scrub_allowlisted(str(value))
    found = {category for category, pattern, _ in _RULES if pattern.search(text)}
    return sorted(found)


def redact(value: object) -> str:
    """Mask endpoint- and credential-shaped values while retaining semantic context."""
    text = str(value)
    for _category, pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
