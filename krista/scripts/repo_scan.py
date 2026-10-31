"""High-precision secret and personal-data shapes for scanning tracked repository files.

`scripts/redaction.find_secrets` is tuned to over-detect (it must never miss a secret in an
output); applied to the repository's own prose it flags words like "bearer" and "token: str".
This scanner is the opposite trade: only shapes that are unmistakably a live credential or a
Hungarian personal identifier, so a hit in a tracked file is a real finding, not noise.
"""

from __future__ import annotations

import re

SECRET_SHAPES: dict[str, re.Pattern[str]] = {
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "github-fine-grained-token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    "api-secret-key": re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "credentialed-url": re.compile(r"\b[a-z][a-z0-9+.-]{1,30}://[^\s:@/]{1,64}:[^\s:@/]{1,64}@[^\s/]+"),
    "literal-secret-assignment": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[=:]\s*["']?(?![A-Za-z_]+\()[A-Za-z0-9/+_\-]{16,}"""
    ),
}

#: RFC 2606 / 6761 reserved names and the platform's own no-reply addresses are not personal data.
_SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "localhost", "users.noreply.github.com")
_SAFE_EMAIL_SUFFIXES = (".invalid", ".test", ".example", ".localhost")

PII_SHAPES: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b(?![Nn]o-?[Rr]eply@)[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
    "hu-phone": re.compile(r"(?<![\w.])(?:\+36|0036|06)[ -]?(?:1|[2-9]\d)[ -]?\d{3}[ -]?\d{3,4}(?![0-9A-Za-z])"),
    "hu-taj": re.compile(r"(?<![\d-])\d{3} \d{3} \d{3}(?![\d-])"),
    "hu-iban": re.compile(r"\bHU\d{2}(?: ?\d{4}){6}\b"),
    "hu-bank-account": re.compile(r"(?<![\d-])\d{8}-\d{8}(?:-\d{8})?(?![\d-])"),
    "hu-tax-id": re.compile(r"(?<![\d-])\d{8}-\d-\d{2}(?![\d-])"),
}


def _email_is_safe(domain: str) -> bool:
    domain = domain.lower()
    return domain in _SAFE_EMAIL_DOMAINS or domain.endswith(_SAFE_EMAIL_SUFFIXES) or domain.endswith(tuple("." + d for d in _SAFE_EMAIL_DOMAINS))


def scan_text(text: str) -> list[tuple[int, str]]:
    """Return (line number, finding kind) for every secret or personal-data shape in `text`."""
    findings: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        for kind, pattern in SECRET_SHAPES.items():
            if pattern.search(line):
                findings.append((number, kind))
        for kind, pattern in PII_SHAPES.items():
            for match in pattern.finditer(line):
                if kind == "email" and _email_is_safe(match.group(1)):
                    continue
                findings.append((number, kind))
    return findings
