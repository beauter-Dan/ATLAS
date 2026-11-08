"""Strip secrets and personal data before anything is sent to an AI provider."""
import re

PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-=]{12,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|authorization|cookie)\b\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_ID]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED_NUMBER]"),
    (re.compile(r"\b[a-fA-F0-9]{32,}\b"), "[REDACTED_HEX]"),
]


def redact(text: str) -> str:
    for rx, rep in PATTERNS:
        text = rx.sub(rep, text)
    return text
