"""
SentinelSOC - redaction before egress.

Evidence leaves this machine and reaches a third-party API. For a security tool
that is a real objection, and "we send your auth logs to OpenRouter" is not an
answer a SOC would accept. DataSentinel made the same promise about its data
("only schema metadata and computed statistics are ever transmitted"); this is
the security-log equivalent.

The design tension: in a *security* investigation the identifiers ARE the
signal. Strip the addresses and accounts and there is nothing left to correlate.
So this pseudonymises consistently rather than deleting - 10.0.4.31 becomes
INT_IP_03 everywhere in the session, so the model can still reason "INT_IP_03
contacted EXT_IP_01 twelve times" without ever seeing the real value. The map is
reversed on the way back, so the analyst reads real addresses.

Modes (REDACT_MODE):
  off     send everything as-is
  pii     redact true personal data only - emails, phones, Aadhaar, PAN, cards.
          Operational identifiers stay readable.  [default]
  strict  also pseudonymise IP addresses, hostnames and account names.
"""

from __future__ import annotations

import os
import re
from typing import Iterable

MODES = ("off", "pii", "strict")

# -- true personal data: redacted in `pii` and `strict` ----------------------

_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # Indian identifiers - SIH context, and exactly the data that must not leave.
    ("AADHAAR", re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("PHONE", re.compile(r"\b(?:\+91[- ]?)?[6-9]\d{9}\b")),
]

# -- operational identifiers: redacted only in `strict` ----------------------

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST = re.compile(r"\b(?:web|app|db|fs|win|fw|mail|dc)-\d{2,}\b")
_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)\b\s*[=:]\s*(\S+)"
)


def _is_private(ip: str) -> bool:
    try:
        a, b, *_ = (int(p) for p in ip.split("."))
    except ValueError:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127


class Redactor:
    """
    Session-scoped, consistent, reversible pseudonymisation.

    One instance per ingestion session: the same real value always maps to the
    same token within a session, and never collides across categories.
    """

    def __init__(self, mode: str | None = None) -> None:
        mode = (mode or os.getenv("REDACT_MODE") or "pii").lower()
        self.mode = mode if mode in MODES else "pii"
        self._to_token: dict[str, str] = {}
        self._to_value: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    def _token(self, kind: str, value: str) -> str:
        existing = self._to_token.get(value)
        if existing:
            return existing
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"{kind}_{self._counters[kind]:02d}"
        self._to_token[value] = token
        self._to_value[token] = value
        return token

    # -- outbound ----------------------------------------------------------

    def redact(self, text: str) -> str:
        """Replace sensitive values with stable tokens. Safe on any string."""
        if not text or self.mode == "off":
            return text

        # Credentials go first: a secret is never worth keeping, in any mode.
        text = _SECRET.sub(lambda m: f"{m.group(1)}=<REDACTED>", text)

        for kind, pattern in _PII_PATTERNS:
            text = pattern.sub(lambda m, k=kind: self._token(k, m.group(0)), text)

        if self.mode == "strict":
            text = _IP.sub(
                lambda m: self._token(
                    "INT_IP" if _is_private(m.group(0)) else "EXT_IP", m.group(0)
                ),
                text,
            )
            text = _HOST.sub(lambda m: self._token("HOST", m.group(0)), text)
        return text

    def redact_all(self, texts: Iterable[str]) -> list[str]:
        return [self.redact(t) for t in texts]

    def redact_event(self, event: dict) -> dict:
        """Redact the free-text and identifier fields of an event row."""
        if self.mode == "off":
            return event
        out = dict(event)
        for field in ("raw", "template"):
            if out.get(field):
                out[field] = self.redact(str(out[field]))
        if self.mode == "strict":
            for field in ("host", "user", "src_ip", "dst_ip"):
                if out.get(field):
                    out[field] = self.redact(str(out[field]))
        return out

    # -- inbound -----------------------------------------------------------

    def restore(self, text: str) -> str:
        """Put the real values back, so the analyst never sees a token."""
        if not text or not self._to_value:
            return text
        for token, value in sorted(self._to_value.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(token, value)
        return text

    def restore_obj(self, obj):
        """Walk a parsed agent result and restore every string in it."""
        if isinstance(obj, str):
            return self.restore(obj)
        if isinstance(obj, list):
            return [self.restore_obj(o) for o in obj]
        if isinstance(obj, dict):
            return {k: self.restore_obj(v) for k, v in obj.items()}
        return obj

    def restore_model(self, model):
        """Restore inside a Pydantic model, returning a new validated instance."""
        if model is None:
            return None
        restored = self.restore_obj(model.model_dump(mode="json"))
        return type(model).model_validate(restored)

    # -- reporting ---------------------------------------------------------

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for token in self._to_value:
            kind = token.rsplit("_", 1)[0]
            counts[kind] = counts.get(kind, 0) + 1
        return {
            "mode": self.mode,
            "values_pseudonymised": len(self._to_value),
            "by_category": counts,
        }
