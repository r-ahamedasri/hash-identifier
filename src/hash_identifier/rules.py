"""
Detection rules.

Design: instead of one big if/elif ladder, each rule is a small
function that inspects a sample and yields zero or more Findings.
Rules register themselves into RULES via the @rule decorator, so
adding a new hash format later means writing one function here —
nothing else in the codebase needs to change.

Every rule receives the raw, unmodified sample string and must be
fast and side-effect free.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator

from .models import Confidence, Finding

Rule = Callable[[str], Iterator[Finding]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    """Register a detector function with the global rule list."""
    RULES.append(fn)
    return fn


_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def _is_hex(s: str) -> bool:
    return bool(_HEX.fullmatch(s))


# ---------------------------------------------------------------------------
# Non-hash lookalikes — checked first so we don't waste later rules'
# confidence budget guessing at something that was never a hash.
# ---------------------------------------------------------------------------


@rule
def not_a_hash_jwt(sample: str) -> Iterator[Finding]:
    parts = sample.split(".")
    if len(parts) == 3 and all(_B64URL.fullmatch(p) for p in parts if p):
        yield Finding(
            algorithm="JWT",
            confidence=Confidence.HIGH,
            reason="three dot-separated base64url segments — a JSON Web Token, not a hash",
            is_hash=False,
        )


@rule
def not_a_hash_base64(sample: str) -> Iterator[Finding]:
    if len(sample) < 20 or _is_hex(sample):
        return
    b64_charset = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    if b64_charset.fullmatch(sample) and len(sample) % 4 == 0:
        yield Finding(
            algorithm="Base64 blob",
            confidence=Confidence.LOW,
            reason="valid base64 alphabet and padding — may be encoded data rather than a hash",
            is_hash=False,
        )


# ---------------------------------------------------------------------------
# PHC-style / crypt-style prefixed formats. High confidence: the prefix
# is a deliberate, standardized marker, so a match is rarely a coincidence.
# ---------------------------------------------------------------------------

_PREFIX_TABLE: dict[str, str] = {
    "$2a$": "bcrypt (2a)",
    "$2b$": "bcrypt (2b)",
    "$2x$": "bcrypt (2x, buggy variant)",
    "$2y$": "bcrypt (2y)",
    "$argon2id$": "Argon2id",
    "$argon2i$": "Argon2i",
    "$argon2d$": "Argon2d",
    "$apr1$": "Apache MD5-crypt (apr1)",
    "$1$": "MD5-crypt",
    "$5$": "SHA-256-crypt",
    "$6$": "SHA-512-crypt",
    "$y$": "yescrypt",
    "$7$": "scrypt",
    "pbkdf2_sha256$": "Django PBKDF2-SHA256",
    "pbkdf2_sha1$": "Django PBKDF2-SHA1",
    "{SSHA}": "Salted SHA (SSHA, LDAP)",
    "{SHA}": "SHA (LDAP, unsalted)",
    "{crypt}": "LDAP crypt wrapper",
}


@rule
def prefixed_format(sample: str) -> Iterator[Finding]:
    for prefix, label in _PREFIX_TABLE.items():
        if sample.startswith(prefix):
            yield Finding(
                algorithm=label,
                confidence=Confidence.HIGH,
                reason=f"begins with the `{prefix}` marker, unique to {label}",
            )
            return


# ---------------------------------------------------------------------------
# Shape-based formats — no clean prefix, but a distinctive overall pattern.
# ---------------------------------------------------------------------------


@rule
def mysql5(sample: str) -> Iterator[Finding]:
    if len(sample) == 41 and sample.startswith("*") and _HEX.fullmatch(sample[1:]):
        yield Finding(
            algorithm="MySQL5",
            confidence=Confidence.HIGH,
            reason="leading `*` followed by 40 hex characters — MySQL's PASSWORD() format",
        )


@rule
def net_ntlm(sample: str) -> Iterator[Finding]:
    if ":" not in sample:
        return
    fields = sample.split(":")
    hex_fields = [f for f in fields if _is_hex(f)]
    if len(fields) >= 3 and len(hex_fields) >= 2:
        long_fields = [f for f in hex_fields if len(f) in (48, 16)]
        if long_fields:
            yield Finding(
                algorithm="NetNTLMv1/v2",
                confidence=Confidence.MEDIUM,
                reason="colon-delimited hex fields matching a captured NetNTLM challenge/response",
            )


@rule
def des_crypt(sample: str) -> Iterator[Finding]:
    des_charset = re.compile(r"^[./0-9A-Za-z]{13}$")
    if des_charset.fullmatch(sample):
        yield Finding(
            algorithm="Traditional DES crypt",
            confidence=Confidence.LOW,
            reason="13 characters from the classic crypt(3) alphabet — legacy Unix DES crypt",
        )


# ---------------------------------------------------------------------------
# Plain hex digests, disambiguated only by length. These are always
# MEDIUM at best — many algorithms share the same output length.
# ---------------------------------------------------------------------------

_HEX_LENGTH_TABLE: dict[int, list[str]] = {
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
}


@rule
def hex_by_length(sample: str) -> Iterator[Finding]:
    if not _is_hex(sample):
        return
    candidates = _HEX_LENGTH_TABLE.get(len(sample))
    if not candidates:
        return
    primary, *rest = candidates
    yield Finding(
        algorithm=primary,
        confidence=Confidence.MEDIUM,
        reason=f"{len(sample)} hex characters — the most common algorithm at this length",
    )
    for other in rest:
        yield Finding(
            algorithm=other,
            confidence=Confidence.LOW,
            reason=f"{len(sample)} hex characters also matches {other}'s output size",
        )
