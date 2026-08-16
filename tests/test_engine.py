"""
Tests for hash_identifier's detection engine.

Organized by hash family so a failing test immediately tells you
which detector broke, not just "something in scan() is wrong."
"""

from __future__ import annotations

from hash_identifier import scan
from hash_identifier.models import Confidence


def _algorithms(sample: str) -> list[str]:
    return [f.algorithm for f in scan(sample).findings]


def _top(sample: str) -> str | None:
    report = scan(sample)
    return report.best.algorithm if report.best else None


class TestHexLengthDetection:
    def test_md5_length(self) -> None:
        assert _top("5f4dcc3b5aa765d61d8327deb882cf99") == "MD5"

    def test_sha1_length(self) -> None:
        assert _top("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") == "SHA-1"

    def test_sha256_length(self) -> None:
        sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _top(sample) == "SHA-256"

    def test_sha512_length(self) -> None:
        sample = "a" * 128
        assert _top(sample) == "SHA-512"

    def test_ambiguous_length_lists_all_candidates(self) -> None:
        sample = "b" * 32
        algos = _algorithms(sample)
        assert "MD5" in algos and "NTLM" in algos and "MD4" in algos

    def test_non_hex_string_has_no_length_candidates(self) -> None:
        assert "MD5" not in _algorithms("z" * 32)


class TestPrefixedFormats:
    def test_bcrypt_2b(self) -> None:
        sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK"
        assert _top(sample) == "bcrypt (2b)"

    def test_argon2id(self) -> None:
        sample = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        assert _top(sample) == "Argon2id"

    def test_apache_apr1(self) -> None:
        assert _top("$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/") == "Apache MD5-crypt (apr1)"

    def test_django_pbkdf2(self) -> None:
        sample = "pbkdf2_sha256$260000$salt123$hashvalueherebase64"
        assert _top(sample) == "Django PBKDF2-SHA256"

    def test_ssha(self) -> None:
        assert _top("{SSHA}dGVzdHNhbHQxMjM0NTY3ODkw") == "Salted SHA (SSHA, LDAP)"

    def test_prefix_beats_length_guess(self) -> None:
        # bcrypt strings are long and mixed-charset; the prefix rule
        # must win outright rather than being buried under hex guesses.
        sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK"
        report = scan(sample)
        assert report.best is not None
        assert report.best.confidence == Confidence.HIGH


class TestShapeBasedFormats:
    def test_mysql5(self) -> None:
        sample = "*A4B6157319038724E3560894F7F932C8886EBFCF"
        assert _top(sample) == "MySQL5"

    def test_des_crypt(self) -> None:
        assert "Traditional DES crypt" in _algorithms("abcdefghijklm")

    def test_net_ntlm_shape(self) -> None:
        challenge = "a" * 16
        response = "b" * 48
        sample = f"user:1001:{challenge}:{response}:extra"
        assert "NetNTLMv1/v2" in _algorithms(sample)


class TestNonHashDetection:
    def test_jwt_flagged_as_not_a_hash(self) -> None:
        sample = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        report = scan(sample)
        assert report.best is not None
        assert report.best.algorithm == "JWT"
        assert report.best.is_hash is False

    def test_empty_string_yields_no_findings(self) -> None:
        assert scan("").is_empty

    def test_whitespace_is_trimmed_before_matching(self) -> None:
        padded = "  5f4dcc3b5aa765d61d8327deb882cf99  "
        assert _top(padded) == "MD5"


class TestReportOrdering:
    def test_findings_sorted_high_to_low(self) -> None:
        report = scan("c" * 32)  # ambiguous hex -> multiple confidences
        confidences = [f.confidence for f in report.findings]
        assert confidences == sorted(confidences, reverse=True)

    def test_unrecognized_input_is_empty_report(self) -> None:
        report = scan("not-a-hash-at-all!!")
        assert report.is_empty
        assert report.best is None
