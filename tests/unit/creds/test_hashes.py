# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_payloads.creds.hashes."""

from __future__ import annotations

from commonhuman_payloads.creds.hashes import (
    HASH_TYPES,
    HashType,
    identify_hash,
    is_hash,
    likely_ntlm,
)


class TestHashTypes:
    def test_hash_types_non_empty(self):
        assert len(HASH_TYPES) > 0

    def test_all_are_hashtype(self):
        for ht in HASH_TYPES:
            assert isinstance(ht, HashType)

    def test_hashcat_modes_are_int_or_none(self):
        for ht in HASH_TYPES:
            assert ht.hashcat_mode is None or isinstance(ht.hashcat_mode, int)


class TestIdentifyHash:
    def test_ntlm_32_hex(self):
        result = identify_hash("aad3b435b51404eeaad3b435b51404ee")
        names = [ht.name for ht in result]
        assert "NTLM" in names or "MD5" in names  # both match 32-hex format

    def test_sha1_40_hex(self):
        result = identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        names = [ht.name for ht in result]
        assert "SHA-1" in names

    def test_sha256_64_hex(self):
        result = identify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        names = [ht.name for ht in result]
        assert "SHA-256" in names

    def test_sha512_128_hex(self):
        result = identify_hash("a" * 128)
        names = [ht.name for ht in result]
        assert "SHA-512" in names

    def test_bcrypt(self):
        result = identify_hash("$2a$12$" + "A" * 53)
        names = [ht.name for ht in result]
        assert "bcrypt" in names

    def test_sha512crypt(self):
        result = identify_hash("$6$" + "A" * 16 + "$" + "B" * 86)
        names = [ht.name for ht in result]
        assert "SHA-512 crypt" in names

    def test_md5crypt(self):
        result = identify_hash("$1$" + "A" * 8 + "$" + "B" * 22)
        names = [ht.name for ht in result]
        assert "MD5 crypt" in names

    def test_mysql41(self):
        result = identify_hash("*" + "A" * 40)
        names = [ht.name for ht in result]
        assert "MySQL 4.1+" in names

    def test_kerberos_asrep(self):
        value = "$krb5asrep$23$user:aabbccdd$eeff0011"
        result = identify_hash(value)
        names = [ht.name for ht in result]
        assert "Kerberos AS-REP" in names

    def test_unknown_returns_empty(self):
        assert identify_hash("not-a-hash-at-all") == []

    def test_strips_whitespace(self):
        result = identify_hash("  " + "a" * 32 + "  ")
        assert len(result) > 0

    def test_multiple_matches_for_32_hex(self):
        # NTLM, LM, and MD5 all match 32-hex
        result = identify_hash("a" * 32)
        assert len(result) >= 2


class TestIsHash:
    def test_true_for_md5(self):
        assert is_hash("d41d8cd98f00b204e9800998ecf8427e")

    def test_true_for_bcrypt(self):
        assert is_hash("$2b$12$" + "A" * 53)

    def test_false_for_plain_text(self):
        assert not is_hash("hello world")

    def test_false_for_empty(self):
        assert not is_hash("")


class TestLikelyNtlm:
    def test_true_for_32_hex(self):
        assert likely_ntlm("aad3b435b51404eeaad3b435b51404ee")

    def test_true_case_insensitive(self):
        assert likely_ntlm("AAD3B435B51404EEAAD3B435B51404EE")

    def test_false_for_wrong_length(self):
        assert not likely_ntlm("aabbccdd")

    def test_false_for_non_hex(self):
        assert not likely_ntlm("z" * 32)

    def test_strips_whitespace(self):
        assert likely_ntlm("  " + "a" * 32 + "  ")
