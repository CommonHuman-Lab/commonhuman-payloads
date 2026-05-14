# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for waf.signatures data validity."""

import re

import pytest

from commonhuman_payloads.waf.signatures import (
    WafSignature,
    SIGNATURES,
    GENERIC_BLOCK_BODIES,
)
from commonhuman_payloads.encoders.transforms import ALL_EVASIONS

_KNOWN_WAFS = [
    "Cloudflare", "Akamai", "Imperva", "AWS WAF", "ModSecurity",
    "Sucuri", "F5 BIG-IP ASM", "Barracuda", "Wordfence", "Fortinet FortiWeb",
]


class TestSignatures:
    def test_non_empty(self):
        assert len(SIGNATURES) > 0

    def test_ten_signatures(self):
        assert len(SIGNATURES) == 10

    def test_all_are_wafsignature(self):
        for sig in SIGNATURES:
            assert isinstance(sig, WafSignature)

    @pytest.mark.parametrize("name", _KNOWN_WAFS)
    def test_known_waf_present(self, name):
        names = [s.name for s in SIGNATURES]
        assert name in names, f"WAF {name!r} not found in SIGNATURES"

    def test_all_have_names(self):
        for sig in SIGNATURES:
            assert isinstance(sig.name, str) and sig.name.strip()

    def test_all_have_evasions(self):
        for sig in SIGNATURES:
            assert len(sig.evasions) > 0, f"{sig.name}: evasions list is empty"

    def test_evasions_are_known_constants(self):
        for sig in SIGNATURES:
            for e in sig.evasions:
                assert e in ALL_EVASIONS, (
                    f"{sig.name}: evasion {e!r} not in ALL_EVASIONS"
                )

    def test_header_clues_are_two_tuples(self):
        for sig in SIGNATURES:
            for clue in sig.header_clues:
                assert len(clue) == 2, f"{sig.name}: header_clue {clue!r} is not a 2-tuple"

    def test_header_patterns_are_valid_regex(self):
        for sig in SIGNATURES:
            for hdr, pattern in sig.header_clues:
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    pytest.fail(f"{sig.name}: header pattern {pattern!r} is invalid: {e}")

    def test_body_patterns_are_valid_regex(self):
        for sig in SIGNATURES:
            for pattern in sig.body_clues:
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    pytest.fail(f"{sig.name}: body pattern {pattern!r} is invalid: {e}")

    def test_status_codes_are_ints(self):
        for sig in SIGNATURES:
            for code in sig.status_codes:
                assert isinstance(code, int)
                assert 100 <= code <= 599


class TestGenericBlockBodies:
    def test_non_empty(self):
        assert len(GENERIC_BLOCK_BODIES) > 0

    def test_all_strings(self):
        for p in GENERIC_BLOCK_BODIES:
            assert isinstance(p, str)

    def test_all_valid_regex(self):
        for pattern in GENERIC_BLOCK_BODIES:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                pytest.fail(f"GENERIC_BLOCK_BODIES pattern {pattern!r} is invalid: {e}")

    def test_at_least_8_patterns(self):
        assert len(GENERIC_BLOCK_BODIES) >= 8
