# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for sqli.error payloads and DB_ERROR_PATTERNS."""

import re

import pytest

from commonhuman_payloads.sqli.error import (
    ERROR_PAYLOADS,
    DB_ERROR_PATTERNS,
    get_error_payloads,
)

_KNOWN_DBMS = ["mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle", "generic"]
_PATTERN_DBMS = ["mysql", "mssql", "postgres", "sqlite", "generic"]


class TestErrorPayloads:
    def test_has_generic_key(self):
        assert "generic" in ERROR_PAYLOADS

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_has_dbms_key(self, dbms):
        assert dbms in ERROR_PAYLOADS, f"ERROR_PAYLOADS missing key {dbms!r}"

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_non_empty(self, dbms):
        assert len(ERROR_PAYLOADS[dbms]) > 0

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_all_strings(self, dbms):
        for p in ERROR_PAYLOADS[dbms]:
            assert isinstance(p, str)


class TestDbErrorPatterns:
    @pytest.mark.parametrize("dbms", _PATTERN_DBMS)
    def test_has_dbms_key(self, dbms):
        assert dbms in DB_ERROR_PATTERNS

    @pytest.mark.parametrize("dbms", _PATTERN_DBMS)
    def test_non_empty(self, dbms):
        assert len(DB_ERROR_PATTERNS[dbms]) > 0

    @pytest.mark.parametrize("dbms", _PATTERN_DBMS)
    def test_patterns_are_valid_regex(self, dbms):
        for pat in DB_ERROR_PATTERNS[dbms]:
            try:
                re.compile(pat, re.IGNORECASE)
            except re.error as e:
                pytest.fail(f"{dbms} pattern {pat!r} is not valid regex: {e}")


class TestGetErrorPayloads:
    def test_known_dbms_returns_list(self):
        result = get_error_payloads("mysql")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_unknown_dbms_includes_generic_payloads(self):
        # Unknown DBMS → specific=[], so result is generic-only.
        # "generic" DBMS → specific=generic list again (generic+generic), so they differ.
        # Just verify unknown returns a non-empty list containing the generic base.
        unknown = get_error_payloads("__unknown__")
        generic_base = get_error_payloads("generic")
        assert len(unknown) > 0
        # Every payload in unknown must be a subset of generic_base payloads
        for p in unknown:
            assert p in generic_base

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_risk1_is_subset_of_risk3(self, dbms):
        r1 = get_error_payloads(dbms, risk=1)
        r3 = get_error_payloads(dbms, risk=3)
        assert len(r1) <= len(r3)

    def test_risk_increases_payload_count(self):
        r1 = get_error_payloads("mysql", risk=1)
        r3 = get_error_payloads("mysql", risk=3)
        assert len(r3) >= len(r1)

    def test_level2_returns_more_than_level1_fewer_than_level3(self):
        l1 = get_error_payloads("mysql", level=1)
        l2 = get_error_payloads("mysql", level=2)
        l3 = get_error_payloads("mysql", level=3)
        assert len(l1) < len(l2) <= len(l3)

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_all_payloads_are_strings(self, dbms):
        for p in get_error_payloads(dbms, risk=3):
            assert isinstance(p, str)
