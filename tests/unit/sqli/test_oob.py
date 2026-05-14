# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for sqli.oob payloads."""

import pytest

from commonhuman_payloads.sqli.oob import (
    OOB_PAYLOADS,
    get_oob_payloads,
)

_KNOWN_DBMS = ["mysql", "mariadb", "mssql", "postgres", "oracle", "auto"]
# SQLite has no native OOB mechanism — it is intentionally absent
_EMPTY_DBMS = ["sqlite"]
_CALLBACK = "http://callback.example.com"


class TestOobPayloads:
    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_has_key(self, dbms):
        assert dbms in OOB_PAYLOADS

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_non_empty(self, dbms):
        assert len(OOB_PAYLOADS[dbms]) > 0

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_all_strings(self, dbms):
        for p in OOB_PAYLOADS[dbms]:
            assert isinstance(p, str)

    def test_sqlite_oob_is_empty(self):
        # SQLite has no native DNS/HTTP OOB mechanism
        assert OOB_PAYLOADS["sqlite"] == []


class TestGetOobPayloads:
    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_callback_substituted(self, dbms):
        result = get_oob_payloads(dbms, _CALLBACK)
        for p in result:
            assert "{callback}" not in p, f"dbms={dbms}: unsubstituted callback in {p!r}"

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_callback_present(self, dbms):
        result = get_oob_payloads(dbms, _CALLBACK)
        assert any(_CALLBACK in p or "example.com" in p for p in result), (
            f"dbms={dbms}: callback not found in any payload"
        )

    def test_unknown_dbms_falls_back_to_auto(self):
        result = get_oob_payloads("__unknown__", _CALLBACK)
        auto = get_oob_payloads("auto", _CALLBACK)
        assert result == auto

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_returns_list(self, dbms):
        result = get_oob_payloads(dbms, _CALLBACK)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_sqlite_returns_empty_list(self):
        result = get_oob_payloads("sqlite", _CALLBACK)
        assert result == []
