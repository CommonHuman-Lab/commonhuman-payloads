# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for sqli.advanced payload getters."""

import pytest

from commonhuman_payloads.sqli.advanced import (
    DB_CONTENTS_PAYLOADS,
    STACKED_PAYLOADS,
    DIOS_PAYLOADS,
    LFI_PAYLOADS,
    PRIVESC_PAYLOADS,
    ENUM_PAYLOADS,
    get_db_contents_payloads,
    get_stacked_payloads,
    get_dios_payloads,
    get_lfi_payloads,
    get_privesc_payloads,
    get_enum_payloads,
)

_CONTENT_DBMS = ["mysql", "mariadb", "mssql", "postgres", "sqlite"]
_CONTENT_TARGETS = ["tables", "columns"]
_ENUM_CATEGORIES = ["version", "current_user", "hostname", "current_database",
                    "list_databases", "list_users", "password_hashes",
                    "find_tables_by_column", "conditional", "nth_row"]


class TestDbContentsPayloads:
    @pytest.mark.parametrize("dbms", _CONTENT_DBMS)
    def test_tables_non_empty(self, dbms):
        result = get_db_contents_payloads(dbms, "tables")
        assert len(result) > 0

    @pytest.mark.parametrize("dbms", _CONTENT_DBMS)
    def test_columns_non_empty(self, dbms):
        result = get_db_contents_payloads(dbms, "columns")
        assert len(result) > 0

    def test_unknown_dbms_returns_empty(self):
        result = get_db_contents_payloads("__unknown__", "tables")
        assert isinstance(result, list)

    def test_unknown_target_returns_empty(self):
        result = get_db_contents_payloads("mysql", "nonexistent_target")
        assert isinstance(result, list)

    @pytest.mark.parametrize("dbms", _CONTENT_DBMS)
    def test_all_strings(self, dbms):
        for target in _CONTENT_TARGETS:
            for p in get_db_contents_payloads(dbms, target):
                assert isinstance(p, str)


class TestStackedPayloads:
    def test_non_empty(self):
        assert len(STACKED_PAYLOADS) > 0

    def test_risk1_returns_list(self):
        result = get_stacked_payloads("mysql", risk=1)
        assert isinstance(result, list)

    def test_risk3_adds_destructive(self):
        r1 = get_stacked_payloads("mysql", risk=1)
        r3 = get_stacked_payloads("mysql", risk=3)
        assert len(r3) >= len(r1)

    def test_unknown_dbms_returns_generic(self):
        result = get_stacked_payloads("__unknown__", risk=1)
        assert isinstance(result, list)

    def test_all_strings(self):
        for p in get_stacked_payloads("mssql", risk=3):
            assert isinstance(p, str)


class TestDiosPayloads:
    def test_non_empty(self):
        result = get_dios_payloads()
        assert len(result) > 0

    def test_all_strings(self):
        for p in get_dios_payloads():
            assert isinstance(p, str)


class TestLfiPayloads:
    def test_non_empty(self):
        result = get_lfi_payloads()
        assert len(result) > 0

    def test_all_strings(self):
        for p in get_lfi_payloads():
            assert isinstance(p, str)


class TestPrivescPayloads:
    def test_risk1_non_empty(self):
        result = get_privesc_payloads(risk=1)
        assert len(result) > 0

    def test_risk3_includes_risk1(self):
        r1 = get_privesc_payloads(risk=1)
        r3 = get_privesc_payloads(risk=3)
        assert len(r3) >= len(r1)

    def test_all_strings(self):
        for p in get_privesc_payloads(risk=3):
            assert isinstance(p, str)


class TestEnumPayloads:
    @pytest.mark.parametrize("cat", _ENUM_CATEGORIES)
    def test_known_category_non_empty(self, cat):
        result = get_enum_payloads(cat)
        assert len(result) > 0, f"category {cat!r} returned empty"

    @pytest.mark.parametrize("cat", _ENUM_CATEGORIES)
    def test_all_strings(self, cat):
        for p in get_enum_payloads(cat):
            assert isinstance(p, str)

    def test_unknown_category_returns_empty(self):
        result = get_enum_payloads("__no_such_category__")
        assert isinstance(result, list)
        assert len(result) == 0
