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
    EXTRACTION_TARGETS,
    get_db_contents_payloads,
    get_stacked_payloads,
    get_dios_payloads,
    get_lfi_payloads,
    get_privesc_payloads,
    get_enum_payloads,
    get_extraction_targets,
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


_EXTRACTION_DBMS = ["mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle"]


class TestExtractionTargets:
    """get_extraction_targets() returns (label, sql_expr) tuples for blind extraction."""

    @pytest.mark.parametrize("dbms", _EXTRACTION_DBMS)
    def test_known_dbms_returns_targets(self, dbms):
        result = get_extraction_targets(dbms)
        assert isinstance(result, list)
        assert len(result) > 0, f"no targets for {dbms!r}"

    @pytest.mark.parametrize("dbms", _EXTRACTION_DBMS)
    def test_each_item_is_label_expr_tuple(self, dbms):
        for item in get_extraction_targets(dbms):
            assert isinstance(item, tuple) and len(item) == 2, (
                f"expected (label, expr) tuple, got {item!r}"
            )
            label, expr = item
            assert isinstance(label, str) and label
            assert isinstance(expr, str) and expr

    @pytest.mark.parametrize("dbms", _EXTRACTION_DBMS)
    def test_exprs_are_standalone_sql_not_injection_payloads(self, dbms):
        """Expressions must be bare SQL (no leading quote or injection prefix)."""
        for _, expr in get_extraction_targets(dbms):
            assert not expr.startswith("'"), (
                f"{dbms}: expr must not start with quote: {expr!r}"
            )
            assert "--" not in expr, (
                f"{dbms}: expr must not contain comment terminator: {expr!r}"
            )

    def test_unknown_dbms_falls_back_to_generic(self):
        result = get_extraction_targets("__unknown__")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_none_dbms_falls_back_to_generic(self):
        result = get_extraction_targets(None)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_empty_string_dbms_falls_back_to_generic(self):
        result = get_extraction_targets("")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_generic_fallback_has_version(self):
        result = get_extraction_targets("__unknown__")
        labels = [label for label, _ in result]
        assert "version" in labels

    def test_mysql_covers_expected_targets(self):
        labels = [label for label, _ in get_extraction_targets("mysql")]
        assert "version" in labels
        assert "current_user" in labels
        assert "current_database" in labels
        assert "tables" in labels

    def test_dict_covers_all_declared_dbms(self):
        for dbms in _EXTRACTION_DBMS:
            assert dbms in EXTRACTION_TARGETS, f"{dbms!r} missing from EXTRACTION_TARGETS"

    def test_case_insensitive_lookup(self):
        upper = get_extraction_targets("MYSQL")
        lower = get_extraction_targets("mysql")
        assert upper == lower
