# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for sqli.union probes and helpers."""

import pytest

from commonhuman_payloads.sqli.union import (
    BREACH_MARKER_PREFIX,
    make_marker,
    CONCAT_PAYLOADS,
    SUBSTRING_PROBES,
    get_concat_payloads,
    get_substring_probes,
    make_substring_payload,
    order_by_probes,
    union_null_probes,
)

_KNOWN_DBMS = ["mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle", "auto"]
_ORDER_BY_VARIANTS = 16   # variants per column position
_UNION_VARIANTS    = 16   # probe forms per (position × variant)
_UNION_COL_VARIANTS = 4   # column variants per position (str, cast, int, char)


class TestBreachMarker:
    def test_prefix_constant(self):
        assert BREACH_MARKER_PREFIX == "BreachSQL_"

    def test_make_marker_uses_prefix(self):
        m = make_marker()
        assert m.startswith(BREACH_MARKER_PREFIX)

    def test_make_marker_randomness(self):
        markers = {make_marker() for _ in range(20)}
        assert len(markers) > 1


class TestConcatPayloads:
    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_has_key_or_falls_back(self, dbms):
        result = get_concat_payloads(dbms)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_unknown_dbms_falls_back_to_auto(self):
        result = get_concat_payloads("__unknown__")
        auto = get_concat_payloads("auto")
        assert result == auto


class TestSubstringProbes:
    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_has_key_or_falls_back(self, dbms):
        result = get_substring_probes(dbms)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_unknown_falls_back_to_auto(self):
        result = get_substring_probes("__unknown__")
        auto = get_substring_probes("auto")
        assert result == auto


class TestMakeSubstringPayload:
    def test_mysql(self):
        p = make_substring_payload("mysql", "user()", 1, "r")
        assert "SUBSTRING" in p
        assert "114" in p  # ord('r') == 114

    def test_sqlite_uses_substr(self):
        p = make_substring_payload("sqlite", "sqlite_version()", 1, "3")
        assert "SUBSTR" in p

    def test_oracle_uses_substr(self):
        p = make_substring_payload("oracle", "user", 1, "S")
        assert "SUBSTR" in p

    def test_position_appears_in_payload(self):
        p = make_substring_payload("mysql", "user()", 7, "x")
        assert ",7," in p

    def test_char_ord_appears_in_payload(self):
        p = make_substring_payload("mysql", "user()", 1, "A")
        assert str(ord("A")) in p


class TestOrderByProbes:
    def test_default_count(self):
        probes = order_by_probes(max_cols=10)
        assert len(probes) == 10 * _ORDER_BY_VARIANTS

    def test_count_at_max_cols_20(self):
        probes = order_by_probes(max_cols=20)
        assert len(probes) == 20 * _ORDER_BY_VARIANTS

    def test_contains_order_by_1(self):
        probes = order_by_probes(max_cols=5)
        assert any("ORDER BY 1" in p or "order" in p.lower() for p in probes)

    def test_all_strings(self):
        for p in order_by_probes(max_cols=3):
            assert isinstance(p, str)


class TestUnionNullProbes:
    def test_count(self):
        probes = union_null_probes(col_count=3, marker="M")
        assert len(probes) == 3 * _UNION_COL_VARIANTS * _UNION_VARIANTS

    def test_count_single_col(self):
        probes = union_null_probes(col_count=1, marker="M")
        assert len(probes) == 1 * _UNION_COL_VARIANTS * _UNION_VARIANTS

    def test_marker_present_in_non_char_probes(self):
        probes = union_null_probes(col_count=2, marker="NEEDLE")
        assert all("NEEDLE" in p or "char(" in p for p in probes)

    def test_char_variant_encodes_marker(self):
        probes = union_null_probes(col_count=1, marker="AB")
        char_probes = [p for p in probes if "char(" in p]
        assert len(char_probes) > 0
        # ord('A')=65, ord('B')=66
        assert any("65" in p and "66" in p for p in char_probes)

    def test_standard_probes_contain_union_select(self):
        probes = union_null_probes(col_count=2, marker="M")
        standard = [p for p in probes if "UNION SELECT" in p or "union" in p.lower()]
        assert len(standard) > 0

    def test_null_count_in_standard_probes(self):
        probes = union_null_probes(col_count=4, marker="M")
        standard = [p for p in probes if "UNION SELECT" in p]
        for p in standard:
            cols_part = p.split("UNION SELECT")[1]
            cols_part = cols_part.split("-- -")[0].split("#")[0]
            assert cols_part.count(",") == 3  # 4 columns = 3 commas

    def test_all_strings(self):
        for p in union_null_probes(col_count=2, marker="M"):
            assert isinstance(p, str)
