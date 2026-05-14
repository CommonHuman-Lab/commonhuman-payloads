# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for sqli.time_based payloads."""

import pytest

from commonhuman_payloads.sqli.time_based import (
    TIME_PAYLOADS,
    get_time_payloads,
)

_KNOWN_DBMS = ["auto", "mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle"]
_PLACEHOLDERS = ["{delay}", "{bench}", "{blob_size}", "{sqlite_bench}"]


class TestTimePayloads:
    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_has_key(self, dbms):
        assert dbms in TIME_PAYLOADS

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_non_empty(self, dbms):
        assert len(TIME_PAYLOADS[dbms]) > 0

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_all_strings(self, dbms):
        for p in TIME_PAYLOADS[dbms]:
            assert isinstance(p, str)


class TestGetTimePayloads:
    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_returns_list(self, dbms):
        result = get_time_payloads(dbms, delay=3)
        assert isinstance(result, list)
        assert len(result) > 0

    @pytest.mark.parametrize("dbms", _KNOWN_DBMS)
    def test_no_unsubstituted_placeholders(self, dbms):
        result = get_time_payloads(dbms, delay=3)
        for p in result:
            for placeholder in _PLACEHOLDERS:
                assert placeholder not in p, (
                    f"dbms={dbms!r}: unsubstituted {placeholder!r} in {p!r}"
                )

    def test_delay_value_appears_in_mysql_payload(self):
        result = get_time_payloads("mysql", delay=5)
        assert any("5" in p for p in result)

    def test_sqlite_bench_scales_with_delay(self):
        r3 = get_time_payloads("sqlite", delay=3)
        r6 = get_time_payloads("sqlite", delay=6)
        # Higher delay → larger bench number in the payload string
        bench_3 = [p for p in r3 if "x<" in p]
        bench_6 = [p for p in r6 if "x<" in p]
        if bench_3 and bench_6:
            # extract number after x<
            import re
            n3 = int(re.search(r"x<(\d+)", bench_3[0]).group(1))
            n6 = int(re.search(r"x<(\d+)", bench_6[0]).group(1))
            assert n6 > n3

    def test_unknown_dbms_falls_back_to_auto(self):
        result = get_time_payloads("__unknown__", delay=1)
        auto = get_time_payloads("auto", delay=1)
        assert result == auto

    @pytest.mark.parametrize("delay", [1, 3, 5, 10])
    def test_all_payloads_are_strings(self, delay):
        for dbms in _KNOWN_DBMS:
            for p in get_time_payloads(dbms, delay=delay):
                assert isinstance(p, str)
