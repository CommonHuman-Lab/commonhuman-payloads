# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for sqli.boolean payloads."""

import pytest

from commonhuman_payloads.sqli.boolean import (
    BOOLEAN_PAIRS,
    BOOLEAN_PAIRS_RISK2,
    get_boolean_pairs,
)


class TestBooleanPairs:
    def test_non_empty(self):
        assert len(BOOLEAN_PAIRS) > 0

    def test_all_are_two_tuples(self):
        for pair in BOOLEAN_PAIRS:
            assert len(pair) == 2, f"Expected 2-tuple, got {pair!r}"

    def test_all_strings(self):
        for true_p, false_p in BOOLEAN_PAIRS:
            assert isinstance(true_p, str)
            assert isinstance(false_p, str)

    def test_true_false_differ(self):
        for true_p, false_p in BOOLEAN_PAIRS:
            assert true_p != false_p, f"true and false payloads should differ: {true_p!r}"

    def test_risk2_non_empty(self):
        assert len(BOOLEAN_PAIRS_RISK2) > 0

    def test_risk2_all_two_tuples(self):
        for pair in BOOLEAN_PAIRS_RISK2:
            assert len(pair) == 2


class TestGetBooleanPairs:
    def test_risk1_returns_list_of_tuples(self):
        result = get_boolean_pairs(risk=1)
        assert isinstance(result, list)
        assert all(len(p) == 2 for p in result)

    def test_risk1_excludes_risk2_payloads(self):
        r1 = get_boolean_pairs(risk=1)
        r2 = get_boolean_pairs(risk=2)
        assert len(r2) > len(r1)

    def test_risk2_includes_risk1_payloads(self):
        r1 = get_boolean_pairs(risk=1)
        r2 = get_boolean_pairs(risk=2)
        for pair in r1:
            assert pair in r2

    def test_risk3_same_as_risk2(self):
        r2 = get_boolean_pairs(risk=2)
        r3 = get_boolean_pairs(risk=3)
        assert r2 == r3

    def test_default_risk_is_1(self):
        default = get_boolean_pairs()
        explicit = get_boolean_pairs(risk=1)
        assert default == explicit
