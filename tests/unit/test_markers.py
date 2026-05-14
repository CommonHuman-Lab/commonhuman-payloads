# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
import re

import pytest

from commonhuman_payloads.markers import make_marker, is_reflected, _DEFAULT_PREFIX


class TestMakeMarker:
    def test_returns_string(self):
        assert isinstance(make_marker(), str)

    def test_default_prefix(self):
        m = make_marker()
        assert m.startswith(_DEFAULT_PREFIX)

    def test_custom_prefix(self):
        m = make_marker(prefix="StingXSS_")
        assert m.startswith("StingXSS_")

    def test_suffix_length_default(self):
        m = make_marker()
        suffix = m[len(_DEFAULT_PREFIX):]
        assert len(suffix) == 6

    def test_suffix_length_custom(self):
        m = make_marker(length=12)
        suffix = m[len(_DEFAULT_PREFIX):]
        assert len(suffix) == 12

    def test_suffix_is_alphanumeric(self):
        m = make_marker()
        suffix = m[len(_DEFAULT_PREFIX):]
        assert re.match(r"^[a-z0-9]+$", suffix)

    def test_randomness(self):
        markers = {make_marker() for _ in range(20)}
        assert len(markers) > 1, "make_marker should not always return the same value"

    def test_breach_prefix(self):
        m = make_marker(prefix="BreachSQL_")
        assert m.startswith("BreachSQL_")
        assert len(m) == len("BreachSQL_") + 6


class TestIsReflected:
    def test_true_when_present(self):
        assert is_reflected("StingXSS_abc", "before StingXSS_abc after") is True

    def test_false_when_absent(self):
        assert is_reflected("StingXSS_abc", "nothing here") is False

    def test_case_sensitive(self):
        assert is_reflected("MARKER", "marker") is False

    def test_empty_body(self):
        assert is_reflected("MARKER", "") is False

    def test_marker_at_start(self):
        assert is_reflected("M", "MXXX") is True

    def test_marker_at_end(self):
        assert is_reflected("M", "XXXM") is True

    def test_empty_marker_always_reflected(self):
        assert is_reflected("", "anything") is True
