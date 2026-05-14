# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for xss public API: get_basic_payloads, get_payloads_for_context."""

import pytest

from commonhuman_payloads.xss import (
    get_basic_payloads,
    get_payloads_for_context,
    HTML_BODY,
    _CONTEXT_LISTS,
)

_ALL_CONTEXTS = list(_CONTEXT_LISTS.keys())


class TestGetBasicPayloads:
    def test_returns_list(self):
        assert isinstance(get_basic_payloads(), list)

    def test_non_empty(self):
        assert len(get_basic_payloads()) > 0

    def test_marker_substituted_default(self):
        # Default marker IS the literal string "{marker}", so placeholders stay intact.
        # Calling with an explicit value verifies substitution actually works.
        payloads = get_basic_payloads(marker="ACTUAL_MARKER")
        assert not any("{marker}" in p for p in payloads)

    def test_custom_marker_substituted(self):
        marker = "StingXSS_abc123"
        payloads = get_basic_payloads(marker=marker)
        assert all(marker in p or "{marker}" not in p for p in payloads)
        # at least some payloads should contain the marker
        assert any(marker in p for p in payloads)

    def test_no_raw_placeholder_remains(self):
        payloads = get_basic_payloads(marker="TEST")
        assert not any("{marker}" in p for p in payloads)

    def test_covers_multiple_contexts(self):
        # basic set draws from html_body, attr_*, script_string_d — at minimum 3 contexts
        payloads = get_basic_payloads(marker="M")
        assert len(payloads) >= 5


class TestGetPayloadsForContext:
    @pytest.mark.parametrize("ctx", _ALL_CONTEXTS)
    def test_known_context_non_empty(self, ctx):
        payloads = get_payloads_for_context(ctx, marker="M")
        assert len(payloads) > 0, f"context {ctx!r} returned empty list"

    @pytest.mark.parametrize("ctx", _ALL_CONTEXTS)
    def test_no_placeholder_remains(self, ctx):
        payloads = get_payloads_for_context(ctx, marker="TESTMARKER")
        for p in payloads:
            assert "{marker}" not in p, f"context {ctx!r}: unsubstituted placeholder in {p!r}"

    @pytest.mark.parametrize("ctx", _ALL_CONTEXTS)
    def test_marker_present(self, ctx):
        payloads = get_payloads_for_context(ctx, marker="UNIQUE_NEEDLE")
        # at least one payload should contain the marker (unless no {marker} placeholder exists)
        raw = _CONTEXT_LISTS[ctx]
        if any("{marker}" in p for p in raw):
            assert any("UNIQUE_NEEDLE" in p for p in payloads), (
                f"context {ctx!r}: marker not found in substituted payloads"
            )

    def test_unknown_context_falls_back_to_html_body(self):
        payloads = get_payloads_for_context("__does_not_exist__", marker="M")
        expected = [p.replace("{marker}", "M") for p in HTML_BODY]
        assert payloads == expected

    def test_returns_list_of_strings(self):
        payloads = get_payloads_for_context("html_body", marker="M")
        assert all(isinstance(p, str) for p in payloads)
