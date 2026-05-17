# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_payloads.waf.payloads."""

from __future__ import annotations

import pytest

from commonhuman_payloads.waf.payloads import (
    WAF_EXTRA_PAYLOADS,
    get_waf_payloads,
)


# ---------------------------------------------------------------------------
# WAF_EXTRA_PAYLOADS table
# ---------------------------------------------------------------------------

class TestWafExtraPayloads:
    def test_is_dict(self):
        assert isinstance(WAF_EXTRA_PAYLOADS, dict)

    def test_at_least_five_wafs(self):
        assert len(WAF_EXTRA_PAYLOADS) >= 5

    def test_known_wafs_present(self):
        expected = {"Cloudflare", "Akamai", "Imperva", "ModSecurity", "Wordfence"}
        assert expected.issubset(WAF_EXTRA_PAYLOADS.keys())

    def test_all_values_are_lists(self):
        for waf, payloads in WAF_EXTRA_PAYLOADS.items():
            assert isinstance(payloads, list), f"{waf} payload list is not a list"

    def test_all_payload_lists_non_empty(self):
        for waf, payloads in WAF_EXTRA_PAYLOADS.items():
            assert len(payloads) > 0, f"{waf} payload list is empty"

    def test_all_payloads_are_strings(self):
        for waf, payloads in WAF_EXTRA_PAYLOADS.items():
            for p in payloads:
                assert isinstance(p, str), f"{waf} has non-string payload: {p!r}"

    def test_marker_placeholder_present(self):
        """Every payload list should have at least one {marker} placeholder."""
        for waf, payloads in WAF_EXTRA_PAYLOADS.items():
            has_marker = any("{marker}" in p for p in payloads)
            assert has_marker, f"{waf} has no payload with {{marker}} placeholder"


# ---------------------------------------------------------------------------
# get_waf_payloads
# ---------------------------------------------------------------------------

class TestGetWafPayloads:
    def test_known_waf_returns_list(self):
        payloads = get_waf_payloads("Cloudflare")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_unknown_waf_returns_empty(self):
        assert get_waf_payloads("UnknownWAF_xyz") == []

    def test_empty_name_returns_empty(self):
        assert get_waf_payloads("") == []

    def test_case_sensitive(self):
        # WAF names are stored as-is; "cloudflare" ≠ "Cloudflare"
        assert get_waf_payloads("cloudflare") == []

    def test_returns_same_reference_as_table(self):
        assert get_waf_payloads("Cloudflare") is WAF_EXTRA_PAYLOADS["Cloudflare"]


# ---------------------------------------------------------------------------
# Payload content spot-checks
# ---------------------------------------------------------------------------

class TestCloudflarePayloads:
    def _payloads(self):
        return get_waf_payloads("Cloudflare")

    def test_has_svg_onload(self):
        assert any("svg" in p.lower() for p in self._payloads())

    def test_all_have_marker(self):
        for p in self._payloads():
            assert "{marker}" in p


class TestAkamaiPayloads:
    def _payloads(self):
        return get_waf_payloads("Akamai")

    def test_has_img_onerror(self):
        assert any("onerror" in p.lower() for p in self._payloads())

    def test_all_have_marker(self):
        for p in self._payloads():
            assert "{marker}" in p


class TestModSecurityPayloads:
    def _payloads(self):
        return get_waf_payloads("ModSecurity")

    def test_non_empty(self):
        assert len(self._payloads()) >= 3

    def test_all_have_marker(self):
        for p in self._payloads():
            assert "{marker}" in p


class TestWordfencePayloads:
    def _payloads(self):
        return get_waf_payloads("Wordfence")

    def test_has_audio_or_video(self):
        assert any("audio" in p.lower() or "video" in p.lower() for p in self._payloads())

    def test_all_have_marker(self):
        for p in self._payloads():
            assert "{marker}" in p


# ---------------------------------------------------------------------------
# Marker substitution
# ---------------------------------------------------------------------------

class TestMarkerSubstitution:
    def test_substitute_renders_valid_payload(self):
        marker = "TESTXSS001"
        payloads = get_waf_payloads("Cloudflare")
        rendered = [p.replace("{marker}", marker) for p in payloads]
        assert all(marker in r for r in rendered)

    def test_no_leftover_placeholder_after_substitution(self):
        marker = "TESTXSS001"
        for _, payloads in WAF_EXTRA_PAYLOADS.items():
            for p in payloads:
                rendered = p.replace("{marker}", marker)
                assert "{marker}" not in rendered
