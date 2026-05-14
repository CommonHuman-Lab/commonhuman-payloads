# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for waf.detect — all branches of detect() and _inject_param()."""

from commonhuman_payloads.waf.detect import detect, _inject_param, WafResult
from commonhuman_payloads.encoders.transforms import EVASION_NONE, EVASION_DOUBLE_ENCODE


# ---------------------------------------------------------------------------
# _inject_param
# ---------------------------------------------------------------------------

class TestInjectParam:
    def test_replaces_existing_param(self):
        url = "https://example.com/search?q=original&page=1"
        result = _inject_param(url, "q", "INJECTED")
        assert "INJECTED" in result
        assert "original" not in result

    def test_adds_missing_param(self):
        url = "https://example.com/page"
        result = _inject_param(url, "q", "value")
        assert "q=value" in result

    def test_preserves_other_params(self):
        url = "https://example.com/search?q=x&page=2"
        result = _inject_param(url, "q", "NEW")
        assert "page=2" in result

    def test_encodes_special_chars(self):
        url = "https://example.com/?q=x"
        result = _inject_param(url, "q", "<script>")
        assert "<script>" not in result  # should be URL-encoded


# ---------------------------------------------------------------------------
# detect() — branch coverage
# ---------------------------------------------------------------------------

class TestDetectNoWaf:
    def test_probe_reflects_200_returns_no_waf(self, make_response, make_get_fn):
        """Probe reflects with 2xx and check_reflection=True → immediate no-WAF."""
        payload = "<script>alert(1)</script>"
        resp = make_response(200, f"Hello {payload} World")
        get_fn = make_get_fn(resp)
        result = detect(get_fn, "https://example.com/?q=x", probe_payload=payload,
                        check_reflection=True)
        assert result.detected is False
        assert result.confidence == "none"
        assert result.evasions == [EVASION_NONE]

    def test_no_signals_returns_no_waf(self, make_response, make_get_fn):
        """Normal 200 with benign body → no WAF."""
        resp = make_response(200, "<html>Hello world</html>")
        get_fn = make_get_fn(resp)
        result = detect(get_fn, "https://example.com/?q=x",
                        probe_payload="<script>alert(1)</script>",
                        check_reflection=False)
        assert result.detected is False

    def test_exception_in_get_fn_returns_no_waf(self, raising_get_fn):
        result = detect(raising_get_fn, "https://example.com/?q=x")
        assert result.detected is False
        assert result.confidence == "none"


class TestDetectSignatureMatch:
    def test_cloudflare_high_confidence(self, make_response, make_get_fn):
        """Headers + body + status all match → high confidence."""
        resp = make_response(
            403,
            "Error 1020 cloudflare attention required cf-ray",
            {"server": "cloudflare", "cf-ray": "abc123xyz"},
        )
        get_fn = make_get_fn(resp)
        result = detect(get_fn, "https://example.com/?q=x",
                        check_reflection=False)
        assert result.detected is True
        assert result.name == "Cloudflare"
        assert result.confidence == "high"
        assert len(result.evasions) > 0

    def test_cloudflare_medium_confidence(self, make_response, make_get_fn):
        """Only server header matches → score=2 → medium confidence."""
        resp = make_response(
            200,
            "Some page",
            {"server": "cloudflare"},
        )
        get_fn = make_get_fn(resp)
        result = detect(get_fn, "https://example.com/?q=x",
                        check_reflection=False)
        assert result.detected is True
        assert result.name == "Cloudflare"
        assert result.confidence == "medium"

    def test_check_reflection_false_skips_reflection_check(self, make_response, make_get_fn):
        """SQL probe with check_reflection=False should NOT short-circuit on reflected text."""
        probe = "' OR 1=1-- -"
        resp = make_response(200, f"Results for {probe}")
        get_fn = make_get_fn(resp)
        # With check_reflection=True this would return immediately
        result_false = detect(get_fn, "https://example.com/?id=1", param="id",
                              probe_payload=probe, check_reflection=False)
        # Should not short-circuit — should go through full scoring
        assert isinstance(result_false, WafResult)


class TestDetectGenericWaf:
    def test_inline_body_block_200(self, make_response, make_get_fn):
        """200 + block phrase in body → inline body block result."""
        resp = make_response(200, "Access Denied — your request was blocked.")
        get_fn = make_get_fn(resp)
        result = detect(get_fn, "https://example.com/?q=x",
                        check_reflection=False)
        assert result.detected is True
        assert "inline" in result.name.lower()
        assert result.confidence == "medium"
        assert EVASION_DOUBLE_ENCODE in result.evasions

    def test_generic_403_double_encode_bypass(self, make_response, make_get_fn):
        """403 on probe, clean 200 on double-encoded probe → double-encode bypass."""
        blocked = make_response(403, "Forbidden")
        clean   = make_response(200, "OK clean")
        get_fn  = make_get_fn([blocked, clean])
        result = detect(get_fn, "https://example.com/?q=x",
                        check_reflection=False)
        assert result.detected is True
        assert "double-encode" in result.name.lower()
        assert EVASION_DOUBLE_ENCODE in result.evasions

    def test_generic_403_double_encode_bypass_with_param(self, make_response, make_get_fn):
        """Same bypass path but with an explicit param (covers line 119 branch)."""
        blocked = make_response(403, "Forbidden")
        clean   = make_response(200, "OK clean")
        get_fn  = make_get_fn([blocked, clean])
        result = detect(get_fn, "https://example.com/search?id=1", param="id",
                        check_reflection=False)
        assert result.detected is True
        assert "double-encode" in result.name.lower()

    def test_generic_403_no_bypass(self, make_response, make_get_fn):
        """403 on probe AND on double-encoded probe → generic WAF low confidence."""
        blocked1 = make_response(403, "Forbidden")
        blocked2 = make_response(403, "Forbidden")
        get_fn   = make_get_fn([blocked1, blocked2])
        result = detect(get_fn, "https://example.com/?q=x",
                        check_reflection=False)
        assert result.detected is True
        assert result.name == "Generic WAF"
        assert result.confidence == "low"

    def test_generic_403_double_encode_probe_raises(self, make_response):
        """Second probe (double-encode) raises → fall through to generic WAF."""
        blocked = make_response(403, "Forbidden")
        call_count = [0]

        def _get(_url):
            call_count[0] += 1
            if call_count[0] == 1:
                return blocked
            raise OSError("connection refused")

        result = detect(_get, "https://example.com/?q=x",
                        check_reflection=False)
        assert result.detected is True
        assert result.name == "Generic WAF"

    def test_generic_blocked_body_also_blocked_double_encode(self, make_response, make_get_fn):
        """Second probe returns 4xx and body block → falls to generic WAF."""
        blocked  = make_response(403, "Forbidden")
        blocked2 = make_response(403, "Access Denied")
        get_fn   = make_get_fn([blocked, blocked2])
        result   = detect(get_fn, "https://example.com/?q=x",
                          check_reflection=False)
        assert result.detected is True

    def test_param_injected_when_provided(self, make_response, make_get_fn):
        """When param is given, it should be injected into URL rather than appended as ?q=."""
        resp = make_response(200, "hello")
        captured_urls = []

        def _get(url):
            captured_urls.append(url)
            return resp

        detect(_get, "https://example.com/search?id=1", param="id",
               check_reflection=False)
        assert len(captured_urls) >= 1
        assert "id=" in captured_urls[0]

    def test_no_param_appends_q(self, make_response):
        """Without param, probe is appended as ?q=<payload>."""
        resp = make_response(200, "hello")
        captured = []

        def _get(url):
            captured.append(url)
            return resp

        detect(_get, "https://example.com/", probe_payload="test",
               check_reflection=False)
        assert "q=" in captured[0]

    def test_url_with_existing_query_uses_ampersand(self, make_response):
        """URL already has query params → use & not ?."""
        resp = make_response(200, "hello")
        captured = []

        def _get(url):
            captured.append(url)
            return resp

        detect(_get, "https://example.com/?page=1", probe_payload="test",
               check_reflection=False)
        assert "page=1" in captured[0]
        assert "&q=" in captured[0]
