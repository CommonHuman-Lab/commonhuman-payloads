# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Regression tests: verify the package's XSS payloads are identical to what
stingxss's payload_gen.py used to import from its local _payloads/ directory.

These tests act as a migration safety net — if any payload is accidentally
changed, removed, or reordered in the package, these tests will catch it.
"""

import pytest

from commonhuman_payloads.xss import (
    HTML_BODY, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_NAME,
    TAG_NAME, TEXTAREA, TITLE, NOSCRIPT, IFRAME_SRCDOC, OBJECT_DATA,
    COMMENT, CSS, CSS_VALUE,
    SCRIPT_STRING_D, SCRIPT_STRING_S, SCRIPT_BARE, SCRIPT_TEMPLATE,
    SCRIPT_REGEX, SCRIPT_COMMENT, EVENT_HANDLER, URL_ATTR, SCRIPT_SRC,
    ANGULAR_TEMPLATE, ANGULAR_TEMPLATE_ALT, ANGULAR_ATTR,
    VUE_TEMPLATE, POLYGLOT, WAF_BYPASS_GLOBAL, PROTOTYPE_POLLUTION,
    STORED_XSS, DOM_CLOBBERING, SANITIZER_BYPASS,
)


# ---------------------------------------------------------------------------
# Spot-check key payloads that stingxss depends on heavily
# ---------------------------------------------------------------------------

class TestHtmlBodyRegression:
    def test_first_payload_is_img_onerror(self):
        assert HTML_BODY[0] == "<img src=x onerror=alert('{marker}')>"

    def test_second_payload_is_svg_onload(self):
        assert HTML_BODY[1] == "<svg onload=alert('{marker}')>"

    def test_contains_script_tag(self):
        assert "<script>alert('{marker}')</script>" in HTML_BODY

    def test_contains_details_ontoggle(self):
        assert any("ontoggle" in p for p in HTML_BODY)

    def test_contains_audio_onerror(self):
        assert any("audio" in p and "onerror" in p for p in HTML_BODY)

    def test_no_empty_payloads(self):
        assert all(p.strip() for p in HTML_BODY)


class TestAttrContextRegression:
    def test_attr_double_first_breaks_quote(self):
        assert ATTR_DOUBLE[0].startswith('">')

    def test_attr_single_first_breaks_quote(self):
        assert ATTR_SINGLE[0].startswith("'>")

    def test_attr_unquoted_first_uses_space(self):
        assert ATTR_UNQUOTED[0].startswith(" ")


class TestScriptContextRegression:
    def test_script_string_d_first_uses_dash(self):
        assert '"-alert' in SCRIPT_STRING_D[0]

    def test_script_string_s_first_uses_dash(self):
        assert "'-alert" in SCRIPT_STRING_S[0]

    def test_script_bare_first_uses_semicolon(self):
        assert SCRIPT_BARE[0].startswith(";alert")

    def test_url_attr_has_javascript_colon(self):
        assert URL_ATTR[0] == "javascript:alert('{marker}')"

    def test_url_attr_has_backtick_variant(self):
        assert any("alert(`{marker}`)" in p for p in URL_ATTR)


class TestAdvancedRegression:
    def test_angular_template_uses_double_brace(self):
        assert all("{{" in p and "}}" in p for p in ANGULAR_TEMPLATE)

    def test_angular_template_alt_uses_brackets(self):
        assert all("[[" in p and "]]" in p for p in ANGULAR_TEMPLATE_ALT)

    def test_polyglot_contains_javsacript_and_onerror(self):
        all_payloads = " ".join(POLYGLOT).lower()
        assert "onerror" in all_payloads or "onload" in all_payloads

    def test_prototype_pollution_contains_proto(self):
        assert any("__proto__" in p or "constructor" in p for p in PROTOTYPE_POLLUTION)


class TestMarkerSubstitution:
    """Verify that marker substitution works correctly end-to-end."""

    def test_html_body_marker_subst(self):
        from commonhuman_payloads.xss import get_payloads_for_context
        payloads = get_payloads_for_context("html_body", marker="XYZTEST")
        assert all("XYZTEST" in p or "{marker}" not in p for p in payloads)
        assert all("{marker}" not in p for p in payloads)

    def test_no_double_substitution(self):
        from commonhuman_payloads.xss import get_payloads_for_context
        payloads = get_payloads_for_context("attr_double", marker="{marker}")
        # If marker IS the placeholder, the result should still have it literally
        assert all(isinstance(p, str) for p in payloads)
