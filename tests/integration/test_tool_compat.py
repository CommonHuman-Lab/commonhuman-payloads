# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Integration tests: verify that both stingxss and breachsql can import and use
everything they need from commonhuman_payloads without errors.

These tests don't require the tools to be installed — they import the package
APIs directly and validate backward-compatibility contracts that both tools
depend on.
"""

import pytest


# ---------------------------------------------------------------------------
# XSS tool compatibility (stingxss payload_gen.py surface)
# ---------------------------------------------------------------------------

class TestStingxssPayloadGenCompat:
    """All symbols that stingxss/engine/analysis/payload_gen.py imports."""

    def test_html_context_symbols(self):
        from commonhuman_payloads.xss import (
            HTML_BODY, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_NAME,
            TAG_NAME, TEXTAREA, TITLE, NOSCRIPT, IFRAME_SRCDOC, OBJECT_DATA,
            COMMENT, CSS, CSS_VALUE,
        )
        for name, lst in [
            ("HTML_BODY", HTML_BODY), ("ATTR_DOUBLE", ATTR_DOUBLE),
            ("ATTR_SINGLE", ATTR_SINGLE), ("ATTR_UNQUOTED", ATTR_UNQUOTED),
            ("ATTR_NAME", ATTR_NAME), ("TAG_NAME", TAG_NAME),
            ("TEXTAREA", TEXTAREA), ("TITLE", TITLE), ("NOSCRIPT", NOSCRIPT),
            ("IFRAME_SRCDOC", IFRAME_SRCDOC), ("OBJECT_DATA", OBJECT_DATA),
            ("COMMENT", COMMENT), ("CSS", CSS), ("CSS_VALUE", CSS_VALUE),
        ]:
            assert isinstance(lst, list) and len(lst) > 0, f"{name} missing or empty"

    def test_script_context_symbols(self):
        from commonhuman_payloads.xss import (
            SCRIPT_STRING_D, SCRIPT_STRING_S, SCRIPT_BARE, SCRIPT_TEMPLATE,
            SCRIPT_REGEX, SCRIPT_COMMENT, EVENT_HANDLER, URL_ATTR, SCRIPT_SRC,
        )
        for name, lst in [
            ("SCRIPT_STRING_D", SCRIPT_STRING_D), ("SCRIPT_STRING_S", SCRIPT_STRING_S),
            ("SCRIPT_BARE", SCRIPT_BARE), ("SCRIPT_TEMPLATE", SCRIPT_TEMPLATE),
            ("SCRIPT_REGEX", SCRIPT_REGEX), ("SCRIPT_COMMENT", SCRIPT_COMMENT),
            ("EVENT_HANDLER", EVENT_HANDLER), ("URL_ATTR", URL_ATTR),
            ("SCRIPT_SRC", SCRIPT_SRC),
        ]:
            assert isinstance(lst, list) and len(lst) > 0, f"{name} missing or empty"

    def test_advanced_symbols(self):
        from commonhuman_payloads.xss import (
            ANGULAR_TEMPLATE, ANGULAR_TEMPLATE_ALT, ANGULAR_ATTR,
            VUE_TEMPLATE, JS_HOISTING, DANGLING_MARKUP, CSS_TRANSITION,
            EXTRA_NO_INTERACTION, FILE_UPLOAD, RESTRICTED_CHARS, POLYGLOT,
            WAF_BYPASS_GLOBAL, WAF_BYPASS_DOUBLE_ENCODE, PROTOTYPE_POLLUTION,
            CLASSIC_LEGACY, ENCODING, CONTENT_TYPE, MODERN_BROWSER, STORED_XSS,
            UNICODE_CASE_BYPASS, UNICODE_LINE_SEP, DOM_CLOBBERING, REPLACE_PATTERN,
            RADIX_OBFUSCATION, UNICODE_URL, SANITIZER_BYPASS, CSP_INJECTION,
        )
        for name, lst in [
            ("ANGULAR_TEMPLATE", ANGULAR_TEMPLATE), ("VUE_TEMPLATE", VUE_TEMPLATE),
            ("POLYGLOT", POLYGLOT), ("STORED_XSS", STORED_XSS),
            ("DOM_CLOBBERING", DOM_CLOBBERING),
        ]:
            assert isinstance(lst, list) and len(lst) > 0, f"{name} missing or empty"

    def test_encoder_symbols(self):
        from commonhuman_payloads.encoders import (
            apply_evasion,
            EVASION_BACKTICK, EVASION_CASE_MIXING, EVASION_CHUNKED_TAGS,
            EVASION_COMMENT_BREAK, EVASION_CSS_EXPR, EVASION_DOUBLE_ENCODE,
            EVASION_HTML_ENCODE, EVASION_NEWLINE, EVASION_NONE,
            EVASION_NULL_BYTE, EVASION_UNICODE,
        )
        assert callable(apply_evasion)

    def test_apply_evasion_roundtrip(self):
        from commonhuman_payloads.encoders import apply_evasion, EVASION_NONE
        payload = "<img src=x onerror=alert('test')>"
        assert apply_evasion(payload, EVASION_NONE) == payload

    def test_waf_detect_symbols(self):
        from commonhuman_payloads.waf import detect, WafResult, SIGNATURES, GENERIC_BLOCK_BODIES
        assert callable(detect)
        assert len(SIGNATURES) > 0
        assert len(GENERIC_BLOCK_BODIES) > 0


# ---------------------------------------------------------------------------
# SQL tool compatibility (breachsql _scanner/payloads surface)
# ---------------------------------------------------------------------------

class TestBreachsqlPayloadsCompat:
    """All symbols that breachsql/_scanner/payloads/__init__.py re-exports."""

    def test_error_symbols(self):
        from commonhuman_payloads.sqli import (
            ERROR_PAYLOADS, DB_ERROR_PATTERNS, get_error_payloads,
        )
        assert isinstance(ERROR_PAYLOADS, dict)
        assert isinstance(DB_ERROR_PATTERNS, dict)
        assert callable(get_error_payloads)

    def test_boolean_symbols(self):
        from commonhuman_payloads.sqli import (
            BOOLEAN_PAIRS, BOOLEAN_PAIRS_RISK2, get_boolean_pairs,
        )
        assert isinstance(BOOLEAN_PAIRS, list)
        assert isinstance(BOOLEAN_PAIRS_RISK2, list)
        assert callable(get_boolean_pairs)

    def test_time_symbols(self):
        from commonhuman_payloads.sqli import TIME_PAYLOADS, get_time_payloads
        assert isinstance(TIME_PAYLOADS, dict)
        assert callable(get_time_payloads)

    def test_union_symbols(self):
        from commonhuman_payloads.sqli import (
            CONCAT_PAYLOADS, SUBSTRING_PROBES,
            make_marker, get_concat_payloads, get_substring_probes,
            make_substring_payload, order_by_probes, union_null_probes,
        )
        assert callable(make_marker)
        assert callable(order_by_probes)
        assert callable(union_null_probes)

    def test_breach_marker_prefix_available(self):
        from commonhuman_payloads.sqli.union import BREACH_MARKER_PREFIX
        assert BREACH_MARKER_PREFIX == "BreachSQL_"

    def test_oob_symbols(self):
        from commonhuman_payloads.sqli import OOB_PAYLOADS, get_oob_payloads
        assert isinstance(OOB_PAYLOADS, dict)
        assert callable(get_oob_payloads)

    def test_advanced_symbols(self):
        from commonhuman_payloads.sqli import (
            DB_CONTENTS_PAYLOADS, get_db_contents_payloads,
            STACKED_PAYLOADS, get_stacked_payloads,
            DIOS_PAYLOADS, get_dios_payloads,
            LFI_PAYLOADS, get_lfi_payloads,
            PRIVESC_PAYLOADS, get_privesc_payloads,
            ENUM_PAYLOADS, get_enum_payloads,
        )
        assert callable(get_db_contents_payloads)
        assert callable(get_enum_payloads)

    def test_apply_evasion_from_encoders(self):
        from commonhuman_payloads.encoders import apply_evasion, EVASION_SQL_COMMENT
        result = apply_evasion("SELECT 1", EVASION_SQL_COMMENT)
        assert "/**/" in result

    def test_waf_detect_callable(self):
        from commonhuman_payloads.waf import detect, WafResult
        assert callable(detect)

        # Simulate the breachsql thin-wrapper call pattern
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "OK"
        resp.headers = {}

        def _get(url):
            return resp

        result = detect(_get, "https://example.com/?id=1", param="id",
                        probe_payload="' OR '1'='1\"-- -",
                        check_reflection=False)
        assert isinstance(result, WafResult)


# ---------------------------------------------------------------------------
# Public API stability — importable from top-level package
# ---------------------------------------------------------------------------

class TestPublicApiStability:
    def test_version_importable(self):
        from commonhuman_payloads import __version__, PAYLOAD_VERSION
        assert __version__
        assert PAYLOAD_VERSION

    def test_xss_api_importable(self):
        from commonhuman_payloads.xss import get_basic_payloads, get_payloads_for_context
        assert callable(get_basic_payloads)
        assert callable(get_payloads_for_context)

    def test_markers_importable(self):
        from commonhuman_payloads.markers import make_marker, is_reflected
        assert callable(make_marker)
        assert callable(is_reflected)

    def test_waf_module_importable(self):
        from commonhuman_payloads.waf import (
            detect, WafResult, WafSignature, SIGNATURES, GENERIC_BLOCK_BODIES,
        )
        assert callable(detect)

    def test_encoders_module_importable(self):
        from commonhuman_payloads.encoders import apply_evasion, ALL_EVASIONS
        assert callable(apply_evasion)
        assert len(ALL_EVASIONS) == 26
