# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for xss.advanced payload lists."""

import pytest

from commonhuman_payloads.xss.advanced import (
    ANGULAR_TEMPLATE, ANGULAR_TEMPLATE_ALT, ANGULAR_ATTR,
    VUE_TEMPLATE, JS_HOISTING, DANGLING_MARKUP,
    CSS_TRANSITION, EXTRA_NO_INTERACTION, FILE_UPLOAD, RESTRICTED_CHARS,
    POLYGLOT, WAF_BYPASS_DOUBLE_ENCODE, WAF_BYPASS_GLOBAL,
    PROTOTYPE_POLLUTION, CLASSIC_LEGACY, ENCODING, MODERN_BROWSER,
    STORED_XSS, UNICODE_CASE_BYPASS, UNICODE_LINE_SEP, DOM_CLOBBERING,
    REPLACE_PATTERN, RADIX_OBFUSCATION, UNICODE_URL, CONTENT_TYPE,
    SANITIZER_BYPASS, CSP_INJECTION,
)

_ALL_LISTS = [
    ("ANGULAR_TEMPLATE",      ANGULAR_TEMPLATE),
    ("ANGULAR_TEMPLATE_ALT",  ANGULAR_TEMPLATE_ALT),
    ("ANGULAR_ATTR",          ANGULAR_ATTR),
    ("VUE_TEMPLATE",          VUE_TEMPLATE),
    ("JS_HOISTING",           JS_HOISTING),
    ("DANGLING_MARKUP",       DANGLING_MARKUP),
    ("CSS_TRANSITION",        CSS_TRANSITION),
    ("EXTRA_NO_INTERACTION",  EXTRA_NO_INTERACTION),
    ("FILE_UPLOAD",           FILE_UPLOAD),
    ("RESTRICTED_CHARS",      RESTRICTED_CHARS),
    ("POLYGLOT",              POLYGLOT),
    ("WAF_BYPASS_DOUBLE_ENCODE", WAF_BYPASS_DOUBLE_ENCODE),
    ("WAF_BYPASS_GLOBAL",     WAF_BYPASS_GLOBAL),
    ("PROTOTYPE_POLLUTION",   PROTOTYPE_POLLUTION),
    ("CLASSIC_LEGACY",        CLASSIC_LEGACY),
    ("ENCODING",              ENCODING),
    ("MODERN_BROWSER",        MODERN_BROWSER),
    ("STORED_XSS",            STORED_XSS),
    ("UNICODE_CASE_BYPASS",   UNICODE_CASE_BYPASS),
    ("UNICODE_LINE_SEP",      UNICODE_LINE_SEP),
    ("DOM_CLOBBERING",        DOM_CLOBBERING),
    ("REPLACE_PATTERN",       REPLACE_PATTERN),
    ("RADIX_OBFUSCATION",     RADIX_OBFUSCATION),
    ("UNICODE_URL",           UNICODE_URL),
    ("CONTENT_TYPE",          CONTENT_TYPE),
    ("SANITIZER_BYPASS",      SANITIZER_BYPASS),
    ("CSP_INJECTION",         CSP_INJECTION),
]


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_non_empty(name, lst):
    assert len(lst) > 0, f"{name} must not be empty"


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_all_strings(name, lst):
    for p in lst:
        assert isinstance(p, str), f"{name}: all entries must be strings"


def test_angular_template_alt_uses_brackets():
    assert all("[[" in p and "]]" in p for p in ANGULAR_TEMPLATE_ALT)


def test_angular_template_alt_mirrors_template_count():
    assert len(ANGULAR_TEMPLATE_ALT) == len(ANGULAR_TEMPLATE)


def test_polyglot_non_trivial():
    assert any(len(p) > 20 for p in POLYGLOT)
