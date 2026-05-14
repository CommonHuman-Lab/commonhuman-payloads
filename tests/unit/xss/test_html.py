# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for xss.html payload lists."""

import pytest

from commonhuman_payloads.xss.html import (
    HTML_BODY, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_NAME,
    TAG_NAME, TEXTAREA, TITLE, NOSCRIPT, IFRAME_SRCDOC, OBJECT_DATA,
    COMMENT, CSS, CSS_VALUE,
)

_ALL_LISTS = [
    ("HTML_BODY",    HTML_BODY),
    ("ATTR_DOUBLE",  ATTR_DOUBLE),
    ("ATTR_SINGLE",  ATTR_SINGLE),
    ("ATTR_UNQUOTED",ATTR_UNQUOTED),
    ("ATTR_NAME",    ATTR_NAME),
    ("TAG_NAME",     TAG_NAME),
    ("TEXTAREA",     TEXTAREA),
    ("TITLE",        TITLE),
    ("NOSCRIPT",     NOSCRIPT),
    ("IFRAME_SRCDOC",IFRAME_SRCDOC),
    ("OBJECT_DATA",  OBJECT_DATA),
    ("COMMENT",      COMMENT),
    ("CSS",          CSS),
    ("CSS_VALUE",    CSS_VALUE),
]


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_non_empty(name, lst):
    assert len(lst) > 0, f"{name} must not be empty"


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_all_strings(name, lst):
    for p in lst:
        assert isinstance(p, str), f"{name}: all payloads must be strings"


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_marker_placeholder(name, lst):
    """Every payload should contain {marker} so substitution is possible."""
    # OBJECT_DATA and ATTR_NAME have entries without {marker} — only flag
    # if NONE of the payloads carry the placeholder
    has_any = any("{marker}" in p for p in lst)
    assert has_any, f"{name}: at least one payload must contain {{marker}}"


def test_html_body_contains_script_tag():
    assert any("<script>" in p for p in HTML_BODY)


def test_html_body_contains_img_onerror():
    assert any("onerror" in p for p in HTML_BODY)


def test_attr_double_breaks_out_of_quote():
    assert any(p.startswith('"') for p in ATTR_DOUBLE)


def test_attr_single_breaks_out_of_quote():
    assert any(p.startswith("'") for p in ATTR_SINGLE)


def test_textarea_closes_tag():
    assert all(p.startswith("</textarea>") for p in TEXTAREA)


def test_title_closes_tag():
    assert all(p.startswith("</title>") for p in TITLE)


def test_comment_closes_comment():
    # Most entries use "-->"; "Sogeti bug" variants use "--!>" (IE quirk)
    assert all(p.startswith("-->") or p.startswith("--!>") for p in COMMENT)
