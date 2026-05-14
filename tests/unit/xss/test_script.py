# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for xss.script payload lists."""

import pytest

from commonhuman_payloads.xss.script import (
    SCRIPT_STRING_D, SCRIPT_STRING_S, SCRIPT_BARE, SCRIPT_TEMPLATE,
    SCRIPT_REGEX, SCRIPT_COMMENT, EVENT_HANDLER, URL_ATTR, SCRIPT_SRC,
)

_ALL_LISTS = [
    ("SCRIPT_STRING_D", SCRIPT_STRING_D),
    ("SCRIPT_STRING_S", SCRIPT_STRING_S),
    ("SCRIPT_BARE",     SCRIPT_BARE),
    ("SCRIPT_TEMPLATE", SCRIPT_TEMPLATE),
    ("SCRIPT_REGEX",    SCRIPT_REGEX),
    ("SCRIPT_COMMENT",  SCRIPT_COMMENT),
    ("EVENT_HANDLER",   EVENT_HANDLER),
    ("URL_ATTR",        URL_ATTR),
    ("SCRIPT_SRC",      SCRIPT_SRC),
]


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_non_empty(name, lst):
    assert len(lst) > 0


@pytest.mark.parametrize("name,lst", _ALL_LISTS)
def test_all_strings(name, lst):
    for p in lst:
        assert isinstance(p, str)


def test_script_string_d_uses_double_quote_escape():
    assert any('"' in p for p in SCRIPT_STRING_D)


def test_script_string_s_uses_single_quote_escape():
    assert any("'" in p for p in SCRIPT_STRING_S)


def test_script_template_uses_backtick():
    assert any("`" in p for p in SCRIPT_TEMPLATE)


def test_url_attr_has_javascript_protocol():
    assert any("javascript:" in p for p in URL_ATTR)


def test_script_src_has_external_url():
    assert any(p.startswith("//") or p.startswith("http") for p in SCRIPT_SRC)


def test_event_handler_contains_alert():
    assert any("alert" in p or "confirm" in p for p in EVENT_HANDLER)
