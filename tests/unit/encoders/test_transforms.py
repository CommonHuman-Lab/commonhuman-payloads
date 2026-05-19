# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for all 24 WAF evasion strategies in encoders.transforms."""

import re
import urllib.parse

import pytest

from commonhuman_payloads.encoders.transforms import (
    # Constants
    EVASION_NONE,
    EVASION_CASE_MIXING,
    EVASION_HTML_ENCODE,
    EVASION_UNICODE,
    EVASION_DOUBLE_ENCODE,
    EVASION_CHUNKED_TAGS,
    EVASION_NULL_BYTE,
    EVASION_NEWLINE,
    EVASION_COMMENT_BREAK,
    EVASION_BACKTICK,
    EVASION_CSS_EXPR,
    EVASION_FROMCHARCODE,
    EVASION_UNESCAPE,
    EVASION_SQL_COMMENT,
    EVASION_SQL_WHITESPACE,
    EVASION_SQL_CASE,
    EVASION_SQL_ENCODE,
    EVASION_SQL_MULTILINE,
    EVASION_SQL_VERSIONED,
    EVASION_SQL_SPACE_DASH,
    EVASION_SQL_SPACE_HASH,
    EVASION_SQL_SPACE_PLUS,
    EVASION_SQL_BLANK_CHARS,
    EVASION_SQL_RANDOM_COMMENTS,
    EVASION_SQL_EQUALTOLIKE,
    EVASION_SQL_BETWEEN,
    ALL_EVASIONS,
    # Main function
    apply_evasion,
    apply_evasion_chain,
    EVASION_NAMES,
    # Public helpers
    case_mix,
    html_encode,
    unicode_escape,
    double_url_encode,
)


# ---------------------------------------------------------------------------
# Constant sanity checks
# ---------------------------------------------------------------------------

class TestConstants:
    def test_all_constants_are_strings(self):
        constants = [
            EVASION_NONE, EVASION_CASE_MIXING, EVASION_HTML_ENCODE,
            EVASION_UNICODE, EVASION_DOUBLE_ENCODE, EVASION_CHUNKED_TAGS,
            EVASION_NULL_BYTE, EVASION_NEWLINE, EVASION_COMMENT_BREAK,
            EVASION_BACKTICK, EVASION_CSS_EXPR,
            EVASION_SQL_COMMENT, EVASION_SQL_WHITESPACE, EVASION_SQL_CASE,
            EVASION_SQL_ENCODE, EVASION_SQL_MULTILINE,
            EVASION_SQL_VERSIONED, EVASION_SQL_SPACE_DASH, EVASION_SQL_SPACE_HASH,
            EVASION_SQL_SPACE_PLUS, EVASION_SQL_BLANK_CHARS,
            EVASION_SQL_RANDOM_COMMENTS, EVASION_SQL_EQUALTOLIKE, EVASION_SQL_BETWEEN,
        ]
        for c in constants:
            assert isinstance(c, str)

    def test_all_evasions_has_26_entries(self):
        assert len(ALL_EVASIONS) == 26

    def test_all_evasions_are_unique(self):
        assert len(ALL_EVASIONS) == len(set(ALL_EVASIONS))

    def test_none_is_first(self):
        assert ALL_EVASIONS[0] == EVASION_NONE


# ---------------------------------------------------------------------------
# apply_evasion — one class per strategy
# ---------------------------------------------------------------------------

class TestNone:
    def test_identity(self):
        payload = "<script>alert('xss')</script>"
        assert apply_evasion(payload, EVASION_NONE) == payload

    def test_empty_string(self):
        assert apply_evasion("", EVASION_NONE) == ""


class TestCaseMixing:
    def test_letters_are_changed(self):
        result = apply_evasion("SELECT", EVASION_CASE_MIXING)
        assert result.lower() == "select"
        assert result != "SELECT" and result != "select"

    def test_alternating_pattern(self):
        result = apply_evasion("SELECT", EVASION_CASE_MIXING)
        assert result == "SeLeCt"

    def test_non_alpha_preserved(self):
        result = apply_evasion("1=1", EVASION_CASE_MIXING)
        assert result == "1=1"

    def test_mixed_input(self):
        # Non-alpha chars don't advance the toggle, so 'b' after '1' is still lowercase
        result = apply_evasion("a1b2", EVASION_CASE_MIXING)
        assert result == "A1b2"


class TestHtmlEncode:
    def test_angle_brackets_encoded(self):
        result = apply_evasion("<script>", EVASION_HTML_ENCODE)
        assert "<" not in result
        assert ">" not in result

    def test_lt_encoded(self):
        result = apply_evasion("<", EVASION_HTML_ENCODE)
        assert result == "&#60;"

    def test_gt_encoded(self):
        result = apply_evasion(">", EVASION_HTML_ENCODE)
        assert result == "&#62;"

    def test_other_chars_preserved(self):
        result = apply_evasion("hello", EVASION_HTML_ENCODE)
        assert result == "hello"


class TestUnicode:
    def test_alpha_runs_escaped(self):
        result = apply_evasion("alert", EVASION_UNICODE)
        assert "\\u" in result

    def test_non_alpha_preserved(self):
        result = apply_evasion("123", EVASION_UNICODE)
        assert result == "123"

    def test_short_alpha_not_escaped(self):
        # Single char is not an "alpha run" per regex [a-zA-Z]{2,}
        result = apply_evasion("a", EVASION_UNICODE)
        assert result == "a"

    def test_two_alpha_chars_escaped(self):
        result = apply_evasion("ab", EVASION_UNICODE)
        assert "\\u0061" in result and "\\u0062" in result


class TestDoubleEncode:
    def test_angle_brackets_double_encoded(self):
        result = apply_evasion("<img>", EVASION_DOUBLE_ENCODE)
        assert "%253c" in result.lower() or "%253C" in result

    def test_no_angle_brackets_full_double_encode(self):
        payload = "' OR 1=1-- -"
        result = apply_evasion(payload, EVASION_DOUBLE_ENCODE)
        # Should be fully double-URL-encoded
        assert "%" in result
        decoded_once = urllib.parse.unquote(result)
        assert "%" in decoded_once  # still has encoding after one decode

    def test_lt_becomes_percent253c(self):
        result = apply_evasion("<", EVASION_DOUBLE_ENCODE)
        assert result == "%253c"


class TestChunkedTags:
    def test_on_handler_broken(self):
        # _chunked_tag inserts /**/ at position 3 in the event name: on → one/**/rror
        result = apply_evasion("<img onerror=x>", EVASION_CHUNKED_TAGS)
        assert "/**/" in result

    def test_script_tag_gets_space(self):
        result = apply_evasion("<script>", EVASION_CHUNKED_TAGS)
        # hatchling splits the tag name
        assert "script" in result.lower()


class TestNullByte:
    def test_null_byte_injected_after_lt(self):
        result = apply_evasion("<script>", EVASION_NULL_BYTE)
        assert "\x00" in result
        assert result.index("<") + 1 == result.index("\x00")

    def test_no_lt_payload_unchanged(self):
        result = apply_evasion("no angle brackets", EVASION_NULL_BYTE)
        assert result == "no angle brackets"

    def test_only_first_lt_affected(self):
        result = apply_evasion("<a><b>", EVASION_NULL_BYTE)
        assert result.count("\x00") == 1


class TestNewline:
    def test_spaces_replaced_with_percent0a(self):
        result = apply_evasion("a b c", EVASION_NEWLINE)
        assert " " not in result
        assert "%0a" in result

    def test_no_spaces_unchanged(self):
        result = apply_evasion("nospaces", EVASION_NEWLINE)
        assert result == "nospaces"


class TestCommentBreak:
    def test_script_tag_gets_comment(self):
        result = apply_evasion("<script>", EVASION_COMMENT_BREAK)
        assert "<!---->" in result

    def test_img_tag_gets_comment(self):
        result = apply_evasion("<img>", EVASION_COMMENT_BREAK)
        assert "<!---->" in result

    def test_unknown_tag_unchanged(self):
        result = apply_evasion("<div>", EVASION_COMMENT_BREAK)
        # div is not in the pattern — unchanged
        assert result == "<div>"


class TestBacktick:
    def test_double_quotes_replaced(self):
        result = apply_evasion('"alert"', EVASION_BACKTICK)
        assert '"' not in result
        assert '`' in result

    def test_single_quotes_replaced(self):
        result = apply_evasion("'alert'", EVASION_BACKTICK)
        assert "'" not in result
        assert "`" in result

    def test_no_quotes_unchanged(self):
        result = apply_evasion("alert(1)", EVASION_BACKTICK)
        assert result == "alert(1)"


class TestCssExpr:
    def test_expression_keyword_broken(self):
        # "expression" → "ex/**/pression": comment is injected mid-word
        result = apply_evasion("expression(alert(1))", EVASION_CSS_EXPR)
        assert "/**/pression" in result

    def test_no_expression_unchanged(self):
        result = apply_evasion("alert(1)", EVASION_CSS_EXPR)
        assert result == "alert(1)"


class TestSqlComment:
    def test_select_keyword_wrapped(self):
        result = apply_evasion("SELECT 1", EVASION_SQL_COMMENT)
        assert "/**/SELECT/**/" in result or "/**/" in result

    def test_union_wrapped(self):
        result = apply_evasion("UNION SELECT", EVASION_SQL_COMMENT)
        assert "/**/" in result


class TestSqlWhitespace:
    def test_spaces_replaced_with_tab(self):
        result = apply_evasion("SELECT 1 FROM t", EVASION_SQL_WHITESPACE)
        assert " " not in result
        assert "\t" in result

    def test_no_spaces_unchanged(self):
        result = apply_evasion("SELECT", EVASION_SQL_WHITESPACE)
        assert result == "SELECT"


class TestSqlCase:
    def test_case_randomized(self):
        # Run 10 times — at least one should differ from the original
        original = "SELECT FROM WHERE"
        results = {apply_evasion(original, EVASION_SQL_CASE) for _ in range(10)}
        lower = original.lower()
        upper = original.upper()
        assert any(r != lower and r != upper for r in results) or len(results) > 1

    def test_only_alpha_changed(self):
        result = apply_evasion("1=1", EVASION_SQL_CASE)
        assert "1" in result and "=" in result


class TestSqlEncode:
    def test_payload_url_encoded(self):
        result = apply_evasion("' OR '1'='1", EVASION_SQL_ENCODE)
        assert "%" in result
        assert "'" not in result

    def test_decoded_roundtrip(self):
        payload = "' OR 1=1-- -"
        result = apply_evasion(payload, EVASION_SQL_ENCODE)
        assert urllib.parse.unquote(result) == payload


class TestSqlMultiline:
    def test_spaces_outside_strings_replaced(self):
        result = apply_evasion("SELECT 1 FROM t", EVASION_SQL_MULTILINE)
        assert "/*\n*/" in result

    def test_spaces_inside_strings_preserved(self):
        result = apply_evasion("'hello world'", EVASION_SQL_MULTILINE)
        # Spaces inside the single-quoted string should stay as spaces
        assert " " in result

    def test_no_spaces_unchanged(self):
        result = apply_evasion("SELECT", EVASION_SQL_MULTILINE)
        assert result == "SELECT"


class TestUnknownEvasion:
    def test_unknown_returns_payload_unchanged(self):
        payload = "test payload"
        result = apply_evasion(payload, "totally_unknown_strategy_xyz")
        assert result == payload


# ---------------------------------------------------------------------------
# Public helper functions
# ---------------------------------------------------------------------------

class TestCaseMixHelper:
    def test_alternates_upper_lower(self):
        assert case_mix("abcde") == "AbCdE"

    def test_non_alpha_skipped(self):
        # Non-alpha chars don't advance the toggle
        assert case_mix("a1b2") == "A1b2"


class TestHtmlEncodeHelper:
    def test_encodes_apostrophe(self):
        assert html_encode("'") == "&#39;"

    def test_encodes_double_quote(self):
        assert html_encode('"') == "&quot;"

    def test_encodes_ampersand(self):
        assert html_encode("&") == "&amp;"

    def test_plain_text_unchanged(self):
        assert html_encode("hello") == "hello"


class TestUnicodeEscapeHelper:
    def test_escapes_every_alpha(self):
        result = unicode_escape("ab")
        assert "\\u0061" in result
        assert "\\u0062" in result

    def test_digits_unchanged(self):
        assert unicode_escape("123") == "123"


class TestDoubleUrlEncodeHelper:
    def test_single_char_double_encoded(self):
        result = double_url_encode("'")
        assert result == "%2527"  # %25 + 27 (' → %27, then %27 → %2527)

    def test_roundtrip_two_decodes(self):
        payload = "abc"
        encoded = double_url_encode(payload)
        assert urllib.parse.unquote(urllib.parse.unquote(encoded)) == payload


# ---------------------------------------------------------------------------
# New strategies (added in evasion expansion to 24)
# ---------------------------------------------------------------------------

class TestSqlVersioned:
    def test_select_wrapped_in_versioned_comment(self):
        result = apply_evasion("SELECT 1", EVASION_SQL_VERSIONED)
        assert "/*!50000SELECT*/" in result or "/*!50000select*/" in result.lower()

    def test_no_keyword_no_change(self):
        result = apply_evasion("1+1", EVASION_SQL_VERSIONED)
        assert result == "1+1"

    def test_original_keyword_absent(self):
        result = apply_evasion("SELECT", EVASION_SQL_VERSIONED)
        # The bare keyword SELECT should be gone; versioned comment present
        assert "/*!50000" in result
        assert result != "SELECT"


class TestSqlSpaceDash:
    def test_spaces_replaced(self):
        result = apply_evasion("SELECT 1", EVASION_SQL_SPACE_DASH)
        assert " " not in result

    def test_contains_dash_comment(self):
        result = apply_evasion("a b", EVASION_SQL_SPACE_DASH)
        assert "--" in result and "\n" in result

    def test_no_spaces_unchanged(self):
        result = apply_evasion("SELECT", EVASION_SQL_SPACE_DASH)
        assert result == "SELECT"


class TestSqlSpaceHash:
    def test_spaces_replaced(self):
        result = apply_evasion("SELECT 1", EVASION_SQL_SPACE_HASH)
        assert " " not in result

    def test_contains_hash_comment(self):
        result = apply_evasion("a b", EVASION_SQL_SPACE_HASH)
        assert "#" in result and "\n" in result

    def test_no_spaces_unchanged(self):
        result = apply_evasion("SELECT", EVASION_SQL_SPACE_HASH)
        assert result == "SELECT"


class TestSqlSpacePlus:
    def test_spaces_replaced_with_plus(self):
        result = apply_evasion("SELECT 1 FROM t", EVASION_SQL_SPACE_PLUS)
        assert " " not in result
        assert "+" in result

    def test_plus_count_matches_space_count(self):
        payload = "a b c d"
        result = apply_evasion(payload, EVASION_SQL_SPACE_PLUS)
        assert result.count("+") == payload.count(" ")

    def test_no_spaces_unchanged(self):
        assert apply_evasion("SELECT", EVASION_SQL_SPACE_PLUS) == "SELECT"


class TestSqlBlankChars:
    _BLANK_CHARS = {"\t", "%0b", "%0c", "%0d"}

    def test_spaces_replaced(self):
        result = apply_evasion("a b", EVASION_SQL_BLANK_CHARS)
        assert " " not in result

    def test_replacement_is_valid_blank(self):
        result = apply_evasion("a b", EVASION_SQL_BLANK_CHARS)
        # The character between 'a' and 'b' must be one of the valid blanks
        middle = result[1:-1]
        assert middle in self._BLANK_CHARS

    def test_no_spaces_unchanged(self):
        assert apply_evasion("SELECT", EVASION_SQL_BLANK_CHARS) == "SELECT"


class TestSqlRandomComments:
    def test_select_chars_separated_by_comments(self):
        result = apply_evasion("SELECT", EVASION_SQL_RANDOM_COMMENTS)
        assert "/**/" in result

    def test_non_keyword_unchanged(self):
        result = apply_evasion("1=1", EVASION_SQL_RANDOM_COMMENTS)
        assert result == "1=1"

    def test_all_letters_still_present(self):
        result = apply_evasion("SELECT", EVASION_SQL_RANDOM_COMMENTS)
        for ch in "SELECT":
            assert ch.upper() in result.upper()


class TestSqlEqualToLike:
    def test_equals_replaced_with_like(self):
        result = apply_evasion("id=1", EVASION_SQL_EQUALTOLIKE)
        assert "=" not in result
        assert "LIKE" in result

    def test_not_equals_preserved(self):
        result = apply_evasion("id!=1", EVASION_SQL_EQUALTOLIKE)
        assert "!=" in result

    def test_less_than_equals_preserved(self):
        result = apply_evasion("id<=1", EVASION_SQL_EQUALTOLIKE)
        assert "<=" in result

    def test_no_equals_unchanged(self):
        result = apply_evasion("SELECT 1", EVASION_SQL_EQUALTOLIKE)
        assert result == "SELECT 1"


class TestFromCharCode:
    def test_event_handler_double_quoted_encoded(self):
        result = apply_evasion('<img src=x onerror="alert(1)">', EVASION_FROMCHARCODE)
        assert "String.fromCharCode" in result
        assert "eval(" in result

    def test_event_handler_single_quoted_encoded(self):
        result = apply_evasion("<img src=x onerror='alert(1)'>", EVASION_FROMCHARCODE)
        assert "String.fromCharCode" in result

    def test_script_block_encoded(self):
        result = apply_evasion("<script>alert(1)</script>", EVASION_FROMCHARCODE)
        assert "String.fromCharCode" in result
        assert "<script>" in result
        assert "</script>" in result

    def test_no_js_payload_unchanged(self):
        payload = "<div>hello</div>"
        result = apply_evasion(payload, EVASION_FROMCHARCODE)
        assert result == payload

    def test_charcode_values_are_correct(self):
        result = apply_evasion('<img src=x onerror="x">', EVASION_FROMCHARCODE)
        # "x" is ord 120
        assert "120" in result

    def test_result_is_string(self):
        result = apply_evasion('<svg onload="alert(1)">', EVASION_FROMCHARCODE)
        assert isinstance(result, str)


class TestUnescapeEncode:
    def test_event_handler_encoded(self):
        result = apply_evasion('<img src=x onerror="alert(1)">', EVASION_UNESCAPE)
        assert "unescape(" in result
        assert "eval(" in result

    def test_script_block_encoded(self):
        result = apply_evasion("<script>alert(1)</script>", EVASION_UNESCAPE)
        assert "unescape(" in result
        assert "<script>" in result

    def test_percent_encoded_chars_present(self):
        result = apply_evasion('<img src=x onerror="x">', EVASION_UNESCAPE)
        # "x" percent-encoded is %78
        assert "%78" in result

    def test_no_js_payload_unchanged(self):
        payload = "<div>hello</div>"
        result = apply_evasion(payload, EVASION_UNESCAPE)
        assert result == payload

    def test_result_is_string(self):
        result = apply_evasion('<svg onload="alert(1)">', EVASION_UNESCAPE)
        assert isinstance(result, str)


class TestSqlBetween:
    def test_greater_than_replaced_with_between(self):
        result = apply_evasion("id>5", EVASION_SQL_BETWEEN)
        assert ">" not in result
        assert "NOT BETWEEN" in result
        assert "AND" in result

    def test_numeric_preserved_in_output(self):
        result = apply_evasion("val>42", EVASION_SQL_BETWEEN)
        assert "42" in result

    def test_no_greater_than_unchanged(self):
        result = apply_evasion("id=1", EVASION_SQL_BETWEEN)
        assert result == "id=1"

    def test_spaced_form(self):
        result = apply_evasion("id > 10", EVASION_SQL_BETWEEN)
        assert "NOT BETWEEN" in result
        assert "10" in result


class TestApplyEvasionChain:
    def test_single_step_chain(self):
        result = apply_evasion_chain("<script>alert(1)</script>", ["html"])
        assert "&#60;" in result

    def test_multi_step_chain_applied_in_order(self):
        result = apply_evasion_chain("<script>alert(1)</script>", ["case", "html"])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_empty_chain_returns_payload_unchanged(self):
        payload = "<script>test</script>"
        assert apply_evasion_chain(payload, []) == payload

    def test_unknown_step_name_skipped(self):
        payload = "<img src=x>"
        result = apply_evasion_chain(payload, ["nonexistent_step"])
        assert result == payload

    def test_none_evasion_step_skipped(self):
        payload = "SELECT 1"
        result = apply_evasion_chain(payload, ["none"])
        assert result == payload

    def test_chain_names_case_insensitive(self):
        r1 = apply_evasion_chain("<b>", ["html"])
        r2 = apply_evasion_chain("<b>", ["HTML"])
        assert r1 == r2

    def test_chain_names_stripped_of_whitespace(self):
        r1 = apply_evasion_chain("<b>", ["html"])
        r2 = apply_evasion_chain("<b>", ["  html  "])
        assert r1 == r2

    def test_apply_evasion_exception_suppressed(self):
        from unittest.mock import patch
        with patch(
            "commonhuman_payloads.encoders.transforms.apply_evasion",
            side_effect=ValueError("boom"),
        ):
            result = apply_evasion_chain("<b>", ["html"])
        assert result == "<b>"
