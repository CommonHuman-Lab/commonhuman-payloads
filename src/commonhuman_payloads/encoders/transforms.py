# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""WAF evasion transform functions and strategy constants."""

from __future__ import annotations

import random
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Evasion strategy name constants
# ---------------------------------------------------------------------------

# Generic (apply to both XSS and SQLi payloads)
EVASION_NONE          = "none"
EVASION_CASE_MIXING   = "case_mixing"
EVASION_HTML_ENCODE   = "html_encode"
EVASION_UNICODE       = "unicode_escape"
EVASION_DOUBLE_ENCODE = "double_encode"
EVASION_CHUNKED_TAGS  = "chunked_tags"
EVASION_NULL_BYTE     = "null_byte"
EVASION_NEWLINE       = "newline_inject"
EVASION_COMMENT_BREAK = "comment_break"
EVASION_BACKTICK      = "backtick_attr"

# XSS-specific
# Splits "expression" with a CSS comment to bypass keyword filters
# (e.g. expression(alert(1)) → ex/**/pression(alert(1)))
EVASION_CSS_EXPR      = "css_expression"

# SQLi-specific
EVASION_SQL_COMMENT         = "sql_comment"          # SELECT/**/1  or  SE/**/LECT
EVASION_SQL_WHITESPACE      = "sql_whitespace"        # replace spaces with tabs
EVASION_SQL_CASE            = "sql_case"              # SeLeCt, uNiOn
EVASION_SQL_ENCODE          = "sql_encode"            # URL-encode the payload
EVASION_SQL_MULTILINE       = "sql_multiline"         # replace spaces with /*\n*/ outside strings
EVASION_SQL_VERSIONED       = "sql_versioned"         # /*!50000SELECT*/ versioned MySQL comments
EVASION_SQL_SPACE_DASH      = "sql_space_dash"        # spaces → --rand\n
EVASION_SQL_SPACE_HASH      = "sql_space_hash"        # spaces → #rand\n
EVASION_SQL_SPACE_PLUS      = "sql_space_plus"        # spaces → +
EVASION_SQL_BLANK_CHARS     = "sql_blank_chars"       # spaces → MySQL blank chars (%09/%0b/%0c/%0d)
EVASION_SQL_RANDOM_COMMENTS = "sql_random_comments"   # S/**/E/**/L/**/E/**/C/**/T
EVASION_SQL_EQUALTOLIKE     = "sql_equaltolike"       # = → LIKE
EVASION_SQL_BETWEEN         = "sql_between"           # > N → NOT BETWEEN 0 AND N

ALL_EVASIONS = [
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
]

_SQL_KEYWORDS = (
    "SELECT", "UNION", "WHERE", "AND", "OR", "FROM",
    "INSERT", "UPDATE", "DELETE", "ORDER", "GROUP",
    "HAVING", "LIMIT", "SLEEP", "BENCHMARK", "WAITFOR",
)


def apply_evasion(payload: str, evasion: str) -> str:
    """Apply a WAF evasion transform to *payload* and return the result.

    Unknown strategies return the payload unchanged.
    """
    if evasion == EVASION_NONE:
        return payload

    if evasion == EVASION_CASE_MIXING:
        return _case_mix(payload)

    if evasion == EVASION_HTML_ENCODE:
        return _html_encode_lt_gt(payload)

    if evasion == EVASION_UNICODE:
        return _unicode_escape_alpha(payload)

    if evasion == EVASION_DOUBLE_ENCODE:
        return _double_url_encode(payload)

    if evasion == EVASION_CHUNKED_TAGS:
        return _chunked_tag(payload)

    if evasion == EVASION_NULL_BYTE:
        return _null_byte_inject(payload)

    if evasion == EVASION_NEWLINE:
        return _newline_inject(payload)

    if evasion == EVASION_COMMENT_BREAK:
        return _comment_break(payload)

    if evasion == EVASION_BACKTICK:
        return _backtick_attr(payload)

    if evasion == EVASION_CSS_EXPR:
        return _css_expression_break(payload)

    if evasion == EVASION_SQL_COMMENT:
        return _sql_comment_inject(payload)

    if evasion == EVASION_SQL_WHITESPACE:
        return payload.replace(" ", "\t")

    if evasion == EVASION_SQL_CASE:
        return _sql_rand_case(payload)

    if evasion == EVASION_SQL_ENCODE:
        return urllib.parse.quote(payload, safe="")

    if evasion == EVASION_SQL_MULTILINE:
        return _sql_multiline(payload)

    if evasion == EVASION_SQL_VERSIONED:
        return _sql_versioned(payload)

    if evasion == EVASION_SQL_SPACE_DASH:
        return _sql_space_dash(payload)

    if evasion == EVASION_SQL_SPACE_HASH:
        return _sql_space_hash(payload)

    if evasion == EVASION_SQL_SPACE_PLUS:
        return payload.replace(" ", "+")

    if evasion == EVASION_SQL_BLANK_CHARS:
        return _sql_blank_chars(payload)

    if evasion == EVASION_SQL_RANDOM_COMMENTS:
        return _sql_random_comments(payload)

    if evasion == EVASION_SQL_EQUALTOLIKE:
        return _sql_equaltolike(payload)

    if evasion == EVASION_SQL_BETWEEN:
        return _sql_between(payload)

    return payload


# ---------------------------------------------------------------------------
# Transform implementations
# ---------------------------------------------------------------------------

def _case_mix(s: str) -> str:
    """Alternate upper/lower on alpha chars."""
    result = []
    toggle = True
    for c in s:
        if c.isalpha():
            result.append(c.upper() if toggle else c.lower())
            toggle = not toggle
        else:
            result.append(c)
    return "".join(result)


def _html_encode_lt_gt(s: str) -> str:
    return s.replace("<", "&#60;").replace(">", "&#62;")


def _unicode_escape_alpha(s: str) -> str:
    """Unicode-escape runs of alphabetic characters."""
    def esc(m: re.Match) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in m.group())
    return re.sub(r"[a-zA-Z]{2,}", esc, s)


def _double_url_encode(s: str) -> str:
    """Double URL-encode only angle brackets.

    WAFs that inspect the raw query string before server-side URL decoding are
    fooled because %253c/%253e (double-encoded) don't match the literal ``<``/``>``
    pattern the WAF checks for.  The server then decodes %25 -> % to yield %3c/%3e,
    and the browser/template decodes those to the actual angle brackets.

    Encoding only < and > keeps event-handler names and attribute values functional.
    For SQL payloads, full double-encoding is applied instead.
    """
    if "<" in s or ">" in s:
        return s.replace("<", "%253c").replace(">", "%253e")
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def double_url_encode(s: str) -> str:
    """Full double URL-encoding (for SQL payloads or plain strings)."""
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _chunked_tag(s: str) -> str:
    """Split tag names and break event handler names with /**/."""
    s = re.sub(r"<(script)", r"<\1 ", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(on\w+)\b", lambda m: m.group()[:3] + "/**/" + m.group()[3:], s)
    return s


def _null_byte_inject(s: str) -> str:
    """Insert a null byte after the first < to confuse WAF parsers."""
    return s.replace("<", "<\x00", 1)


def _newline_inject(s: str) -> str:
    """Replace spaces with %0a (URL-encoded newline)."""
    return s.replace(" ", "%0a")


def _comment_break(s: str) -> str:
    """Insert <!--/--> inside HTML tag keywords."""
    return re.sub(r"<(/?)(script|img|svg|iframe|body|details|video|input)",
                  r"<\1\2<!---->", s, flags=re.IGNORECASE)


def _backtick_attr(s: str) -> str:
    """Replace attribute quote chars with backticks (IE legacy trick)."""
    return s.replace('"', "`").replace("'", "`")


def _css_expression_break(s: str) -> str:
    """Break 'expression' with a CSS comment to bypass keyword filters."""
    return re.sub(r"\bexpression\b", "ex/**/pression", s, flags=re.IGNORECASE)


def _sql_comment_inject(s: str) -> str:
    """Wrap SQL keywords with /**/ comments."""
    result = s
    for kw in _SQL_KEYWORDS:
        result = result.replace(kw, f"/**/{kw}/**/")
        result = result.replace(kw.lower(), f"/**/{kw.lower()}/**/")
    return result


def _sql_rand_case(s: str) -> str:
    """Randomly mix the case of alphabetic characters."""
    def _rand(m: re.Match) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in m.group(0)
        )
    return re.sub(r"[A-Za-z]+", _rand, s)


def _sql_multiline(s: str) -> str:
    """Replace spaces outside SQL string literals with /*\\n*/."""
    result_parts: list[str] = []
    in_string = False
    for ch in s:
        if ch == "'" and not in_string:
            in_string = True
            result_parts.append(ch)
        elif ch == "'" and in_string:
            in_string = False
            result_parts.append(ch)
        elif ch == " " and not in_string:
            result_parts.append("/*\n*/")
        else:
            result_parts.append(ch)
    return "".join(result_parts)


def _sql_versioned(s: str) -> str:
    """Wrap SQL keywords in versioned MySQL comments: SELECT → /*!50000SELECT*/"""
    result = s
    for kw in _SQL_KEYWORDS:
        result = re.sub(rf'\b{kw}\b', f'/*!50000{kw}*/', result, flags=re.IGNORECASE)
    return result


def _sql_space_dash(s: str) -> str:
    """Replace spaces with --<random>\\n (space2dash)."""
    import string
    rand = "".join(random.choices(string.ascii_lowercase, k=6))
    return s.replace(" ", f"--{rand}\n")


def _sql_space_hash(s: str) -> str:
    """Replace spaces with #<random>\\n (space2hash)."""
    import string
    rand = "".join(random.choices(string.ascii_lowercase, k=6))
    return s.replace(" ", f"#{rand}\n")


def _sql_blank_chars(s: str) -> str:
    """Replace spaces with a random MySQL-accepted blank character."""
    return s.replace(" ", random.choice(["\t", "%0b", "%0c", "%0d"]))


def _sql_random_comments(s: str) -> str:
    """Insert /**/ between every character of SQL keywords."""
    result = s
    for kw in _SQL_KEYWORDS:
        obfuscated = "/**/".join(kw)
        result = re.sub(rf'\b{kw}\b', obfuscated, result, flags=re.IGNORECASE)
    return result


def _sql_equaltolike(s: str) -> str:
    """Replace standalone = with LIKE (bypasses = operator filters)."""
    return re.sub(r'(?<![!<>])=(?!=)', " LIKE ", s)


def _sql_between(s: str) -> str:
    """Replace > N with NOT BETWEEN 0 AND N (bypasses > operator filters)."""
    return re.sub(r'>(\s*\d+)', r' NOT BETWEEN 0 AND\1', s)


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def case_mix(s: str) -> str:
    """Public alias for _case_mix."""
    return _case_mix(s)


def html_encode(s: str) -> str:
    """HTML-encode a set of special characters (apostrophe, quotes, brackets, etc.)."""
    _html_map = {
        "'": "&#39;",
        '"': "&quot;",
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
        "=": "&#61;",
        "(": "&#40;",
        ")": "&#41;",
        ";": "&#59;",
        "-": "&#45;",
    }
    return "".join(_html_map.get(c, c) for c in s)


def unicode_escape(s: str) -> str:
    """\\uXXXX-escape every alphabetic character."""
    return "".join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in s)
