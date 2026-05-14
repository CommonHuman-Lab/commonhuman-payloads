# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""WAF evasion transforms and strategy constants."""

from .transforms import (
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
    EVASION_SQL_COMMENT,
    EVASION_SQL_WHITESPACE,
    EVASION_SQL_CASE,
    EVASION_SQL_ENCODE,
    EVASION_SQL_MULTILINE,
    ALL_EVASIONS,
    # Functions
    apply_evasion,
    double_url_encode,
    case_mix,
    html_encode,
    unicode_escape,
)

__all__ = [
    "EVASION_NONE",
    "EVASION_CASE_MIXING",
    "EVASION_HTML_ENCODE",
    "EVASION_UNICODE",
    "EVASION_DOUBLE_ENCODE",
    "EVASION_CHUNKED_TAGS",
    "EVASION_NULL_BYTE",
    "EVASION_NEWLINE",
    "EVASION_COMMENT_BREAK",
    "EVASION_BACKTICK",
    "EVASION_CSS_EXPR",
    "EVASION_SQL_COMMENT",
    "EVASION_SQL_WHITESPACE",
    "EVASION_SQL_CASE",
    "EVASION_SQL_ENCODE",
    "EVASION_SQL_MULTILINE",
    "ALL_EVASIONS",
    "apply_evasion",
    "double_url_encode",
    "case_mix",
    "html_encode",
    "unicode_escape",
]
