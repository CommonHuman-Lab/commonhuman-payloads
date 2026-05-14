# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""XSS payload collections — HTML contexts, script contexts, and advanced vectors."""

from __future__ import annotations

from typing import List

from .html import (
    HTML_BODY, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_NAME,
    TAG_NAME, TEXTAREA, TITLE, NOSCRIPT, IFRAME_SRCDOC, OBJECT_DATA,
    COMMENT, CSS, CSS_VALUE,
)
from .script import (
    SCRIPT_STRING_D, SCRIPT_STRING_S, SCRIPT_BARE, SCRIPT_TEMPLATE,
    SCRIPT_REGEX, SCRIPT_COMMENT, EVENT_HANDLER, URL_ATTR, SCRIPT_SRC,
)
from .advanced import (
    ANGULAR_TEMPLATE, ANGULAR_TEMPLATE_ALT, ANGULAR_ATTR,
    VUE_TEMPLATE, JS_HOISTING, DANGLING_MARKUP,
    CSS_TRANSITION, EXTRA_NO_INTERACTION,
    FILE_UPLOAD, RESTRICTED_CHARS, POLYGLOT,
    WAF_BYPASS_DOUBLE_ENCODE, WAF_BYPASS_GLOBAL,
    PROTOTYPE_POLLUTION, CLASSIC_LEGACY, ENCODING,
    MODERN_BROWSER, STORED_XSS, UNICODE_CASE_BYPASS, UNICODE_LINE_SEP,
    DOM_CLOBBERING, REPLACE_PATTERN, RADIX_OBFUSCATION, UNICODE_URL,
    CONTENT_TYPE, SANITIZER_BYPASS, CSP_INJECTION,
)

__all__ = [
    # html
    "HTML_BODY", "ATTR_DOUBLE", "ATTR_SINGLE", "ATTR_UNQUOTED", "ATTR_NAME",
    "TAG_NAME", "TEXTAREA", "TITLE", "NOSCRIPT", "IFRAME_SRCDOC", "OBJECT_DATA",
    "COMMENT", "CSS", "CSS_VALUE",
    # script
    "SCRIPT_STRING_D", "SCRIPT_STRING_S", "SCRIPT_BARE", "SCRIPT_TEMPLATE",
    "SCRIPT_REGEX", "SCRIPT_COMMENT", "EVENT_HANDLER", "URL_ATTR", "SCRIPT_SRC",
    # advanced
    "ANGULAR_TEMPLATE", "ANGULAR_TEMPLATE_ALT", "ANGULAR_ATTR",
    "VUE_TEMPLATE", "JS_HOISTING", "DANGLING_MARKUP",
    "CSS_TRANSITION", "EXTRA_NO_INTERACTION",
    "FILE_UPLOAD", "RESTRICTED_CHARS", "POLYGLOT",
    "WAF_BYPASS_DOUBLE_ENCODE", "WAF_BYPASS_GLOBAL",
    "PROTOTYPE_POLLUTION", "CLASSIC_LEGACY", "ENCODING",
    "MODERN_BROWSER", "STORED_XSS", "UNICODE_CASE_BYPASS", "UNICODE_LINE_SEP",
    "DOM_CLOBBERING", "REPLACE_PATTERN", "RADIX_OBFUSCATION", "UNICODE_URL",
    "CONTENT_TYPE", "SANITIZER_BYPASS", "CSP_INJECTION",
    # functions
    "get_basic_payloads",
    "get_payloads_for_context",
]


def get_basic_payloads(marker: str = "{marker}") -> List[str]:
    """Return a small cross-context set of payloads for quick probing.

    Uses the first 3 entries from each primary context.  Substitute *marker*
    into the ``{marker}`` placeholder before injecting.
    """
    base = HTML_BODY[:3] + ATTR_DOUBLE[:2] + ATTR_SINGLE[:2] + SCRIPT_STRING_D[:2]
    return [p.replace("{marker}", marker) for p in base]


_CONTEXT_LISTS = {
    "html_body":       HTML_BODY,
    "attr_double":     ATTR_DOUBLE,
    "attr_single":     ATTR_SINGLE,
    "attr_unquoted":   ATTR_UNQUOTED,
    "attr_name":       ATTR_NAME,
    "tag_name":        TAG_NAME,
    "textarea":        TEXTAREA,
    "title":           TITLE,
    "noscript":        NOSCRIPT,
    "iframe_srcdoc":   IFRAME_SRCDOC,
    "object_data":     OBJECT_DATA,
    "comment":         COMMENT,
    "css":             CSS,
    "css_value":       CSS_VALUE,
    "script_string_d": SCRIPT_STRING_D,
    "script_string_s": SCRIPT_STRING_S,
    "script_bare":     SCRIPT_BARE,
    "script_template": SCRIPT_TEMPLATE,
    "script_regex":    SCRIPT_REGEX,
    "script_comment":  SCRIPT_COMMENT,
    "event_handler":   EVENT_HANDLER,
    "url_attr":        URL_ATTR,
    "script_src":      SCRIPT_SRC,
    "angular_template":     ANGULAR_TEMPLATE,
    "angular_template_alt": ANGULAR_TEMPLATE_ALT,
    "angular_attr":    ANGULAR_ATTR,
    "vue_template":    VUE_TEMPLATE,
    "js_hoisting":     JS_HOISTING,
    "dangling_markup": DANGLING_MARKUP,
    "polyglot":        POLYGLOT,
}


def get_payloads_for_context(context: str, marker: str = "{marker}") -> List[str]:
    """Return payloads for *context* with ``{marker}`` substituted.

    *context* is a lowercase string matching one of the keys in the internal
    context map (e.g. ``"html_body"``, ``"attr_double"``, ``"script_bare"``).
    Unknown contexts fall back to ``HTML_BODY``.
    """
    raw = _CONTEXT_LISTS.get(context, HTML_BODY)
    return [p.replace("{marker}", marker) for p in raw]
