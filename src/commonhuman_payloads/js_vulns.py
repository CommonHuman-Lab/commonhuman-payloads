# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Comprehensive vulnerable JavaScript library database.

Each entry describes a library with known XSS or code-execution CVEs,
how to detect it from a script src URL or inline content, and how to
determine whether the detected version falls in the vulnerable range.

Designed to be shared across all CommonHuman-Lab scanner tools.

Usage::

    from commonhuman_payloads.js_vulns import KNOWN_VULNERABLE_LIBS, LibSpec

    for spec in KNOWN_VULNERABLE_LIBS:
        # check spec.vuln_if(detected_version_tuple)
        ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Tuple


# ---------------------------------------------------------------------------
# Version comparison helper
# ---------------------------------------------------------------------------

def _ver(v: str) -> Tuple[int, ...]:
    """Parse a dotted version string into a comparable integer tuple."""
    try:
        parts = tuple(int(x) for x in re.split(r"[.\-]", v) if x.isdigit())
        return parts if parts else (0,)
    except (ValueError, TypeError):
        return (0,)


# ---------------------------------------------------------------------------
# LibSpec dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LibSpec:
    """Specification for a vulnerable JavaScript library."""
    library_id:   str
    display_name: str
    url_patterns: Tuple[str, ...]   # regexes matched against <script src> URL
    ver_regex:    str               # regex to extract version from URL or source
    inline_fp:    str               # unique fingerprint string in library source
    vuln_if:      Any  # Callable[[Tuple[int, ...]], bool]
    cve:          str               # CVE ID(s) or tracker URL
    advisory:     str               # human-readable advice


# ---------------------------------------------------------------------------
# Vulnerable library table
# ---------------------------------------------------------------------------

KNOWN_VULNERABLE_LIBS: List[LibSpec] = [

    # jQuery < 1.9.0 — DOM-based XSS via selector parsing
    LibSpec(
        library_id   = "jquery",
        display_name = "jQuery",
        url_patterns = (
            r"jquery[._\-](\d+\.\d+(?:\.\d+)*)",
            r"jquery/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"jquery\s+(?:javascript\s+library\s+)?v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "jQuery JavaScript Library",
        vuln_if      = lambda v: len(v) >= 2 and v[0] == 1 and v[1] < 9,
        cve          = "https://bugs.jquery.com/ticket/11290",
        advisory     = (
            "jQuery < 1.9.0: DOM-based XSS via malformed CSS selectors — "
            "$('<img onerror=...>') executes HTML. Upgrade to 1.9.0+, 2.x, or 3.x."
        ),
    ),

    # jQuery 1.x/2.x/3.x < 3.5.0 — XSS via $.htmlPrefilter
    LibSpec(
        library_id   = "jquery-xss-htmlprefilter",
        display_name = "jQuery (htmlPrefilter XSS)",
        url_patterns = (
            r"jquery[._\-](\d+\.\d+(?:\.\d+)*)",
            r"jquery/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"jquery\s+(?:javascript\s+library\s+)?v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "jQuery JavaScript Library",
        vuln_if      = lambda v: (
            (len(v) >= 2 and v[0] == 1) or
            (len(v) >= 2 and v[0] == 2) or
            (len(v) >= 2 and v[0] == 3 and (v[1] < 5 or (v[1] == 5 and len(v) >= 3 and v[2] == 0)))
        ),
        cve          = "CVE-2020-11022, CVE-2020-11023",
        advisory     = (
            "jQuery < 3.5.0: XSS via $.htmlPrefilter — passing HTML from "
            "untrusted sources to jQuery DOM manipulation methods leads to "
            "code execution. Upgrade to 3.5.0+."
        ),
    ),

    # AngularJS < 1.8.0 — sandbox escape / template injection
    LibSpec(
        library_id   = "angularjs",
        display_name = "AngularJS",
        url_patterns = (
            r"angular(?:js)?[._\-](\d+\.\d+(?:\.\d+)*)",
            r"angular/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"angularjs\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "AngularJS v",
        vuln_if      = lambda v: len(v) >= 2 and v[0] == 1 and v[1] < 8,
        cve          = "CVE-2019-10768, CVE-2020-7676",
        advisory     = (
            "AngularJS < 1.8.0: multiple sandbox-escape / CSTI vulnerabilities "
            "allow arbitrary JS execution via template expressions. "
            "Migrate to Angular 2+ or upgrade to 1.8.x."
        ),
    ),

    # Bootstrap < 3.4.0 — XSS via data-template attribute (tooltip/popover)
    LibSpec(
        library_id   = "bootstrap-xss-tooltip",
        display_name = "Bootstrap (tooltip/popover XSS)",
        url_patterns = (
            r"bootstrap[._\-](\d+\.\d+(?:\.\d+)*)",
            r"bootstrap/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"bootstrap\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "Bootstrap v",
        vuln_if      = lambda v: len(v) >= 2 and v[0] == 3 and v[1] < 4,
        cve          = "CVE-2019-8331",
        advisory     = (
            "Bootstrap 3 < 3.4.0: XSS via data-template attribute in tooltip "
            "and popover plugins. Upgrade to 3.4.0+ or 4.x."
        ),
    ),

    # Bootstrap < 4.3.1 — XSS via data-template
    LibSpec(
        library_id   = "bootstrap4-xss-tooltip",
        display_name = "Bootstrap 4 (tooltip/popover XSS)",
        url_patterns = (
            r"bootstrap[._\-](\d+\.\d+(?:\.\d+)*)",
            r"bootstrap/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"bootstrap\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "Bootstrap v",
        vuln_if      = lambda v: (
            len(v) >= 2 and v[0] == 4 and
            (v[1] < 3 or (v[1] == 3 and len(v) >= 3 and v[2] < 1))
        ),
        cve          = "CVE-2019-8331",
        advisory     = (
            "Bootstrap 4 < 4.3.1: XSS via data-template attribute. "
            "Upgrade to 4.3.1+."
        ),
    ),

    # Lodash < 4.17.21 — prototype pollution → potential RCE / XSS
    LibSpec(
        library_id   = "lodash-prototype-pollution",
        display_name = "Lodash (prototype pollution)",
        url_patterns = (
            r"lodash(?:\.min)?[._\-](\d+\.\d+(?:\.\d+)*)",
            r"lodash/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"lodash\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "lodash",
        vuln_if      = lambda v: (
            len(v) >= 3 and (
                v[0] < 4 or
                (v[0] == 4 and v[1] < 17) or
                (v[0] == 4 and v[1] == 17 and v[2] < 21)
            )
        ),
        cve          = "CVE-2021-23337, CVE-2020-8203",
        advisory     = (
            "Lodash < 4.17.21: prototype pollution via _.merge(), _.set(), _.zipObjectDeep(). "
            "Can lead to denial-of-service or XSS through polluted Object.prototype properties. "
            "Upgrade to 4.17.21+."
        ),
    ),

    # Moment.js < 2.29.2 — ReDoS
    LibSpec(
        library_id   = "momentjs-redos",
        display_name = "Moment.js (ReDoS)",
        url_patterns = (
            r"moment[._\-](\d+\.\d+(?:\.\d+)*)",
            r"moment/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"moment\.js\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "moment.js",
        vuln_if      = lambda v: (
            len(v) >= 3 and (
                v[0] < 2 or
                (v[0] == 2 and v[1] < 29) or
                (v[0] == 2 and v[1] == 29 and v[2] < 2)
            )
        ),
        cve          = "CVE-2022-24785",
        advisory     = (
            "Moment.js < 2.29.2: ReDoS via crafted locale strings. "
            "Upgrade to 2.29.2+. Consider migrating to date-fns or Luxon."
        ),
    ),

    # Vue.js < 2.6.13 — XSS via v-bind
    LibSpec(
        library_id   = "vuejs-xss",
        display_name = "Vue.js (XSS)",
        url_patterns = (
            r"vue(?:\.min)?[._\-](\d+\.\d+(?:\.\d+)*)",
            r"vue/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"vue(?:\.js)?\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "Vue.js v",
        vuln_if      = lambda v: (
            len(v) >= 2 and v[0] == 2 and (
                v[1] < 6 or (v[1] == 6 and len(v) >= 3 and v[2] < 13)
            )
        ),
        cve          = "CVE-2021-22960",
        advisory     = (
            "Vue.js 2 < 2.6.13: server-side rendering XSS via v-bind attribute injection. "
            "Upgrade to 2.6.13+."
        ),
    ),

    # Handlebars < 4.7.7 — prototype pollution
    LibSpec(
        library_id   = "handlebars-prototype-pollution",
        display_name = "Handlebars (prototype pollution)",
        url_patterns = (
            r"handlebars[._\-](\d+\.\d+(?:\.\d+)*)",
            r"handlebars/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"handlebars\s+v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "Handlebars",
        vuln_if      = lambda v: (
            len(v) >= 3 and (
                v[0] < 4 or
                (v[0] == 4 and v[1] < 7) or
                (v[0] == 4 and v[1] == 7 and v[2] < 7)
            )
        ),
        cve          = "CVE-2021-23369, CVE-2019-19919",
        advisory     = (
            "Handlebars < 4.7.7: prototype pollution and RCE via template injection. "
            "Upgrade to 4.7.7+."
        ),
    ),

    # DOMPurify < 2.3.6 — mXSS bypass
    LibSpec(
        library_id   = "dompurify-mxss",
        display_name = "DOMPurify (mXSS bypass)",
        url_patterns = (
            r"dompurify[._\-](\d+\.\d+(?:\.\d+)*)",
            r"DOMPurify[._\-](\d+\.\d+(?:\.\d+)*)",
        ),
        ver_regex    = r"dompurify\s+(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "DOMPurify",
        vuln_if      = lambda v: (
            len(v) >= 3 and (
                v[0] < 2 or
                (v[0] == 2 and v[1] < 3) or
                (v[0] == 2 and v[1] == 3 and v[2] < 6)
            )
        ),
        cve          = "CVE-2022-37434",
        advisory     = (
            "DOMPurify < 2.3.6: mutation-based XSS (mXSS) bypass via "
            "namespace confusion. Upgrade to 2.3.6+."
        ),
    ),

    # Underscore.js < 1.13.0 — arbitrary code execution via template
    LibSpec(
        library_id   = "underscore-template-rce",
        display_name = "Underscore.js (template RCE)",
        url_patterns = (
            r"underscore[._\-](\d+\.\d+(?:\.\d+)*)",
            r"underscore/(\d+\.\d+(?:\.\d+)*)/",
        ),
        ver_regex    = r"underscore\.js\s+(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "Underscore.js",
        vuln_if      = lambda v: (
            len(v) >= 3 and (
                v[0] < 1 or
                (v[0] == 1 and v[1] < 13)
            )
        ),
        cve          = "CVE-2021-23358",
        advisory     = (
            "Underscore.js < 1.13.0: arbitrary code execution via template function "
            "when processing user-controlled templates. Upgrade to 1.13.0+."
        ),
    ),
]
