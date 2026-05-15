# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""WAF detection logic — probe, score, fingerprint.

Tools call detect() by passing their injector's .get method and their own
probe payload:

    from commonhuman_payloads.waf import detect, WafResult

    result = detect(injector.get, url, param,
                    probe_payload="<script>alert(1)</script>",
                    check_reflection=True)
"""

from __future__ import annotations

import re
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from .signatures import SIGNATURES, GENERIC_BLOCK_BODIES
from ..encoders.transforms import (
    EVASION_NONE,
    EVASION_CASE_MIXING,
    EVASION_HTML_ENCODE,
    EVASION_UNICODE,
    EVASION_DOUBLE_ENCODE,
    EVASION_COMMENT_BREAK,
    EVASION_SQL_COMMENT,
    EVASION_SQL_CASE,
    EVASION_SQL_VERSIONED,
    EVASION_SQL_SPACE_DASH,
    EVASION_SQL_BLANK_CHARS,
    EVASION_SQL_RANDOM_COMMENTS,
    EVASION_SQL_EQUALTOLIKE,
)


@dataclass
class WafResult:
    detected:   bool
    name:       Optional[str]
    evasions:   List[str]
    confidence: str  # "high" | "medium" | "low" | "none"


def detect(
    get_fn:           Callable[[str], Any],
    url:              str,
    param:            Optional[str] = None,
    probe_payload:    str = "<script>alert(1)</script>",
    check_reflection: bool = True,
) -> WafResult:
    """Probe the target and fingerprint the WAF from the response.

    get_fn:           callable(url) → response with .status_code, .text, .headers
    url:              target URL
    param:            inject as this GET parameter value; if None, appends ?q=payload
    probe_payload:    tool-specific probe (XSS payload for stingxss, SQLi for breachsql)
    check_reflection: return "no WAF" immediately when probe reflects with a 2xx response;
                      set False for SQLi probes where reflection isn't meaningful
    """
    try:
        if param:
            probe_url = _inject_param(url, param, probe_payload)
        else:
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}q={up.quote(probe_payload)}"
        resp = get_fn(probe_url)
    except Exception:
        return WafResult(detected=False, name=None, evasions=[EVASION_NONE], confidence="none")

    if check_reflection and resp.status_code < 400 and probe_payload.lower() in resp.text.lower():
        return WafResult(detected=False, name=None, evasions=[EVASION_NONE], confidence="none")

    headers_lower: dict[str, str] = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body = resp.text

    best_match = None
    best_score = 0

    for sig in SIGNATURES:
        score = 0
        for hdr, pattern in sig.header_clues:
            val = headers_lower.get(hdr, "")
            if val and re.search(pattern, val, re.IGNORECASE):
                score += 2
        for pattern in sig.body_clues:
            if re.search(pattern, body, re.IGNORECASE):
                score += 1
        if resp.status_code in sig.status_codes:
            score += 1
        if score > best_score:
            best_score = score
            best_match = sig

    if best_match and best_score >= 2:
        confidence = "high" if best_score >= 4 else "medium"
        return WafResult(
            detected=True,
            name=best_match.name,
            evasions=best_match.evasions,
            confidence=confidence,
        )

    _body_blocked = any(re.search(p, body, re.IGNORECASE) for p in GENERIC_BLOCK_BODIES)
    if resp.status_code in (403, 406, 429, 503) or _body_blocked:
        if _body_blocked and resp.status_code < 400:
            return WafResult(
                detected=True,
                name="Generic WAF (inline body block — double-encode bypass likely)",
                evasions=[
                    EVASION_DOUBLE_ENCODE, EVASION_SQL_VERSIONED, EVASION_SQL_COMMENT,
                    EVASION_SQL_CASE, EVASION_CASE_MIXING, EVASION_HTML_ENCODE,
                    EVASION_SQL_RANDOM_COMMENTS, EVASION_SQL_BLANK_CHARS,
                ],
                confidence="medium",
            )
        # Hard block (4xx): fire a double-encoded probe — if it bypasses, the WAF
        # inspects the raw URL before decoding.
        try:
            double_enc = up.quote(up.quote(probe_payload, safe=""), safe="")
            if param:
                de_url = _inject_param(url, param, double_enc)
            else:
                sep = "&" if "?" in url else "?"
                de_url = f"{url}{sep}q={double_enc}"
            de_resp = get_fn(de_url)
            _de_blocked = any(re.search(p, de_resp.text, re.IGNORECASE) for p in GENERIC_BLOCK_BODIES)
            if de_resp.status_code < 400 and not _de_blocked:
                return WafResult(
                    detected=True,
                    name="Generic WAF (double-encode bypass)",
                    evasions=[
                        EVASION_DOUBLE_ENCODE, EVASION_SQL_VERSIONED, EVASION_SQL_COMMENT,
                        EVASION_SQL_CASE, EVASION_CASE_MIXING, EVASION_HTML_ENCODE,
                    ],
                    confidence="medium",
                )
        except Exception:
            pass
        return WafResult(
            detected=True,
            name="Generic WAF",
            evasions=[
                EVASION_SQL_VERSIONED, EVASION_SQL_COMMENT, EVASION_SQL_CASE,
                EVASION_SQL_RANDOM_COMMENTS, EVASION_SQL_SPACE_DASH,
                EVASION_SQL_BLANK_CHARS, EVASION_SQL_EQUALTOLIKE,
                EVASION_CASE_MIXING, EVASION_HTML_ENCODE,
                EVASION_UNICODE, EVASION_COMMENT_BREAK,
            ],
            confidence="low",
        )

    return WafResult(detected=False, name=None, evasions=[EVASION_NONE], confidence="none")


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace the value of *param* in the URL query string with *value*."""
    parsed = up.urlparse(url)
    qs = up.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = up.urlencode(qs, doseq=True)
    return up.urlunparse(parsed._replace(query=new_qs))
