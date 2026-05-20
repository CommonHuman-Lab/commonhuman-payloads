# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
commonhuman-payloads — shared payload collections, encoders, WAF signatures, and credential data.

Quick start:

    from commonhuman_payloads.xss import get_basic_payloads, get_payloads_for_context
    from commonhuman_payloads.sqli import get_error_payloads, get_boolean_pairs
    from commonhuman_payloads.encoders import apply_evasion, EVASION_DOUBLE_ENCODE
    from commonhuman_payloads.waf import SIGNATURES, GENERIC_BLOCK_BODIES, get_waf_payloads
    from commonhuman_payloads.js_vulns import KNOWN_VULNERABLE_LIBS, LibSpec
    from commonhuman_payloads.creds.paths import ALL_HOME_PATHS, BY_SERVICE
    from commonhuman_payloads.creds.patterns import ALL_PATTERNS, HIGH_CONFIDENCE
    from commonhuman_payloads.creds.signatures import identify_dump, is_dump_file
    from commonhuman_payloads.creds.hashes import identify_hash, is_hash
"""

__version__ = "0.1.3"

__all__ = ["__version__"]
