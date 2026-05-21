# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
commonhuman-payloads — shared payload collections, encoders, and WAF signatures.

Quick start:

    from commonhuman_payloads.xss import get_basic_payloads, get_payloads_for_context
    from commonhuman_payloads.sqli import get_error_payloads, get_boolean_pairs
    from commonhuman_payloads.encoders import apply_evasion, EVASION_DOUBLE_ENCODE
    from commonhuman_payloads.waf import SIGNATURES, GENERIC_BLOCK_BODIES, get_waf_payloads
    from commonhuman_payloads.js_vulns import KNOWN_VULNERABLE_LIBS, LibSpec
"""

__version__ = "0.1.5"

__all__ = ["__version__"]
