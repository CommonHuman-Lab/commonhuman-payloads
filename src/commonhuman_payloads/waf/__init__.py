# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""WAF signature data (fingerprints + recommended evasions)."""

from .signatures import WafSignature, SIGNATURES, GENERIC_BLOCK_BODIES
from .detect import WafResult, detect, _inject_param
from .payloads import WAF_EXTRA_PAYLOADS, get_waf_payloads

__all__ = [
    "WafSignature", "SIGNATURES", "GENERIC_BLOCK_BODIES",
    "WafResult", "detect", "_inject_param",
    "WAF_EXTRA_PAYLOADS", "get_waf_payloads",
]
