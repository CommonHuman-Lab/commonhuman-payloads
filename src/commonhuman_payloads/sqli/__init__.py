# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""SQL injection payload collections."""

from .error import ERROR_PAYLOADS, DB_ERROR_PATTERNS, get_error_payloads
from .boolean import BOOLEAN_PAIRS, BOOLEAN_PAIRS_RISK2, get_boolean_pairs
from .time_based import TIME_PAYLOADS, get_time_payloads
from .union import (
    CONCAT_PAYLOADS, SUBSTRING_PROBES,
    make_marker, get_concat_payloads, get_substring_probes,
    make_substring_payload, order_by_probes, union_null_probes,
)
from .oob import OOB_PAYLOADS, get_oob_payloads
from .advanced import (
    DB_CONTENTS_PAYLOADS, STACKED_PAYLOADS, DIOS_PAYLOADS,
    LFI_PAYLOADS, PRIVESC_PAYLOADS, ENUM_PAYLOADS, EXTRACTION_TARGETS,
    get_db_contents_payloads, get_stacked_payloads,
    get_dios_payloads, get_lfi_payloads, get_privesc_payloads, get_enum_payloads,
    get_extraction_targets,
)

__all__ = [
    "ERROR_PAYLOADS", "DB_ERROR_PATTERNS", "get_error_payloads",
    "BOOLEAN_PAIRS", "BOOLEAN_PAIRS_RISK2", "get_boolean_pairs",
    "TIME_PAYLOADS", "get_time_payloads",
    "CONCAT_PAYLOADS", "SUBSTRING_PROBES",
    "make_marker", "get_concat_payloads", "get_substring_probes",
    "make_substring_payload", "order_by_probes", "union_null_probes",
    "OOB_PAYLOADS", "get_oob_payloads",
    "DB_CONTENTS_PAYLOADS", "STACKED_PAYLOADS", "DIOS_PAYLOADS",
    "LFI_PAYLOADS", "PRIVESC_PAYLOADS", "ENUM_PAYLOADS",
    "get_db_contents_payloads", "get_stacked_payloads",
    "get_dios_payloads", "get_lfi_payloads", "get_privesc_payloads", "get_enum_payloads",
    "EXTRACTION_TARGETS", "get_extraction_targets",
]
