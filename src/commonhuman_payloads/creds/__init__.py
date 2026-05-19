# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
commonhuman-payloads.creds — credential paths, patterns, dump signatures, and hash detection.

Quick start:

    from commonhuman_payloads.creds.paths import ALL_HOME_PATHS, SYSTEM_PATHS, BY_SERVICE
    from commonhuman_payloads.creds.patterns import ALL_PATTERNS, HIGH_CONFIDENCE
    from commonhuman_payloads.creds.signatures import identify_dump, is_dump_file
    from commonhuman_payloads.creds.hashes import identify_hash, is_hash
"""

from .hashes import HashType, HASH_TYPES, identify_hash, is_hash, likely_ntlm
from .paths import (
    CredPath,
    ALL_HOME_PATHS,
    ALL_SYSTEM_PATHS,
    BY_SERVICE,
    INTERESTING_EXTENSIONS,
    INTERESTING_FILENAMES,
)
from .patterns import CredPattern, ALL_PATTERNS, HIGH_CONFIDENCE
from .signatures import DumpSignature, DUMP_SIGNATURES, identify_dump, is_dump_file

__all__ = [
    # hashes
    "HashType",
    "HASH_TYPES",
    "identify_hash",
    "is_hash",
    "likely_ntlm",
    # paths
    "CredPath",
    "ALL_HOME_PATHS",
    "ALL_SYSTEM_PATHS",
    "BY_SERVICE",
    "INTERESTING_EXTENSIONS",
    "INTERESTING_FILENAMES",
    # patterns
    "CredPattern",
    "ALL_PATTERNS",
    "HIGH_CONFIDENCE",
    # signatures
    "DumpSignature",
    "DUMP_SIGNATURES",
    "identify_dump",
    "is_dump_file",
]
