# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Shared marker utilities for injection-detection tools."""

from __future__ import annotations

import random
import string

_DEFAULT_PREFIX = "CH_"


def make_marker(prefix: str = _DEFAULT_PREFIX, length: int = 6) -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}{suffix}"


def is_reflected(marker: str, body: str) -> bool:
    return marker in body
