# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Marker generation helpers shared across scanners."""

from __future__ import annotations

import random
import string

_DEFAULT_PREFIX = "CHPayload_"


def make_marker(prefix: str = _DEFAULT_PREFIX, length: int = 6) -> str:
    """Return a random scan marker string.

    Tools should pass their own prefix (e.g. ``"StingXSS_"``) to keep markers
    namespaced per-tool and easy to grep in logs.
    """
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}{suffix}"


def is_reflected(marker: str, body: str) -> bool:
    """Return True if *marker* appears verbatim in *body*."""
    return marker in body
