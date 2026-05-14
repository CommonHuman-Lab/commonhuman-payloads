# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Shared fixtures for commonhuman-payloads test suite."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# HTTP response factory
# ---------------------------------------------------------------------------

def _make_response(
    status_code: int = 200,
    text: str = "OK",
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    """Return a mock HTTP response with .status_code, .text, .headers."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


@pytest.fixture
def make_response():
    """Factory fixture: make_response(status=200, text='', headers={})."""
    return _make_response


@pytest.fixture
def clean_response():
    """A clean 200 with no WAF signals."""
    return _make_response(200, "<html>Hello</html>")


@pytest.fixture
def cloudflare_response():
    """A Cloudflare-blocked 403."""
    return _make_response(
        403,
        "Error 1020 cloudflare cf-ray blocked",
        {"server": "cloudflare", "cf-ray": "abc123"},
    )


@pytest.fixture
def generic_block_response():
    """A generic WAF hard 403 with no WAF-specific headers."""
    return _make_response(403, "Forbidden")


@pytest.fixture
def inline_block_response():
    """A 200 response whose body contains a generic block phrase."""
    return _make_response(200, "Access Denied — your request was blocked.")


# ---------------------------------------------------------------------------
# Callable get_fn factories
# ---------------------------------------------------------------------------

@pytest.fixture
def make_get_fn(make_response):
    """
    Returns a factory that builds a get_fn callable.

    Usage::

        get_fn = make_get_fn(resp)              # always returns resp
        get_fn = make_get_fn([resp1, resp2])    # returns resp1 first, resp2 next
    """
    def _factory(responses):
        if not isinstance(responses, list):
            responses = [responses]
        responses = list(responses)

        def _get(url: str):
            if len(responses) == 1:
                return responses[0]
            return responses.pop(0)

        return _get
    return _factory


@pytest.fixture
def raising_get_fn():
    """A get_fn that always raises a connection error."""
    def _get(url: str):
        raise OSError("connection refused")
    return _get
