# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
import re
import commonhuman_payloads


def test_version_string():
    assert isinstance(commonhuman_payloads.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", commonhuman_payloads.__version__)


def test_payload_version_string():
    assert isinstance(commonhuman_payloads.PAYLOAD_VERSION, str)
    assert re.match(r"^\d{4}\.\d{2}$", commonhuman_payloads.PAYLOAD_VERSION), (
        "PAYLOAD_VERSION must be YYYY.MM format"
    )


def test_all_exports():
    assert "__version__" in commonhuman_payloads.__all__
    assert "PAYLOAD_VERSION" in commonhuman_payloads.__all__
