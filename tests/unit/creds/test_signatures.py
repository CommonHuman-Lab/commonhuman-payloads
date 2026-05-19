# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_payloads.creds.signatures."""

from __future__ import annotations

import tempfile
import os

from commonhuman_payloads.creds.signatures import (
    DUMP_SIGNATURES,
    DumpSignature,
    identify_dump,
    is_dump_file,
)


class TestDumpSignatures:
    def test_non_empty(self):
        assert len(DUMP_SIGNATURES) > 0

    def test_all_are_dump_signature(self):
        for s in DUMP_SIGNATURES:
            assert isinstance(s, DumpSignature)

    def test_has_lsass(self):
        names = [s.name for s in DUMP_SIGNATURES]
        assert "LSASS Minidump" in names

    def test_has_ccache(self):
        types = [s.dump_type for s in DUMP_SIGNATURES]
        assert "ccache" in types

    def test_has_keytab(self):
        types = [s.dump_type for s in DUMP_SIGNATURES]
        assert "keytab" in types

    def test_has_sqlite(self):
        names = [s.name for s in DUMP_SIGNATURES]
        assert any("SQLite" in n for n in names)


class TestIdentifyDump:
    def test_lsass_minidump(self):
        data = b"MDMP" + b"\x00" * 60
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "lsass"

    def test_registry_hive(self):
        data = b"regf" + b"\x00" * 60
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "sam"

    def test_ccache_v4(self):
        data = b"\x05\x04" + b"\x00" * 62
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "ccache"

    def test_ccache_v3(self):
        data = b"\x05\x03" + b"\x00" * 62
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "ccache"

    def test_keytab_v2(self):
        data = b"\x05\x02" + b"\x00" * 62
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "keytab"

    def test_keytab_v1(self):
        data = b"\x05\x01" + b"\x00" * 62
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "keytab"

    def test_sqlite_browser_db(self):
        data = b"SQLite format 3\x00" + b"\x00" * 48
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "browser"

    def test_pkcs12(self):
        data = b"\x30\x82" + b"\x00" * 62
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "certificate"

    def test_java_keystore(self):
        data = b"\xfe\xed\xfe\xed" + b"\x00" * 60
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "keystore"

    def test_ntds_dit_at_offset(self):
        # ESE magic appears at offset 4
        data = b"\x00\x00\x00\x00\xef\xcd\xab\x89" + b"\x00" * 56
        result = identify_dump(data)
        assert result is not None
        assert result.dump_type == "ntds"

    def test_unknown_data_returns_none(self):
        data = b"\xff\xff\xff\xff" + b"\x00" * 60
        result = identify_dump(data)
        assert result is None

    def test_empty_data_returns_none(self):
        assert identify_dump(b"") is None

    def test_too_short_for_offset_magic(self):
        # NTDS magic needs at least 8 bytes — give only 4
        data = b"\x00\x00\x00\x00"
        result = identify_dump(data)
        assert result is None or result.dump_type != "ntds"


class TestIsDumpFile:
    def test_recognises_lsass_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dmp") as f:
            f.write(b"MDMP" + b"\x00" * 60)
            path = f.name
        try:
            result = is_dump_file(path)
            assert result is not None
            assert result.dump_type == "lsass"
        finally:
            os.unlink(path)

    def test_returns_none_for_text_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w") as f:
            f.write("just a text file\n")
            path = f.name
        try:
            assert is_dump_file(path) is None
        finally:
            os.unlink(path)

    def test_returns_none_for_missing_file(self):
        assert is_dump_file("/tmp/definitely_does_not_exist_12345.dmp") is None
