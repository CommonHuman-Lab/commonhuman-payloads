# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_payloads.js_vulns."""

from __future__ import annotations

import pytest

from commonhuman_payloads.js_vulns import (
    KNOWN_VULNERABLE_LIBS,
    LibSpec,
    _ver,
)


# ---------------------------------------------------------------------------
# _ver — version string parser
# ---------------------------------------------------------------------------

class TestVer:
    def test_simple_three_part(self):
        assert _ver("1.2.3") == (1, 2, 3)

    def test_two_part(self):
        assert _ver("2.6") == (2, 6)

    def test_with_dash(self):
        assert _ver("1.2-3") == (1, 2, 3)

    def test_empty_string_returns_zero(self):
        assert _ver("") == (0,)

    def test_non_numeric_returns_zero(self):
        assert _ver("x.y.z") == (0,)

    def test_mixed_numeric(self):
        assert _ver("3.5.0-beta.1") == (3, 5, 0, 1)

    def test_version_with_leading_v(self):
        # 'v' is not a digit so _ver strips it; "v1" fails isdigit, rest parses
        result = _ver("v1.9.0")
        assert isinstance(result, tuple)

    def test_none_returns_zero(self):
        assert _ver(None) == (0,)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# LibSpec dataclass
# ---------------------------------------------------------------------------

class TestLibSpec:
    def _sample(self) -> LibSpec:
        return KNOWN_VULNERABLE_LIBS[0]

    def test_has_library_id(self):
        s = self._sample()
        assert isinstance(s.library_id, str) and s.library_id

    def test_has_display_name(self):
        s = self._sample()
        assert isinstance(s.display_name, str) and s.display_name

    def test_url_patterns_is_tuple(self):
        s = self._sample()
        assert isinstance(s.url_patterns, tuple)
        assert len(s.url_patterns) >= 1

    def test_ver_regex_is_str(self):
        s = self._sample()
        assert isinstance(s.ver_regex, str)

    def test_inline_fp_is_str(self):
        s = self._sample()
        assert isinstance(s.inline_fp, str)

    def test_vuln_if_is_callable(self):
        s = self._sample()
        assert callable(s.vuln_if)

    def test_cve_is_str(self):
        s = self._sample()
        assert isinstance(s.cve, str)

    def test_advisory_is_str(self):
        s = self._sample()
        assert isinstance(s.advisory, str)

    def test_is_frozen(self):
        s = self._sample()
        with pytest.raises((AttributeError, TypeError)):
            s.library_id = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# KNOWN_VULNERABLE_LIBS table
# ---------------------------------------------------------------------------

class TestKnownVulnerableLibs:
    def test_at_least_ten_entries(self):
        assert len(KNOWN_VULNERABLE_LIBS) >= 10

    def test_all_entries_are_libspec(self):
        for spec in KNOWN_VULNERABLE_LIBS:
            assert isinstance(spec, LibSpec)

    def test_all_library_ids_unique(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert len(ids) == len(set(ids))

    def test_jquery_present(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert any("jquery" in i for i in ids)

    def test_angularjs_present(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert "angularjs" in ids

    def test_lodash_present(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert any("lodash" in i for i in ids)

    def test_bootstrap_present(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert any("bootstrap" in i for i in ids)

    def test_dompurify_present(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert any("dompurify" in i for i in ids)


# ---------------------------------------------------------------------------
# vuln_if — version range checks
# ---------------------------------------------------------------------------

class TestJqueryVulnIf:
    """jQuery < 1.9.0 — DOM XSS via selector parsing."""

    def _spec(self) -> LibSpec:
        return next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "jquery")

    def test_vuln_1_8_3(self):
        assert self._spec().vuln_if(_ver("1.8.3")) is True

    def test_vuln_1_0_0(self):
        assert self._spec().vuln_if(_ver("1.0.0")) is True

    def test_not_vuln_1_9_0(self):
        assert self._spec().vuln_if(_ver("1.9.0")) is False

    def test_not_vuln_2_0_0(self):
        assert self._spec().vuln_if(_ver("2.0.0")) is False

    def test_not_vuln_3_6_0(self):
        assert self._spec().vuln_if(_ver("3.6.0")) is False


class TestJqueryHtmlprefilterVulnIf:
    """jQuery < 3.5.0 — XSS via $.htmlPrefilter."""

    def _spec(self) -> LibSpec:
        return next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "jquery-xss-htmlprefilter")

    def test_vuln_1_x(self):
        assert self._spec().vuln_if(_ver("1.12.4")) is True

    def test_vuln_2_x(self):
        assert self._spec().vuln_if(_ver("2.2.4")) is True

    def test_vuln_3_4_1(self):
        assert self._spec().vuln_if(_ver("3.4.1")) is True

    def test_not_vuln_3_5_1(self):
        assert self._spec().vuln_if(_ver("3.5.1")) is False

    def test_not_vuln_3_6_0(self):
        assert self._spec().vuln_if(_ver("3.6.0")) is False


class TestAngularJsVulnIf:
    """AngularJS < 1.8.0 — sandbox escape."""

    def _spec(self) -> LibSpec:
        return next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "angularjs")

    def test_vuln_1_7_9(self):
        assert self._spec().vuln_if(_ver("1.7.9")) is True

    def test_not_vuln_1_8_0(self):
        assert self._spec().vuln_if(_ver("1.8.0")) is False

    def test_not_vuln_1_8_3(self):
        assert self._spec().vuln_if(_ver("1.8.3")) is False


class TestLodashVulnIf:
    """Lodash < 4.17.21 — prototype pollution."""

    def _spec(self) -> LibSpec:
        return next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "lodash-prototype-pollution")

    def test_vuln_4_17_20(self):
        assert self._spec().vuln_if(_ver("4.17.20")) is True

    def test_vuln_3_0_0(self):
        assert self._spec().vuln_if(_ver("3.0.0")) is True

    def test_not_vuln_4_17_21(self):
        assert self._spec().vuln_if(_ver("4.17.21")) is False

    def test_not_vuln_4_18_0(self):
        assert self._spec().vuln_if(_ver("4.18.0")) is False


class TestDomPurifyVulnIf:
    """DOMPurify < 2.3.6 — mXSS bypass."""

    def _spec(self) -> LibSpec:
        return next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "dompurify-mxss")

    def test_vuln_2_3_5(self):
        assert self._spec().vuln_if(_ver("2.3.5")) is True

    def test_vuln_2_2_0(self):
        assert self._spec().vuln_if(_ver("2.2.0")) is True

    def test_not_vuln_2_3_6(self):
        assert self._spec().vuln_if(_ver("2.3.6")) is False

    def test_not_vuln_3_0_0(self):
        assert self._spec().vuln_if(_ver("3.0.0")) is False


# ---------------------------------------------------------------------------
# URL pattern matching
# ---------------------------------------------------------------------------

class TestUrlPatterns:
    def _matches(self, spec: LibSpec, url: str) -> bool:
        import re
        return any(re.search(p, url) for p in spec.url_patterns)

    def test_jquery_cdn_url(self):
        spec = next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "jquery")
        assert self._matches(spec, "/static/jquery-3.4.1.min.js")

    def test_jquery_path_url(self):
        spec = next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "jquery")
        assert self._matches(spec, "https://code.jquery.com/jquery/1.8.3/jquery.min.js")

    def test_lodash_url(self):
        spec = next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "lodash-prototype-pollution")
        assert self._matches(spec, "/js/lodash.min-4.17.20.js")

    def test_angularjs_url(self):
        spec = next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "angularjs")
        assert self._matches(spec, "/js/angular-1.7.9.min.js")

    def test_bootstrap_url(self):
        spec = next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "bootstrap-xss-tooltip")
        assert self._matches(spec, "/assets/bootstrap-3.3.7.min.js")
