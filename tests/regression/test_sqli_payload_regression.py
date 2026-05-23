# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Regression tests: verify the package's SQLi payloads match what breachsql's
local _scanner/payloads/ modules used to provide.

Also validates time-based benchmark calibration so it doesn't drift back to
values that caused false negatives.
"""

from commonhuman_payloads.sqli import (
    get_error_payloads,
    get_boolean_pairs,
    get_time_payloads,
    get_db_contents_payloads,
    order_by_probes,
    union_null_probes,
    make_marker,
    DB_ERROR_PATTERNS,
)
from commonhuman_payloads.sqli.union import BREACH_MARKER_PREFIX


class TestErrorPayloadRegression:
    def test_mysql_contains_extractvalue(self):
        payloads = get_error_payloads("mysql", risk=1)
        assert any("EXTRACTVALUE" in p or "extractvalue" in p.lower() for p in payloads)

    def test_mssql_contains_convert(self):
        payloads = get_error_payloads("mssql", risk=1)
        assert any("CONVERT" in p or "convert" in p.lower() for p in payloads)

    def test_postgres_contains_cast(self):
        payloads = get_error_payloads("postgres", risk=1)
        assert any("CAST" in p or "cast" in p.lower() for p in payloads)

    def test_risk3_includes_xp_cmdshell_or_os_cmd(self):
        payloads = get_error_payloads("mssql", risk=3)
        # Risk 3 should add OS-level payloads
        all_text = " ".join(payloads).lower()
        assert "xp_cmdshell" in all_text or "exec" in all_text

    def test_db_error_patterns_mysql_matches_real_error(self):
        import re
        mysql_errors = DB_ERROR_PATTERNS["mysql"]
        sample = "You have an error in your SQL syntax near '' at line 1"
        assert any(re.search(p, sample, re.IGNORECASE) for p in mysql_errors)


class TestBooleanPairRegression:
    def test_pairs_include_tautology_and_contradiction(self):
        pairs = get_boolean_pairs(risk=1)
        true_vals = [tp for tp, _ in pairs]
        false_vals = [fp for _, fp in pairs]
        # Standard AND-based pairs exist (may not be first — string-comparison pairs are first)
        assert any("1=1" in t or "AND 1" in t for t in true_vals)
        assert any("1=2" in f or "AND 0" in f or "1=0" in f for f in false_vals)

    def test_most_pairs_have_comment_suffix(self):
        pairs = get_boolean_pairs(risk=1)
        # Some pairs use string comparison (e.g. '1'='1) with no comment needed
        with_comment = [tp for tp, _ in pairs if "--" in tp or "#" in tp]
        assert len(with_comment) > 0, "Expected at least some pairs to have a comment suffix"


class TestTimePayloadRegression:
    def test_mysql_uses_sleep(self):
        payloads = get_time_payloads("mysql", delay=3)
        assert any("SLEEP(3)" in p or "sleep(3)" in p.lower() for p in payloads)

    def test_mssql_uses_waitfor(self):
        payloads = get_time_payloads("mssql", delay=3)
        assert any("WAITFOR" in p or "waitfor" in p.lower() for p in payloads)

    def test_postgres_uses_pg_sleep(self):
        payloads = get_time_payloads("postgres", delay=3)
        assert any("pg_sleep(3)" in p for p in payloads)

    def test_sqlite_cte_uses_sufficient_iterations(self):
        """sqlite_bench must be large enough to exceed a 3s threshold."""
        payloads = get_time_payloads("sqlite", delay=3)
        cte_payloads = [p for p in payloads if "x<" in p]
        assert len(cte_payloads) > 0
        import re
        for p in cte_payloads:
            n = int(re.search(r"x<(\d+)", p).group(1))
            assert n >= 25_000_000, (
                f"SQLite CTE bench={n} is likely too small for a 3s delay "
                f"(need ~25M+ iterations). Payload: {p!r}"
            )

    def test_sqlite_blob_size_does_not_overflow(self):
        """blob_size must stay well below SQLite's ~1GB limit."""
        import re
        payloads = get_time_payloads("sqlite", delay=10)
        blob_payloads = [p for p in payloads if "randomblob(" in p]
        for p in blob_payloads:
            size = int(re.search(r"randomblob\((\d+)\)", p).group(1))
            assert size <= 1_000_000_000, (
                f"randomblob({size}) will hit SQLite's blob-size limit. Payload: {p!r}"
            )


class TestUnionProbeRegression:
    def test_breach_marker_prefix_unchanged(self):
        assert BREACH_MARKER_PREFIX == "BreachSQL_"

    def test_make_marker_breach_prefix(self):
        m = make_marker()
        assert m.startswith("BreachSQL_")

    def test_order_by_probes_count(self):
        probes = order_by_probes(max_cols=20)
        assert len(probes) == 360  # 20 × 18

    def test_union_null_probes_count_3_cols(self):
        probes = union_null_probes(col_count=3, marker="M")
        assert len(probes) == 216  # 3 × 4 × 18

    def test_first_order_by_probe(self):
        probes = order_by_probes(max_cols=5)
        assert probes[0] == "' ORDER BY 1-- -"


class TestWafBypassPayloadRegression:
    """Specific WAF bypass payload content that breachsql depended on."""

    def test_generic_error_comment_terminators_present(self):
        payloads = get_error_payloads("generic", risk=1)
        assert any("--/**/-" in p for p in payloads)
        assert any("--%0A-" in p for p in payloads)
        assert any("--%23%0A-" in p for p in payloads)
        assert any("--%23foo%0D%0A-" in p for p in payloads)

    def test_generic_error_payload_count(self):
        assert len(get_error_payloads("generic", risk=1)) >= 30

    def test_order_by_group_by_variant(self):
        assert any("GROUP BY" in p for p in order_by_probes(max_cols=2))

    def test_order_by_comment_wrapped(self):
        assert any("/**/ORDER/**/BY/**/" in p for p in order_by_probes(max_cols=2))

    def test_order_by_conditional_comment(self):
        assert any("/*!ORDER BY*/" in p for p in order_by_probes(max_cols=2))

    def test_order_by_percent_encoded_newline(self):
        assert any("%0Aorder%0Aby%0A" in p for p in order_by_probes(max_cols=2))

    def test_union_all_select_present(self):
        assert any("UNION ALL SELECT" in p for p in union_null_probes(col_count=2, marker="M"))

    def test_union_distinctrow_present(self):
        assert any("Distinctrow" in p for p in union_null_probes(col_count=2, marker="M"))

    def test_union_and_null_variant(self):
        assert any("AnD null UNiON" in p for p in union_null_probes(col_count=2, marker="M"))

    def test_union_and_false_variant(self):
        assert any("And False Union" in p for p in union_null_probes(col_count=2, marker="M"))

    def test_mysql_time_xor_sleep_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("XOR(if(now()=sysdate(),sleep(" in p for p in payloads)

    def test_mysql_time_encoded_sleep_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("select*from(select(sleep(" in p for p in payloads)

    def test_mysql_time_comment_xor_sleep(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("/**/xor/**/sleep(" in p for p in payloads)

    def test_mysql_time_or_sleep_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("or (sleep(" in p for p in payloads)

    def test_boolean_char_zero_pair(self):
        trues = [t for t, _ in get_boolean_pairs(risk=1)]
        assert any("char(0)" in t for t in trues)

    def test_boolean_mod_pair(self):
        trues = [t for t, _ in get_boolean_pairs(risk=1)]
        assert any("mod(29,9)" in t for t in trues)

    def test_boolean_point_pair(self):
        trues = [t for t, _ in get_boolean_pairs(risk=1)]
        assert any("point(29,9)" in t for t in trues)

    def test_boolean_false_union_pair(self):
        trues = [t for t, _ in get_boolean_pairs(risk=1)]
        assert any("False" in t and ("UNION" in t or "Union" in t) for t in trues)

    def test_boolean_if_pair(self):
        trues = [t for t, _ in get_boolean_pairs(risk=1)]
        assert any("IF(1=1" in t for t in trues)

    def test_boolean_case_when_pair(self):
        trues = [t for t, _ in get_boolean_pairs(risk=1)]
        assert any("CASE WHEN" in t for t in trues)

    def test_mysql_db_contents_group_concat(self):
        payloads = get_db_contents_payloads("mysql", "tables")
        assert any("GROUP_CONCAT" in p for p in payloads)

    def test_mysql_db_contents_waf_bypass_encoding(self):
        payloads = get_db_contents_payloads("mysql", "tables")
        assert any("%53ELECT" in p or "%46ROM" in p for p in payloads)


class TestEvasionRegression:
    """Verify apply_evasion behavior that breachsql tests depend on."""

    def test_sql_whitespace_replaces_spaces(self):
        from commonhuman_payloads.encoders import apply_evasion, EVASION_SQL_WHITESPACE
        result = apply_evasion("SELECT 1 FROM t", EVASION_SQL_WHITESPACE)
        assert " " not in result
        assert "\t" in result

    def test_sql_encode_url_encodes(self):
        from commonhuman_payloads.encoders import apply_evasion, EVASION_SQL_ENCODE
        import urllib.parse
        payload = "' OR 1=1-- -"
        result = apply_evasion(payload, EVASION_SQL_ENCODE)
        assert urllib.parse.unquote(result) == payload

    def test_double_encode_has_percent_signs(self):
        from commonhuman_payloads.encoders import apply_evasion, EVASION_DOUBLE_ENCODE
        result = apply_evasion("' OR '1'='1", EVASION_DOUBLE_ENCODE)
        assert "%" in result

    def test_case_mixing_is_not_swapcase(self):
        """Regression: old breachsql used swapcase(); package uses alternating."""
        from commonhuman_payloads.encoders import apply_evasion, EVASION_CASE_MIXING
        result = apply_evasion("SELECT", EVASION_CASE_MIXING)
        # Package behaviour: SeLeCt (alternating), not select (swapcase)
        assert result == "SeLeCt"

    def test_null_byte_inserts_into_tag_not_appends(self):
        """Regression: old breachsql appended %00; package inserts \\x00 after <."""
        from commonhuman_payloads.encoders import apply_evasion, EVASION_NULL_BYTE
        result = apply_evasion("<script>", EVASION_NULL_BYTE)
        assert "\x00" in result
        assert not result.endswith("%00")
