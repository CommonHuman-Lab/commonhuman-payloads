# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_payloads.creds.patterns."""

from __future__ import annotations

import pytest

from commonhuman_payloads.creds.patterns import (
    ALL_PATTERNS,
    HIGH_CONFIDENCE,
    CredPattern,
    PRIVATE_KEY_PATTERNS,
    CLOUD_PATTERNS,
    GENERIC_PATTERNS,
    JWT_PATTERNS,
    DATABASE_PATTERNS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match(name: str, text: str) -> bool:
    for p in ALL_PATTERNS:
        if p.name == name:
            return bool(p.pattern.search(text))
    raise KeyError(f"Pattern not found: {name!r}")


# ---------------------------------------------------------------------------
# Private key patterns
# ---------------------------------------------------------------------------

class TestPrivateKeyPatterns:
    def test_pem_rsa_key(self):
        assert _match("pem_rsa_key", "-----BEGIN RSA PRIVATE KEY-----")

    def test_pem_ec_key(self):
        assert _match("pem_ec_key", "-----BEGIN EC PRIVATE KEY-----")

    def test_pem_private_key(self):
        assert _match("pem_private_key", "-----BEGIN PRIVATE KEY-----")

    def test_pem_openssh_key(self):
        assert _match("pem_openssh_key", "-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_pem_dsa_key(self):
        assert _match("pem_dsa_key", "-----BEGIN DSA PRIVATE KEY-----")

    def test_putty_ppk(self):
        assert _match("putty_ppk", "PuTTY-User-Key-File-2")

    def test_no_false_positive_public_key(self):
        assert not _match("pem_rsa_key", "-----BEGIN RSA PUBLIC KEY-----")


# ---------------------------------------------------------------------------
# Cloud patterns
# ---------------------------------------------------------------------------

class TestCloudPatterns:
    def test_aws_access_key(self):
        assert _match("aws_access_key", "AKIAIOSFODNN7EXAMPLE")

    def test_aws_access_key_asia_prefix(self):
        assert _match("aws_access_key", "ASIAIOSFODNN7EXAMPLE")

    def test_aws_secret_key(self):
        assert _match("aws_secret_key", 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

    def test_gcp_service_account(self):
        assert _match("gcp_service_account", '"type": "service_account"')

    def test_gcp_api_key(self):
        assert _match("gcp_api_key", "AIzaSyD-9tSrke72I6e64MRsGiA8gqbCJ4OPeGg")

    def test_azure_storage_key(self):
        key = "A" * 86 + "=="
        assert _match("azure_storage_key", f"AccountKey={key}")

    def test_github_token_ghs(self):
        assert _match("github_token", "ghs_" + "A" * 36)

    def test_github_token_ghp(self):
        assert _match("github_token", "ghp_" + "A" * 36)

    def test_github_fine_grained(self):
        assert _match("github_fine_grained", "github_pat_" + "A" * 82)

    def test_gitlab_token(self):
        assert _match("gitlab_token", "glpat-FakeGitLabTokenExample12345")

    def test_slack_token(self):
        assert _match("slack_token", "xoxb-123456789-abcdefghijklmnop")

    def test_stripe_key_live(self):
        assert _match("stripe_key", "sk_live_FakeStripeKeyForLabTesting1234")

    def test_stripe_key_test(self):
        assert _match("stripe_key", "pk_test_FakeStripeTestKeyForTesting1234")

    def test_twilio_sid(self):
        assert _match("twilio_sid", " AC" + "a" * 32 + " ")

    def test_sendgrid_key(self):
        assert _match("sendgrid_key", "SG." + "A" * 22 + "." + "B" * 43)

    def test_npm_token(self):
        assert _match("npm_token", "npm_" + "A" * 36)

    def test_anthropic_key(self):
        assert _match("anthropic_key", "sk-ant-" + "A" * 90)

    def test_openai_key(self):
        assert _match("openai_key", "sk-" + "A" * 48)


# ---------------------------------------------------------------------------
# Generic patterns
# ---------------------------------------------------------------------------

class TestGenericPatterns:
    def test_env_password_equals(self):
        assert _match("env_password", "password=MySecret123!")

    def test_env_password_colon(self):
        assert _match("env_password", "passwd: hunter2")

    def test_env_password_no_match_path(self):
        assert not _match("env_password", "PWD=/home/user")

    def test_env_api_key(self):
        assert _match("env_api_key", "API_KEY=abcdef1234567890")

    def test_env_token(self):
        assert _match("env_token", "ACCESS_TOKEN=eyJhbGciOiJSUzI1NiJ9sometoken")

    def test_env_secret_key(self):
        assert _match("env_secret", "SECRET_KEY=django-insecure-fake-secret-key-for-lab")

    def test_env_secret_plain(self):
        assert _match("env_secret", "secret=mysecretvalue")

    def test_basic_auth_url(self):
        assert _match("basic_auth_url", "https://admin:Password123@api.example.com")

    def test_connection_string_pw(self):
        assert _match("connection_string_pw", "password=PgProductionPass123!")

    def test_connection_string_pw_no_path(self):
        assert not _match("connection_string_pw", "pwd=/home/user")

    def test_docker_auth(self):
        assert _match("docker_auth", '"auth": "bGFidXNlcjpEb2NrZXJQYXNzd29yZDEyMyE="')

    def test_pgpass_password(self):
        line = "localhost:5432:production_db:labuser:PgProductionPass123!"
        assert _match("pgpass_password", line)

    def test_netrc_password(self):
        assert _match("netrc_password", "machine ftp.example.com login labuser password FtpPassword789!")

    def test_env_token_bearer(self):
        assert _match("env_token", "bearer=someaccesstoken12345678")


# ---------------------------------------------------------------------------
# JWT patterns
# ---------------------------------------------------------------------------

class TestJwtPatterns:
    def test_jwt_token(self):
        jwt = (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0"
            ".FAKESIGNATURE"
        )
        assert _match("jwt_token", jwt)

    def test_non_jwt_string_no_match(self):
        assert not _match("jwt_token", "not.a.jwt.token")


# ---------------------------------------------------------------------------
# Database DSN patterns
# ---------------------------------------------------------------------------

class TestDatabasePatterns:
    def test_postgres_dsn(self):
        assert _match("postgres_dsn", "postgresql://labuser:PgPass@localhost:5432/db")

    def test_mysql_dsn(self):
        assert _match("mysql_dsn", "mysql://root:RootPass@localhost/mydb")

    def test_mongodb_dsn(self):
        assert _match("mongodb_dsn", "mongodb://user:MongoPass@localhost:27017/db")

    def test_mongodb_srv_dsn(self):
        assert _match("mongodb_dsn", "mongodb+srv://user:Pass@cluster.example.com/db")

    def test_redis_auth_dsn(self):
        assert _match("redis_auth_dsn", "redis://:CachedPass789@localhost:6379/0")

    def test_mssql_dsn(self):
        assert _match("mssql_dsn", "mssql://sa:SaPass@sqlserver.example.com/master")


# ---------------------------------------------------------------------------
# Aggregated lists
# ---------------------------------------------------------------------------

class TestAggregated:
    def test_all_patterns_non_empty(self):
        assert len(ALL_PATTERNS) > 0

    def test_high_confidence_subset_of_all(self):
        all_names = {p.name for p in ALL_PATTERNS}
        for p in HIGH_CONFIDENCE:
            assert p.name in all_names

    def test_high_confidence_all_high(self):
        assert all(p.confidence == "high" for p in HIGH_CONFIDENCE)

    def test_all_patterns_are_credpattern(self):
        for p in ALL_PATTERNS:
            assert isinstance(p, CredPattern)

    def test_covers_all_sublists(self):
        all_names = {p.name for p in ALL_PATTERNS}
        for sub in [PRIVATE_KEY_PATTERNS, CLOUD_PATTERNS, GENERIC_PATTERNS, JWT_PATTERNS, DATABASE_PATTERNS]:
            for p in sub:
                assert p.name in all_names
