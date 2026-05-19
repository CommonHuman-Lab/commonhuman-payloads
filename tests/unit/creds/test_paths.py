# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_payloads.creds.paths."""

from __future__ import annotations

from commonhuman_payloads.creds.paths import (
    ALL_HOME_PATHS,
    ALL_SYSTEM_PATHS,
    AWS_PATHS,
    BROWSER_PATHS,
    BY_SERVICE,
    CredPath,
    DATABASE_PATHS,
    DOCKER_PATHS,
    GCP_PATHS,
    GIT_PATHS,
    INFRA_PATHS,
    INTERESTING_EXTENSIONS,
    INTERESTING_FILENAMES,
    K8S_PATHS,
    PASSWORD_MANAGER_PATHS,
    SHELL_HISTORY_PATHS,
    SSH_PATHS,
    SYSTEM_PATHS,
    AZURE_PATHS,
)


class TestCredPath:
    def test_fields(self):
        p = CredPath(".ssh/id_rsa", "ssh", "private_key")
        assert p.pattern == ".ssh/id_rsa"
        assert p.service == "ssh"
        assert p.cred_type == "private_key"
        assert p.absolute is False

    def test_absolute_flag(self):
        p = CredPath("/etc/shadow", "linux", "password", absolute=True)
        assert p.absolute is True


class TestSshPaths:
    def test_contains_id_rsa(self):
        patterns = [p.pattern for p in SSH_PATHS]
        assert ".ssh/id_rsa" in patterns

    def test_contains_id_ed25519(self):
        patterns = [p.pattern for p in SSH_PATHS]
        assert ".ssh/id_ed25519" in patterns

    def test_all_are_cred_path(self):
        for p in SSH_PATHS:
            assert isinstance(p, CredPath)

    def test_all_ssh_service(self):
        for p in SSH_PATHS:
            assert p.service == "ssh"


class TestAwsPaths:
    def test_contains_credentials(self):
        patterns = [p.pattern for p in AWS_PATHS]
        assert ".aws/credentials" in patterns

    def test_all_aws_service(self):
        for p in AWS_PATHS:
            assert p.service == "aws"


class TestAllHomePaths:
    def test_non_empty(self):
        assert len(ALL_HOME_PATHS) > 0

    def test_all_are_cred_path(self):
        for p in ALL_HOME_PATHS:
            assert isinstance(p, CredPath)

    def test_no_absolute_paths(self):
        for p in ALL_HOME_PATHS:
            assert not p.absolute

    def test_includes_ssh(self):
        ssh = [p for p in ALL_HOME_PATHS if p.service == "ssh"]
        assert len(ssh) > 0

    def test_includes_git(self):
        git = [p for p in ALL_HOME_PATHS if p.service == "git"]
        assert len(git) > 0

    def test_covers_all_sublists(self):
        all_patterns = {p.pattern for p in ALL_HOME_PATHS}
        for sublist in [SSH_PATHS, AWS_PATHS, GCP_PATHS, AZURE_PATHS, K8S_PATHS,
                        DOCKER_PATHS, GIT_PATHS, SHELL_HISTORY_PATHS,
                        PASSWORD_MANAGER_PATHS, BROWSER_PATHS, DATABASE_PATHS, INFRA_PATHS]:
            for p in sublist:
                assert p.pattern in all_patterns


class TestAllSystemPaths:
    def test_contains_etc_shadow(self):
        patterns = [p.pattern for p in ALL_SYSTEM_PATHS]
        assert "/etc/shadow" in patterns

    def test_all_absolute(self):
        for p in ALL_SYSTEM_PATHS:
            assert p.absolute

    def test_matches_system_paths_list(self):
        assert list(ALL_SYSTEM_PATHS) == list(SYSTEM_PATHS)


class TestByService:
    def test_ssh_key(self):
        assert "ssh" in BY_SERVICE
        assert len(BY_SERVICE["ssh"]) > 0

    def test_aws_key(self):
        assert "aws" in BY_SERVICE

    def test_linux_key(self):
        assert "linux" in BY_SERVICE

    def test_all_paths_indexed(self):
        total = sum(len(v) for v in BY_SERVICE.values())
        expected = len(ALL_HOME_PATHS) + len(ALL_SYSTEM_PATHS)
        assert total == expected


class TestInterestingSets:
    def test_interesting_extensions_contains_pem(self):
        assert ".pem" in INTERESTING_EXTENSIONS

    def test_interesting_extensions_contains_env(self):
        assert ".env" in INTERESTING_EXTENSIONS

    def test_interesting_filenames_contains_netrc(self):
        assert ".netrc" in INTERESTING_FILENAMES

    def test_interesting_filenames_contains_pgpass(self):
        assert ".pgpass" in INTERESTING_FILENAMES

    def test_interesting_extensions_is_frozenset(self):
        assert isinstance(INTERESTING_EXTENSIONS, frozenset)

    def test_interesting_filenames_is_frozenset(self):
        assert isinstance(INTERESTING_FILENAMES, frozenset)
