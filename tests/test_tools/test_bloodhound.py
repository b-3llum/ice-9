"""Tests for BloodHound wrapper command building and Cypher query resolution."""

from __future__ import annotations

import pytest
from ice_9.tools.bloodhound import CYPHER_QUERIES, BloodHoundWrapper


class TestBuildCommand:
    def test_output_dir_default_and_zip(self):
        cmd = BloodHoundWrapper().build_command("corp.local")
        assert "--zip" in cmd
        assert "/tmp/bloodhound" in cmd

    def test_auth_flags(self):
        cmd = BloodHoundWrapper().build_command(
            "corp.local", username="svc", password="pw", dc="10.0.0.5"
        )
        assert cmd[cmd.index("-u") + 1] == "svc"
        assert cmd[cmd.index("-p") + 1] == "pw"
        assert cmd[cmd.index("--dc") + 1] == "10.0.0.5"


class TestResolveQuery:
    def test_known_query_returns_cypher_and_params(self):
        cypher, params = BloodHoundWrapper._resolve_query("domain_admins", "corp.local")
        assert cypher is CYPHER_QUERIES["domain_admins"]
        assert params == {"domain_upper": "DOMAIN ADMINS@CORP.LOCAL"}

    def test_unknown_query_returns_none(self):
        assert BloodHoundWrapper._resolve_query("does_not_exist") == (None, {})

    def test_empty_domain_uses_unknown_placeholder(self):
        _, params = BloodHoundWrapper._resolve_query("domain_admins", "")
        assert params == {"domain_upper": "DOMAIN ADMINS@UNKNOWN"}

    def test_domain_queries_use_bound_parameter_not_interpolation(self):
        # The two domain-scoped queries must reference the bound parameter.
        for name in ("domain_admins", "shortest_path_to_da"):
            assert "$domain_upper" in CYPHER_QUERIES[name]

    def test_no_query_contains_legacy_placeholder(self):
        # The old string-replace placeholder must be gone everywhere.
        for name, q in CYPHER_QUERIES.items():
            assert "{domain_upper}" not in q, name

    def test_malicious_domain_stays_in_param_value(self):
        # A crafted domain must not land in the query text; it rides the param.
        evil = "x' RETURN 1 //"
        cypher, params = BloodHoundWrapper._resolve_query("domain_admins", evil)
        assert "RETURN 1 //" not in cypher
        assert "X' RETURN 1 //" in params["domain_upper"]


@pytest.mark.parametrize("name", list(CYPHER_QUERIES))
def test_all_queries_resolve(name):
    cypher, params = BloodHoundWrapper._resolve_query(name, "corp.local")
    assert cypher and "domain_upper" in params
