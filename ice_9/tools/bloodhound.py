"""BloodHound AD attack path analyzer — Neo4j query integration."""

from __future__ import annotations

import re
from typing import Any

from ice_9.tools.base import (
    ToolResult,
    ToolWrapper,
    validate_output_path,
    validate_target,
)

# Pre-built Cypher queries for common attack path analysis
CYPHER_QUERIES = {
    "domain_admins": (
        "MATCH (g:Group {name: $domain_upper}) "
        "MATCH p=shortestPath((u:User)-[*1..]->(g)) "
        "WHERE u<>g RETURN p"
    ),
    "kerberoastable": (
        "MATCH (u:User {hasspn: true}) "
        "WHERE u.enabled = true "
        "RETURN u.name, u.serviceprincipalnames, u.admincount"
    ),
    "asrep_roastable": (
        "MATCH (u:User {dontreqpreauth: true}) "
        "WHERE u.enabled = true "
        "RETURN u.name, u.displayname"
    ),
    "unconstrained_delegation": (
        "MATCH (c:Computer {unconstraineddelegation: true}) "
        "RETURN c.name, c.operatingsystem"
    ),
    "shortest_path_to_da": (
        "MATCH (u:User),(g:Group {name: $domain_upper}) "
        "MATCH p=shortestPath((u)-[*1..]->(g)) "
        "RETURN u.name, length(p) AS hops ORDER BY hops ASC LIMIT 20"
    ),
    "high_value_targets": (
        "MATCH (n {highvalue: true}) "
        "RETURN labels(n), n.name, n.operatingsystem"
    ),
    "sessions": (
        "MATCH (c:Computer)-[:HasSession]->(u:User) "
        "RETURN c.name, u.name LIMIT 50"
    ),
    "local_admins": (
        "MATCH p=(u:User)-[:AdminTo]->(c:Computer) "
        "RETURN u.name, c.name"
    ),
    "dcsync_rights": (
        "MATCH p=(n)-[:GetChanges|GetChangesAll*1..]->(d:Domain) "
        "RETURN n.name, labels(n)"
    ),
    "gpo_abuse": (
        "MATCH (g:GPO)-[:GpLink]->(o) "
        "MATCH p=(u)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl*1..]->(g) "
        "RETURN u.name, g.name, o.name"
    ),
}


class BloodHoundWrapper(ToolWrapper):
    """BloodHound / SharpHound data collection and Neo4j query integration."""

    name = "bloodhound"
    description = "AD attack path analysis — SharpHound collection + Neo4j Cypher queries"
    binary = "bloodhound-python"  # bloodhound.py collector
    att_ck_ids = ["T1087.002", "T1069.002", "T1482"]  # Account/Group Discovery, Domain Trust

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "bloodhound",
    ) -> None:
        super().__init__()
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build bloodhound-python collection command."""
        cmd = [self.get_binary_path()]

        # Domain
        cmd.extend(["-d", validate_target(target, "domain")])

        # Collection method
        method = kwargs.get("method", "all")
        cmd.extend(["-c", method])

        # Domain controller
        dc = kwargs.get("dc")
        if dc:
            cmd.extend(["--dc", dc])

        # Auth
        username = kwargs.get("username")
        password = kwargs.get("password")
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])

        nt_hash = kwargs.get("nt_hash")
        if nt_hash:
            cmd.extend(["--hashes", f":{nt_hash}"])

        # Nameserver
        ns = kwargs.get("nameserver")
        if ns:
            cmd.extend(["-ns", ns])

        # Output
        output_dir = validate_output_path(kwargs.get("output_dir", "/tmp/bloodhound"))
        cmd.extend(["--zip", "-o", output_dir])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse bloodhound-python output."""
        lines = result.stdout.strip().splitlines()
        collected = {
            "users": 0, "computers": 0, "groups": 0,
            "domains": 0, "gpos": 0, "ous": 0,
        }

        for line in lines:
            lower = line.lower()
            for key in collected:
                if key in lower and ("found" in lower or "done" in lower):
                    # Try to extract count
                    nums = re.findall(r"(\d+)", line)
                    if nums:
                        collected[key] = int(nums[0])

        return {
            "collected": collected,
            "raw_lines": lines[-20:],  # Last 20 lines
        }

    @staticmethod
    def _resolve_query(
        query_name: str, domain: str = ""
    ) -> tuple[str | None, dict[str, Any]]:
        """Resolve a pre-built query name to (cypher, params).

        Returns ``(None, {})`` for an unknown name. The domain is returned as a
        bound parameter value (``domain_upper``) rather than interpolated into
        the query text, so it cannot alter the query structure.
        """
        cypher = CYPHER_QUERIES.get(query_name)
        if cypher is None:
            return None, {}
        domain_upper = (
            f"DOMAIN ADMINS@{domain.upper()}" if domain else "DOMAIN ADMINS@UNKNOWN"
        )
        return cypher, {"domain_upper": domain_upper}

    def query_neo4j(self, query_name: str, domain: str = "") -> dict[str, Any]:
        """Run a pre-built Cypher query against Neo4j."""
        try:
            from neo4j import GraphDatabase
        except ImportError:
            return {"error": "neo4j Python driver not installed. Run: pip install neo4j"}

        cypher, params = self._resolve_query(query_name, domain)
        if cypher is None:
            return {
                "error": f"Unknown query: {query_name}",
                "available": list(CYPHER_QUERIES.keys()),
            }

        try:
            driver = GraphDatabase.driver(
                self.neo4j_uri, auth=(self.neo4j_user, self.neo4j_password)
            )
            with driver.session() as session:
                # Bind domain_upper as a query parameter; the driver escapes it,
                # so a crafted domain cannot inject Cypher. Unused parameters
                # (queries without $domain_upper) are ignored by the driver.
                result = session.run(cypher, **params)
                records = [dict(record) for record in result]
            driver.close()
            return {"query": query_name, "results": records, "count": len(records)}
        except Exception as e:
            return {"error": str(e), "query": query_name}

    def get_available_queries(self) -> list[dict[str, str]]:
        """List available pre-built queries."""
        return [
            {"name": name, "cypher": query}
            for name, query in CYPHER_QUERIES.items()
        ]
