"""Tests for entity extraction from tool outputs."""

from __future__ import annotations

from pathlib import Path

import pytest
from ice_9.core.campaign import create_campaign
from ice_9.core.intel import EntityType, RelType
from ice_9.db.store import Store
from ice_9.intel.extractor import EntityExtractor, _email_to_name

CAMPAIGN_ID = "test_camp_01"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "test.db", check_same_thread=False)
    # Create a campaign so FK constraints are satisfied
    campaign = create_campaign(name="Test", scope=["10.0.0.0/8"])
    campaign.id = CAMPAIGN_ID
    s.save_campaign(campaign)
    yield s
    s.close()


@pytest.fixture
def extractor(store: Store) -> EntityExtractor:
    return EntityExtractor(store)


# --- Nmap extraction ---


class TestNmapExtraction:
    NMAP_PARSED = {
        "hosts": [
            {
                "ip": "192.168.1.10",
                "state": "up",
                "addresses": [
                    {"addr": "192.168.1.10", "type": "ipv4"},
                    {"addr": "AA:BB:CC:DD:EE:FF", "type": "mac"},
                ],
                "hostnames": ["web01.example.com"],
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "8.9p1",
                    },
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "nginx",
                        "version": "1.18.0",
                    },
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "closed",
                        "service": "https",
                    },
                ],
                "os": [{"name": "Ubuntu 22.04", "accuracy": 95}],
            }
        ],
        "summary": {"hosts_up": 1},
    }

    def test_extracts_host_entity(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID
        )

        hosts = [e for e in entities if e.entity_type == EntityType.HOST]
        assert len(hosts) == 1
        assert hosts[0].name == "192.168.1.10"
        assert hosts[0].properties["os"] == "Ubuntu 22.04"
        assert hosts[0].properties["mac"] == "AA:BB:CC:DD:EE:FF"
        assert hosts[0].confidence == 0.9

    def test_extracts_domain_entity(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID
        )

        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) == 1
        assert domains[0].name == "web01.example.com"

    def test_extracts_service_entities(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID
        )

        services = [e for e in entities if e.entity_type == EntityType.SERVICE]
        # Only open ports generate service entities
        assert len(services) == 2
        svc_names = {s.name for s in services}
        assert "192.168.1.10:22/tcp" in svc_names
        assert "192.168.1.10:80/tcp" in svc_names

    def test_creates_host_to_domain_relationship(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID
        )

        resolve_rels = [r for r in rels if r.rel_type == RelType.RESOLVES_TO]
        assert len(resolve_rels) == 1

    def test_creates_host_to_service_relationships(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID
        )

        svc_rels = [r for r in rels if r.rel_type == RelType.RUNS_SERVICE]
        assert len(svc_rels) == 2

    def test_extract_and_store(self, extractor: EntityExtractor, store: Store):
        entities, rels = extractor.extract_and_store(
            "nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID
        )

        # Should be persisted in DB
        db_entities = store.get_entities(CAMPAIGN_ID)
        assert len(db_entities) == len(entities)

        db_rels = store.get_relationships(CAMPAIGN_ID)
        assert len(db_rels) == len(rels)

    def test_deduplication(self, extractor: EntityExtractor, store: Store):
        # Extract twice — should not create duplicates
        extractor.extract_and_store("nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID)
        extractor.extract_and_store("nmap", self.NMAP_PARSED, "192.168.1.0/24", CAMPAIGN_ID)

        entities = store.get_entities(CAMPAIGN_ID)
        hosts = [e for e in entities if e.entity_type == EntityType.HOST]
        assert len(hosts) == 1  # Not duplicated


# --- theHarvester extraction ---


class TestTheHarvesterExtraction:
    HARVESTER_PARSED = {
        "emails": ["john.doe@example.com", "jane.smith@example.com", "info@example.com"],
        "subdomains": ["mail.example.com", "vpn.example.com"],
        "ips": ["93.184.216.34"],
        "email_count": 3,
        "subdomain_count": 2,
    }

    def test_extracts_email_entities(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "theharvester", self.HARVESTER_PARSED, "example.com", CAMPAIGN_ID
        )

        emails = [e for e in entities if e.entity_type == EntityType.EMAIL]
        assert len(emails) == 3

    def test_infers_person_entities(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "theharvester", self.HARVESTER_PARSED, "example.com", CAMPAIGN_ID
        )

        persons = [e for e in entities if e.entity_type == EntityType.PERSON]
        # info@ is generic — should not generate a person
        assert len(persons) == 2
        names = {p.name for p in persons}
        assert "John Doe" in names
        assert "Jane Smith" in names

    def test_creates_owns_email_relationships(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "theharvester", self.HARVESTER_PARSED, "example.com", CAMPAIGN_ID
        )

        email_rels = [r for r in rels if r.rel_type == RelType.OWNS_EMAIL]
        assert len(email_rels) == 2  # Only non-generic emails

    def test_creates_organization_entity(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "theharvester", self.HARVESTER_PARSED, "example.com", CAMPAIGN_ID
        )

        orgs = [e for e in entities if e.entity_type == EntityType.ORGANIZATION]
        assert len(orgs) == 1
        assert orgs[0].name == "example.com"

    def test_extracts_subdomain_entities(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed(
            "theharvester", self.HARVESTER_PARSED, "example.com", CAMPAIGN_ID
        )

        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) == 2


# --- Credential extraction ---


class TestCredentialExtraction:
    def test_responder_ntlmv2_hashes(self, extractor: EntityExtractor):
        parsed = {
            "ntlmv2_hashes": ["jsmith::CORP:aabbccdd:112233:hash_data"],
            "ntlmv1_hashes": [],
            "captured_from": [{"ip": "192.168.1.50"}],
        }
        entities, rels = extractor.extract_from_parsed(
            "responder", parsed, "eth0", CAMPAIGN_ID
        )

        creds = [e for e in entities if e.entity_type == EntityType.CREDENTIAL]
        assert len(creds) == 1
        assert creds[0].properties["hash_type"] == "NTLMv2"
        assert creds[0].properties["username"] == "jsmith"

        persons = [e for e in entities if e.entity_type == EntityType.PERSON]
        assert len(persons) == 1
        assert persons[0].name == "jsmith"

    def test_secretsdump_hashes(self, extractor: EntityExtractor):
        parsed = {
            "hashes": [
                "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
                "CORP\\svc_sql:1001:aad3b435:nthash:::",
            ],
        }
        entities, rels = extractor.extract_from_parsed(
            "secretsdump", parsed, "192.168.1.1", CAMPAIGN_ID
        )

        creds = [e for e in entities if e.entity_type == EntityType.CREDENTIAL]
        assert len(creds) == 2

        persons = [e for e in entities if e.entity_type == EntityType.PERSON]
        assert len(persons) == 2
        names = {p.name for p in persons}
        assert "Administrator" in names
        assert "svc_sql" in names

    def test_kerberoast_hashes(self, extractor: EntityExtractor):
        parsed = {
            "tgs_hashes": ["$krb5tgs$23$*svc_web$CORP$http/web01*$..."],
            "spn_accounts": [],
        }
        entities, rels = extractor.extract_from_parsed(
            "getuserspns", parsed, "dc01.corp.local", CAMPAIGN_ID
        )

        creds = [e for e in entities if e.entity_type == EntityType.CREDENTIAL]
        assert len(creds) == 1
        assert creds[0].name == "TGS:svc_web"

    def test_asreproast_hashes(self, extractor: EntityExtractor):
        parsed = {
            "asrep_hashes": ["$krb5asrep$23$nopreauth@CORP:hash_data"],
        }
        entities, rels = extractor.extract_from_parsed(
            "getnpusers", parsed, "dc01.corp.local", CAMPAIGN_ID
        )

        creds = [e for e in entities if e.entity_type == EntityType.CREDENTIAL]
        assert len(creds) == 1

        persons = [e for e in entities if e.entity_type == EntityType.PERSON]
        assert len(persons) == 1
        assert persons[0].properties.get("no_preauth") is True


# --- Helper function tests ---


class TestEmailToName:
    def test_dot_separated(self):
        assert _email_to_name("john.doe") == "John Doe"

    def test_underscore_separated(self):
        assert _email_to_name("john_doe") == "John Doe"

    def test_dash_separated(self):
        assert _email_to_name("john-doe") == "John Doe"

    def test_generic_emails_skipped(self):
        for generic in ["info", "admin", "support", "noreply", "security"]:
            assert _email_to_name(generic) == ""

    def test_short_names_skipped(self):
        assert _email_to_name("x") == ""
        assert _email_to_name("") == ""

    def test_numeric_names_skipped(self):
        # Single unseparated alphanumeric string won't match
        assert _email_to_name("jdoe123") == ""


# --- Subdomain/DNS extraction ---


class TestDomainExtraction:
    def test_amass_subdomains(self, extractor: EntityExtractor):
        parsed = {
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "addresses": ["1.2.3.4"],
            "sources": ["crt.sh"],
        }
        entities, _ = extractor.extract_from_parsed("amass", parsed, "example.com", CAMPAIGN_ID)

        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) == 2

        hosts = [e for e in entities if e.entity_type == EntityType.HOST]
        assert len(hosts) == 1

    def test_subfinder_subdomains(self, extractor: EntityExtractor):
        parsed = {"subdomains": ["api.example.com", "cdn.example.com"], "count": 2}
        entities, _ = extractor.extract_from_parsed("subfinder", parsed, "example.com", CAMPAIGN_ID)

        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) == 2

    def test_unknown_tool_returns_empty(self, extractor: EntityExtractor):
        entities, rels = extractor.extract_from_parsed("unknown_tool", {}, "target", CAMPAIGN_ID)
        assert entities == []
        assert rels == []
