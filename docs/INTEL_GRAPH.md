# Intelligence Graph & Subject Profiling System

## What Was Built

An interactive graph-based intelligence visualization and behavioral prediction system for ice_9. The system aggregates intelligence from all campaign phases into interconnected entity graphs, builds social engineering-focused subject profiles, and runs Monte Carlo behavioral simulations to predict attack success rates.

Think BloodHound meets OSINT intelligence platform — every discovered host, user, credential, and domain becomes a clickable node in a force-directed graph. The crown jewel: a behavioral prediction engine that simulates social engineering scenarios against profiled targets.

## Why

Red team engagements generate massive amounts of disconnected data across tools and phases. Nmap finds hosts, theHarvester finds emails, Responder captures hashes, BloodHound maps AD relationships — but correlating these into actionable intelligence requires manual effort. This system automates that correlation and adds AI-powered analysis on top.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Dashboard (React)                        │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  IntelGraph  │  │SubjectProfile│  │ SimulationPanel    │  │
│  │ (force-2d)  │  │  + Radar     │  │ + Results          │  │
│  └──────┬──────┘  └──────┬───────┘  └────────┬───────────┘  │
│         │                │                    │              │
│  ┌──────┴────────────────┴────────────────────┴──────────┐  │
│  │              API Client (intel.ts)                     │  │
│  └───────────────────────┬───────────────────────────────┘  │
└──────────────────────────┼──────────────────────────────────┘
                           │ REST + SSE
┌──────────────────────────┼──────────────────────────────────┐
│                    FastAPI (api.py)                          │
│  /graph  /entities  /subjects  /simulate  /extract          │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                 Intel Backend (ice_9/intel/)                 │
│  ┌───────────┐  ┌────────────┐  ┌──────────┐  ┌─────────┐  │
│  │ Extractor │  │ Enrichment │  │ Profiler │  │Simulator│  │
│  │(9 tools) │  │ (AI+OSINT) │  │ (SE/AI)  │  │(Monte C)│  │
│  └─────┬─────┘  └─────┬──────┘  └────┬─────┘  └────┬────┘  │
│        │               │              │              │       │
│  ┌─────┴───────────────┴──────────────┴──────────────┴───┐  │
│  │           TeamOrchestrator (AI Agents)                 │  │
│  │   social_engineer | intelligence_analyst | coordinator │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│              SQLite Store (entities, relationships,          │
│                   subject_profiles tables)                   │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Data Models (`ice_9/core/intel.py`)
- **Entity** — graph nodes (person, host, domain, credential, email, organization, service, network, certificate)
- **Relationship** — graph edges with typed connections (admin_of, has_credential, runs_service, etc.)
- **SubjectProfile** — SE-focused dossier linked to a person entity
- **SimulationResult / ScenarioResult** — Monte Carlo simulation outputs

### Entity Extractor (`ice_9/intel/extractor.py`)
Parses tool outputs into entities and relationships. Supports 9 tools:
- **nmap** → hosts, services, domains + RUNS_SERVICE, RESOLVES_TO relationships
- **theHarvester** → emails, persons (inferred), organizations + OWNS_EMAIL, MEMBER_OF
- **amass / subfinder** → domains, hosts
- **bloodhound** → organization/AD summary
- **responder** → credentials, persons + HAS_CREDENTIAL
- **secretsdump** → NTLM credentials, persons
- **getuserspns** → Kerberos TGS credentials (kerberoasting)
- **getnpusers** → AS-REP credentials

Deduplicates entities by (type, name) and merges confidence scores/sources on collision.

### Enrichment Engine (`ice_9/intel/enrichment.py`)
AI-powered OSINT enrichment per entity type:
- **Person** → social engineer agent profiles personality, interests, risk factors
- **Email** → domain correlation, breach pattern indicators
- **Domain** → recon analyst evaluates technology stack
- **Host** → exploit researcher analyzes service profile for attack opportunities

### Subject Profiler (`ice_9/intel/profiler.py`)
Builds SE-focused intelligence dossiers:
1. Aggregates graph data (emails, credentials, org relationships)
2. Populates digital footprint (hash types, SPNs, pre-auth status)
3. AI-generates susceptibility scores per attack vector (phishing, pretexting, baiting, vishing, tailgating)
4. Recommends pretext scenarios with estimated success rates

### Behavioral Simulator (`ice_9/intel/simulation.py`)
MiroFish-inspired Monte Carlo simulation:
1. Builds target persona from OSINT data
2. Runs N simulations per scenario (default 5 scenarios x 50 runs)
3. Varies time of day, urgency, communication channel
4. Tracks outcomes: comply, partial comply, refuse, report to IT
5. Calculates success rates with 95% confidence intervals
6. Generates narrative report via report_writer agent

### EventBus Integration (`ice_9/intel/hooks.py`)
- Subscribes to PHASE_COMPLETE events
- Auto-extracts entities in background thread
- Emits ENTITY_EXTRACTED, INTEL_ENRICHED, SUBJECT_PROFILED, SIMULATION_* events

### Dashboard (`dashboard/src/`)
- **IntelGraph** — Force-directed 2D graph (react-force-graph-2d)
  - Nodes colored by entity type, sized by connection count
  - Click → sidebar with entity detail + relationships
  - Right-click → context menu (Enrich, Create Profile)
  - Search, type filters, real-time SSE updates
- **SubjectProfile** — Full dossier view with contact, footprint, susceptibility bars
- **SimulationPanel** — Configure and run simulations
- **SimulationResults** — Expandable scenario results with sample interactions

## How to Use

### Dashboard
1. Navigate to a campaign → click "Intel Graph" button
2. Click "Extract Entities" to populate the graph from existing tool results
3. Click nodes to inspect, right-click to enrich or profile
4. For person entities, create a profile → view susceptibility scores
5. Run behavioral simulations from the profile view

### API
```bash
# Get the full graph
GET /campaigns/{id}/graph

# List entities (with filters)
GET /campaigns/{id}/graph/entities?entity_type=person&min_confidence=0.5

# Enrich an entity
POST /campaigns/{id}/graph/entities/{entity_id}/enrich

# Create a subject profile
POST /campaigns/{id}/subjects/{entity_id}/profile

# Run behavioral simulation
POST /campaigns/{id}/subjects/{subject_id}/simulate
{"num_simulations": 100}

# Reprocess all task outputs
POST /campaigns/{id}/graph/extract
```

## Behavioral Prediction Methodology

The simulation engine adapts MiroFish's multi-agent approach:

1. **Knowledge Graph Seeding** — Entity graph provides organizational context, credential exposure, communication patterns
2. **Persona Generation** — OSINT data maps to behavioral traits (risk tolerance, authority deference, technical savvy)
3. **Monte Carlo Simulation** — N independent AI-simulated interactions per scenario with parameter variation (time, urgency, channel)
4. **Statistical Aggregation** — Success rates with binomial confidence intervals, weighted overall susceptibility (60% average + 40% max)
5. **Report Synthesis** — Coordinator agent synthesizes findings into actionable SE playbook

## Limitations

- **Simulation fidelity** depends on OSINT data quality — sparse data yields low-confidence predictions
- **No real breach data integration** — HIBP API patterns are stubbed, not connected to live services
- **BloodHound integration** is collection-level only — Neo4j Cypher queries require separate BloodHound instance
- **LLM dependency** — enrichment, profiling, and simulation require configured AI providers
- **No persistent simulation history** — results stored in subject profile JSON blob, not queryable independently
- **Frontend requires npm install** — `react-force-graph-2d` dependency added but npm not available in current environment

## Future Improvements

- Connect to live OSINT APIs (HIBP, Shodan, Hunter.io, LinkedIn scraping)
- Add interactive post-simulation agent chat (MiroFish-style "ask the simulated target" mode)
- Build attack path visualization overlaying the entity graph
- Add credential correlation (link hashes to breach databases, detect password reuse)
- Export SE playbooks as PDF/DOCX reports
- Add graph clustering by AD group / network segment / organization
- Real-time graph updates via SSE as tools discover new entities during active phases

## Test Coverage

59 new tests across 3 test files:
- `tests/test_intel/test_models.py` — Entity, Relationship, SubjectProfile CRUD (28 tests)
- `tests/test_intel/test_extractor.py` — extraction from nmap, theHarvester, responder, secretsdump, kerberoast, AS-REP (21 tests)
- `tests/test_intel/test_intel_api.py` — graph, entity, subject, extraction API endpoints (10 tests)

All 153 tests pass (94 original + 59 new).
