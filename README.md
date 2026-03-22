# ice_9

![ice_9](https://raw.githubusercontent.com/b-3llum/ice-9/main/assets/banner.png)

**Red Team Orchestration Platform — MITRE ATT&CK-Aligned Campaign Management**

![version](https://img.shields.io/badge/version-0.1.0-blue)
![python](https://img.shields.io/badge/python-3.10+-blue)
![platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![license](https://img.shields.io/badge/license-Private-lightgrey)

---

## Overview

**ice_9** is a red team orchestration platform that manages the full lifecycle of a penetration testing engagement — from reconnaissance through impact. It maps every operation to the MITRE ATT&CK framework, integrates 16 offensive tools under a unified interface, and orchestrates a multi-agent AI team that can plan engagements, analyse results, and execute phases autonomously.

Instead of running tools manually and tracking findings in spreadsheets, ice_9 provides a campaign database, structured phase execution, automated finding extraction, and a real-time web dashboard with live event streaming.

---

## Architecture

```
                      ┌───────────────────────────┐
                      │      Dashboard (React)     │
                      │  PhaseTimeline │ ActivityFeed│ FindingsTable
                      └──────────┬────────────────┘
                            SSE / REST
                      ┌──────────┴────────────────┐
                      │     FastAPI REST Server     │
                      │  /campaigns  /phases  /ai   │
                      │  /tools  /events/stream     │
                      └──────────┬────────────────┘
                           EventBus (pub/sub)
             ┌───────────────┼───────────────┐
             │               │               │
     ┌───────┴──────┐ ┌─────┴──────┐ ┌──────┴──────┐
     │ Phase Engine │ │  AI Team   │ │ Tool Runner │
     │ 13 ATT&CK   │ │ 6 Agents   │ │ 16 Wrappers │
     │ modules      │ │ multi-LLM  │ │ subprocess  │
     └───────┬──────┘ └─────┬──────┘ └──────┬──────┘
             └───────────────┼───────────────┘
                      ┌──────┴──────┐
                      │   SQLite    │
                      │ campaigns,  │
                      │ findings,   │
                      │ audit trail │
                      └─────────────┘
```

---

## Integrated Tools

    nmap               Network scanner — host discovery, port scanning, service detection
    nuclei             Template-based vulnerability scanner
    kerb-map           Kerberos attack surface mapper — SPNs, AS-REP, delegation, encryption
    bloodhound         AD attack path analysis via bloodhound-python
    crackmapexec       Credential spraying, share enumeration, command execution
    metasploit         Exploitation framework — module execution, session management
    secretsdump        Extract SAM, LSA secrets, cached creds, NTDS.dit
    getnpusers         AS-REP roasting — TGTs for accounts without pre-auth
    getuserspns        Kerberoasting — TGS tickets for service accounts
    psexec             Remote command execution via SMB
    wmiexec            Remote command execution via WMI
    ntlmrelayx         NTLM relay attack framework
    theharvester       OSINT — email, subdomain, host harvesting
    amass              Attack surface mapping and subdomain enumeration
    subfinder          Passive subdomain discovery via multiple sources
    responder          LLMNR/NBT-NS/MDNS poisoner — capture Net-NTLM hashes

All tools are detected automatically via `$PATH`. Configure additional search paths in `ice9.yaml` with the `tool_paths` directive.

---

## ATT&CK Phase Modules

ice_9 maps every operation to a MITRE ATT&CK tactic. Each phase module knows which tools to run, how to plan tasks against the campaign scope, and how to extract findings from tool output.

| Phase | ATT&CK ID | Primary Tools |
|---|---|---|
| Reconnaissance | TA0043 | nmap, nuclei, theharvester, amass, subfinder |
| Resource Development | TA0042 | metasploit |
| Initial Access | TA0001 | nuclei, metasploit |
| Execution | TA0002 | psexec, wmiexec, metasploit |
| Persistence | TA0003 | metasploit |
| Privilege Escalation | TA0004 | metasploit, crackmapexec |
| Defense Evasion | TA0005 | metasploit |
| Credential Access | TA0006 | kerb-map, secretsdump, getnpusers, getuserspns, responder |
| Discovery | TA0007 | bloodhound, crackmapexec, nmap |
| Lateral Movement | TA0008 | psexec, wmiexec, crackmapexec, ntlmrelayx |
| Collection | TA0009 | crackmapexec |
| Exfiltration | TA0010 | — |
| Impact | TA0040 | metasploit |

---

## AI Agent Team

ice_9 orchestrates a multi-agent AI team. Each agent has a specialised role and system prompt. Agents run in parallel, results are synthesised by the coordinator.

| Agent | Role |
|---|---|
| **Coordinator** | Red team lead — plans engagements, assigns tasks, synthesises results |
| **Recon Analyst** | Analyses scan data, maps attack surfaces, prioritises targets |
| **Exploit Researcher** | Researches CVEs, assesses exploitability, suggests attack vectors |
| **Social Engineer** | Profiles organisations, recommends phishing/pretexting scenarios |
| **Report Writer** | Drafts findings with severity ratings and remediation guidance |
| **Code Analyst** | Reviews source code for OWASP Top 10 and CWE issues |

**Supported LLM providers:** Ollama (local, default), Anthropic Claude, OpenAI, Groq, Mistral. Provider fallback chains are supported — if one provider fails, the next is tried automatically.

**Autopilot mode** (`ice9 campaign auto`) lets the AI coordinator select and execute phases iteratively, producing a full engagement with zero manual intervention.

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Offensive tools installed and accessible via `$PATH`
- Ollama running locally (default LLM provider), or API keys for cloud providers

### Install

```bash
git clone https://github.com/b-3llum/ice-9 ~/ice-9
cd ~/ice-9
pip install -e .
```

### Verify

```bash
ice9 --help
```

---

## Configuration

ice_9 loads configuration from the first file found:

1. `./config/ice9.yaml`
2. `./ice9.yaml`
3. `~/.ice9/config.yaml`

```yaml
# ice9.yaml
data_dir: ~/.ice9

# Extra directories to search for tool binaries
tool_paths:
  - ~/.local/bin
  - /opt/impacket/bin

# LLM providers
providers:
  ollama:
    base_url: "http://localhost:11434"
    model: "llama3.2:3b"
  # claude:
  #   api_key: "${ANTHROPIC_API_KEY}"
  #   model: "claude-sonnet-4-6-20250514"
  # openai:
  #   api_key: "${OPENAI_API_KEY}"
  #   model: "gpt-4o"

# Agent role assignments
agents:
  coordinator:
    provider: ollama
    model: "llama3.2:3b"
  recon_analyst:
    provider: ollama
  exploit_researcher:
    provider: ollama
  report_writer:
    provider: ollama
```

Environment variables are resolved with `${VAR_NAME}` syntax in YAML values.

---

## Usage

### Campaign Lifecycle

```bash
# Create a campaign with scope targets
ice9 campaign create -n "Corp Pentest" -s "10.10.10.0/24" "corp.local"

# List campaigns
ice9 campaign list

# Show campaign detail — phases, findings, progress
ice9 campaign show <campaign_id>

# Activate, pause, resume, complete, abort
ice9 campaign activate <id>
ice9 campaign pause <id>
ice9 campaign complete <id>
```

### Phase Execution

```bash
# Run a single phase (by name or ATT&CK ID)
ice9 phase run <campaign_id> recon
ice9 phase run <campaign_id> credential_access
ice9 phase run <campaign_id> TA0007

# Skip a phase
ice9 phase skip <campaign_id> resource_dev
```

### AI Operations

```bash
# Generate an AI engagement plan
ice9 campaign show <id>   # AI plan included in output

# Full autopilot — AI selects and executes up to 5 phases
ice9 campaign auto <id> --max 5
```

### REST API

```bash
# Start the API server
uvicorn ice_9.api:app --host 0.0.0.0 --port 8000

# With API key authentication
ICE9_API_KEY=your_key uvicorn ice_9.api:app --host 0.0.0.0 --port 8443
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev          # Dev server → http://localhost:5173
npm run build        # Production build
```

---

## Real-Time Events

ice_9 emits structured events for every operation via an in-process event bus. The API exposes these as Server-Sent Events for live dashboard updates.

| Event | Description |
|---|---|
| `tool_start` | Tool binary launched with target and args |
| `tool_output` | Batched stdout lines from running tool |
| `tool_complete` | Tool finished — duration, return code |
| `tool_error` | Tool failed — error message |
| `phase_start` | Phase execution began |
| `phase_plan` | AI generated task plan for phase |
| `phase_task_start` | Individual task within phase started |
| `phase_task_complete` | Task finished — success/failure, duration |
| `phase_complete` | Phase execution finished |
| `ai_request` | LLM request sent to provider |
| `ai_chunk` | Streaming token from LLM |
| `ai_response` | Complete LLM response received |
| `auto_phase_select` | Autopilot AI selected next phase |
| `auto_complete` | Autopilot run finished |
| `finding_new` | New vulnerability finding created |

```bash
# Subscribe to live events
curl -N http://localhost:8443/events/stream?campaign_id=<id>

# Get recent event history
curl http://localhost:8443/events/recent?limit=50
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/campaigns` | Create campaign |
| GET | `/campaigns` | List campaigns |
| GET | `/campaigns/{id}` | Campaign detail |
| PUT | `/campaigns/{id}/status` | Transition status |
| DELETE | `/campaigns/{id}` | Delete campaign |
| POST | `/campaigns/{id}/phases/{phase}/run` | Execute phase (live events) |
| GET | `/campaigns/{id}/phases/running` | Check running phase |
| GET | `/campaigns/{id}/findings` | List findings |
| POST | `/campaigns/{id}/ai/plan` | AI engagement plan |
| POST | `/campaigns/{id}/ai/analyze` | Multi-agent analysis |
| POST | `/campaigns/{id}/ai/ask` | Query specific agent |
| POST | `/campaigns/{id}/ai/auto` | AI autopilot |
| GET | `/tools` | List tools + availability |
| GET | `/ai/agents` | List AI agents |
| GET | `/ai/providers` | List LLM providers |
| GET | `/events/stream` | SSE event stream |
| GET | `/events/recent` | Event history buffer |

---

## Reporting

ice_9 generates structured DOCX penetration test reports with:

- Executive summary
- Scope and methodology
- Findings table with severity breakdown (Critical / High / Medium / Low / Info)
- Detailed finding descriptions with evidence and remediation
- ATT&CK technique mapping
- AI-generated attack narrative

---

## Project Structure

```
ice_9/
├── ai/
│   ├── agents.py          # Agent definitions, roles, system prompts
│   ├── llm.py             # Multi-provider LLM client (Ollama, Claude, OpenAI, Groq, Mistral)
│   ├── orchestrator.py    # Campaign autopilot — AI phase selection
│   ├── providers.py       # Provider registry and fallback chains
│   └── team.py            # Multi-agent parallel orchestration
├── config/
│   └── settings.py        # YAML config loading, path resolution, tool_paths
├── core/
│   ├── audit.py           # Audit logging
│   ├── campaign.py        # Campaign lifecycle operations
│   ├── events.py          # EventBus singleton — real-time observability
│   ├── models.py          # Pydantic models — Campaign, Phase, Task, Finding
│   └── state.py           # State machine validation
├── db/
│   └── store.py           # SQLite persistence (WAL mode, cascade deletes)
├── phases/
│   ├── base.py            # PhaseModule base class
│   ├── recon.py           # TA0043 — Reconnaissance
│   ├── credential_access.py # TA0006 — Credential Access
│   ├── lateral_movement.py  # TA0008 — Lateral Movement
│   └── ...                # 13 phase modules total
├── tools/
│   ├── base.py            # ToolWrapper base class — build_command, parse_output, run
│   ├── nmap.py            # Network scanner integration
│   ├── kerb_map.py        # kerb-map AD attack surface mapper
│   ├── impacket.py        # Impacket suite (6 tools)
│   └── ...                # 16 tool wrappers total
├── reporting/
│   └── generator.py       # DOCX report generation
├── api.py                 # FastAPI REST + SSE endpoints
├── cli.py                 # Typer CLI commands
└── main.py                # Entry point

dashboard/                 # React/TypeScript web UI
├── src/
│   ├── api/               # Typed API client
│   ├── components/        # PhaseTimeline, ActivityFeed, FindingsTable, AIChat
│   ├── hooks/             # useEventStream (SSE), React Query
│   └── types/             # TypeScript interfaces
└── vite.config.ts
```

---

## Legal

ice_9 is designed exclusively for use in **authorised** penetration testing engagements and red team operations where written permission has been obtained from the system owner.

Use against systems for which you do not have explicit written authorisation is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation worldwide. The author assumes no liability for misuse.
