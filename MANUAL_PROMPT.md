# Task: Create Comprehensive ice_9 User Manual

You are updating the documentation for **ice_9**, a red team orchestration platform. The project lives at `~/projects/redforge/` (package name: `ice_9`). You need to **rewrite `README.md`** into a comprehensive user manual that serves as both a quick-start guide and a full reference. It should be clear enough that someone with basic pentest knowledge can install, configure, and operate the platform from scratch.

## What to produce

**Rewrite `/home/bellum/projects/redforge/README.md`** — a single comprehensive manual covering everything below. Also update `/home/bellum/projects/redforge/deploy/README.md` to be consistent with the main manual.

## Requirements

1. **Include visual documentation** — Run CLI commands and capture their output as fenced code blocks. Take screenshots of the web dashboard pages (Campaigns list, Campaign detail with phase timeline, Tools page, AI Agents page) and save them as PNG files in `assets/` then reference them with `![description](assets/filename.png)`.

2. **Structure** — Use the outline below. Every section must have practical examples, not just descriptions.

3. **Tone** — Direct, professional, no fluff. Written for red team operators.

---

## Manual Outline

### 1. Header & Overview
- Banner image (already exists at `assets/banner.png`)
- One-paragraph description of what ice_9 does
- Key capabilities bullet list (campaign management, 16 tools, 13 ATT&CK phases, multi-agent AI, real-time dashboard, DOCX reporting)

### 2. Architecture
- Keep the existing mermaid diagrams (architecture, state machine, phase execution flow) — they're good
- Add a brief text explanation of each layer

### 3. Installation

#### 3a. Prerequisites
- Python 3.10+
- Node.js 18+ (for dashboard)
- Ollama running locally (default LLM provider)
- Offensive tools (nmap, nuclei, etc.) installed and in PATH

#### 3b. Install from source
```bash
git clone <repo> ~/projects/redforge
cd ~/projects/redforge
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

#### 3c. Install offensive tools
Document how to install the 16 integrated tools. Group by install method:
- **System packages (pacman/apt):** nmap, metasploit
- **Go tools:** nuclei, amass, subfinder (`go install ...`)
- **pip tools (install into the project venv):** bloodhound-python, impacket, theHarvester
- **AUR/manual:** nxc (netexec), Responder (clone to /opt/Responder)
- **Your own tools:** kerb-map (already at ~/kerb-map)
- Note: Run `ice9 tool list` to verify all 16 show as "available"

#### 3d. Install dashboard
```bash
cd dashboard
npm install
```

#### 3e. Verify installation
Show expected output of `ice9 --help` and `ice9 tool list` (all 16 available, 0 missing).

### 4. Configuration

#### 4a. Config file locations
ice_9 searches: `./config/ice9.yaml` → `./ice9.yaml` → `~/.ice9/config.yaml`

#### 4b. Full annotated config example
Show the complete `config/ice9.yaml` with comments explaining every field:
- `data_dir` — where SQLite DB and evidence are stored
- `tool_paths` — extra directories to search for binaries
- `providers` — LLM provider configs (ollama, claude, openai, groq, mistral)
- `agents` — per-agent provider/model/system_prompt overrides
- Environment variable syntax: `${VAR_NAME}`

#### 4c. Environment variables
| Variable | Purpose | Default |
|---|---|---|
| `ICE9_API_KEY` | REST API authentication key | (none — open) |
| `ICE9_CORS_ORIGINS` | Allowed CORS origins | `*` |
| `ICE9_HOME` | Data directory override | `~/.ice9` |
| `ANTHROPIC_API_KEY` | Claude API key | — |
| `OPENAI_API_KEY` | OpenAI API key | — |
| `GROQ_API_KEY` | Groq API key | — |

### 5. Running ice_9

#### 5a. CLI only (simplest)
```bash
source .venv/bin/activate
ice9 campaign create -n "Test" -s "10.10.10.0/24"
ice9 campaign list
```

#### 5b. API server
```bash
source .venv/bin/activate
uvicorn ice_9.api:app --host 0.0.0.0 --port 8443
```

#### 5c. Dashboard
```bash
cd dashboard
npm run dev
# Dashboard at http://localhost:3000, proxies /api to localhost:8443
```

#### 5d. Systemd services (recommended for persistent operation)
Document the service files and how to install them:

**ice9-api.service:**
```ini
[Unit]
Description=ice_9 Red Team Orchestration API (dev)
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=exec
User=bellum
Group=bellum
WorkingDirectory=/home/bellum/projects/redforge
Environment=PATH=/home/bellum/projects/redforge/.venv/bin:/home/bellum/go/bin:/home/bellum/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=VIRTUAL_ENV=/home/bellum/projects/redforge/.venv
EnvironmentFile=-/home/bellum/projects/redforge/.env
ExecStart=/home/bellum/projects/redforge/.venv/bin/uvicorn ice_9.api:app --host 0.0.0.0 --port 8443 --log-level info
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

**ice9-dashboard.service:**
```ini
[Unit]
Description=ice_9 Dashboard (Vite dev server)
After=ice9-api.service
Wants=ice9-api.service

[Service]
Type=exec
User=bellum
Group=bellum
WorkingDirectory=/home/bellum/projects/redforge/dashboard
Environment=PATH=/home/bellum/.nvm/versions/node/v22.22.1/bin:/home/bellum/projects/redforge/dashboard/node_modules/.bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/home/bellum/.nvm/versions/node/v22.22.1/bin/npx vite --host 0.0.0.0 --port 3000
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

**Installation:**
```bash
sudo cp ice9-api.service ice9-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ice9-api ice9-dashboard
```

**bellum-services integration:**
Mention that these are integrated into the `bellum-services` script for unified management:
```bash
bellum-services status    # shows all services including ice9-api, ice9-dashboard
bellum-services restart   # restarts everything
bellum-services logs ice9-api  # tail API logs
```

### 6. CLI Reference

Document every command group with examples and expected output. Include actual CLI output in fenced code blocks.

#### 6a. Campaign Management
- `ice9 campaign create` — all flags (`-n`, `-s`, `--client`, `--lead`, `--description`)
- `ice9 campaign list` — with `--status` filter
- `ice9 campaign show <id>` — show the rich panel + phase table
- `ice9 campaign activate/pause/resume/complete/abort <id>`
- `ice9 campaign delete <id>` — with confirmation prompt
- `ice9 campaign auto <id> --max N` — AI autopilot

#### 6b. Phase Execution
- `ice9 phase list <id>` — show phase status table
- `ice9 phase run <id> recon` — run by name
- `ice9 phase run <id> TA0006` — run by ATT&CK ID
- `ice9 phase skip <id> resource_dev`
- `ice9 phase start/complete <id> <phase>` — manual transitions

#### 6c. Tool Management
- `ice9 tool list` — show the availability table
- `ice9 tool run nmap --target 10.10.10.0/24 --campaign <id>` — direct tool execution
- `ice9 tool add --name mytool --binary /path/to/tool --desc "description" --attck T1234`

#### 6d. AI Team
- `ice9 team status` — show agent/provider table
- `ice9 team ask "analyze these results" --agent recon_analyst --campaign <id>`
- `ice9 team run <id> --prompt "what attack paths exist?"`
- `ice9 team plan <id>` — generate engagement plan
- `ice9 team analyze <id>` — analyze findings

#### 6e. Reporting
- `ice9 report generate <id>` — default DOCX output
- `ice9 report generate <id> --output report.docx --ai-summary --ai-narrative`

#### 6f. Audit
- `ice9 audit show --limit 50 --campaign <id>`

### 7. REST API Reference

Full endpoint table with:
- Method, path, description
- Request/response examples for key endpoints (create campaign, run phase, AI auto)
- Authentication header: `X-API-Key: <key>`
- SSE stream usage with curl

### 8. Web Dashboard Guide

For each page, include a screenshot and description:

#### 8a. Campaigns Page
- Screenshot of campaign list view
- Shows: name, status badge, scope, progress bar, findings count, created date
- Click campaign name to drill into detail

#### 8b. Campaign Detail Page
- Screenshot of detail view
- Sections: stats cards (progress, findings, scope, created), ATT&CK phase timeline with Run buttons, Live Activity feed (SSE), Findings table with severity filters, AI Assistant panel with Generate Plan / Analyze Findings / agent chat

#### 8c. Tools Page
- Screenshot of tools list
- Shows: 16 tools with binary path, availability status, ATT&CK IDs, description
- "16 available 0 missing" header

#### 8d. AI Agents Page
- Screenshot of agents page
- Left: agent roles with provider/model/status
- Right: LLM providers with API key status

### 9. Workflow Examples

#### 9a. Full engagement walkthrough (CLI)
Step-by-step from campaign creation through report generation:
```bash
# 1. Create campaign
ice9 campaign create -n "Corp Pentest" -s "10.10.10.0/24" "172.16.0.0/16" --client "ACME Corp" --lead "operator"

# 2. Activate
ice9 campaign activate <id>

# 3. Run recon
ice9 phase run <id> recon

# 4. Run credential access
ice9 phase run <id> credential_access

# 5. Check findings
ice9 findings list <id>

# 6. Generate report
ice9 report generate <id> --ai-summary --ai-narrative

# 7. Complete campaign
ice9 campaign complete <id>
```

#### 9b. AI autopilot walkthrough
```bash
ice9 campaign create -n "Auto Engagement" -s "10.10.10.0/24"
ice9 campaign activate <id>
ice9 campaign auto <id> --max 5
# AI selects and executes up to 5 phases automatically
```

#### 9c. Using the dashboard
Describe the workflow visually — create campaign, watch phase timeline, click Run on phases, monitor Live Activity feed, review findings, use AI chat.

### 10. Integrated Tools Reference

Table of all 16 tools with:
| Tool | Binary | ATT&CK Techniques | Install Method | Description |
Each tool gets one row.

### 11. ATT&CK Phase Modules

Table of all 13 phases with:
| Phase | ATT&CK ID | Tools Used | Description |

### 12. AI Agent Team

Table of all 6 agents. Explain:
- Provider fallback chains
- How to configure different providers per agent
- Autopilot mode behavior

### 13. Troubleshooting

Common issues and fixes:

| Problem | Cause | Fix |
|---|---|---|
| Tools show as MISSING | Binary not in PATH | Install tool or add path to `tool_paths` in ice9.yaml. Run `ice9 tool list` to verify |
| `address already in use` on port 8443 | Old uvicorn process | `kill $(lsof -ti:8443)` then restart |
| Dashboard shows stale data | API server not running or wrong port | Start API: `uvicorn ice_9.api:app --port 8443` |
| ice9-dashboard.service fails | npx not found (nvm not in systemd PATH) | Use full nvm path in service file: `/home/user/.nvm/versions/node/vX.X.X/bin/npx` |
| ice9-api.service fails | Port conflict or missing venv | Check `journalctl -u ice9-api -n 30`, kill port conflicts, verify venv path |
| Impacket tools not found | pip names differ from system packages | pip installs as `secretsdump.py` not `impacket-secretsdump`. ice_9 handles this automatically |
| netexec won't install via pip | Python 3.14 compatibility | Install via system package manager (e.g., `yay -S netexec` on Arch) |
| AI agents return errors | Ollama not running or model not pulled | `systemctl start ollama && ollama pull llama3.2:3b` |
| theHarvester wrong package | PyPI `theHarvester` 0.0.1 is a placeholder | Install from git: `pip install "theHarvester @ git+https://github.com/laramies/theHarvester.git"` |
| Responder wrong package | PyPI `Responder` is a web framework | Clone from GitHub to /opt/Responder, do NOT `pip install Responder` |

### 14. Production Deployment
Reference the existing `deploy/README.md` content — service user, TLS, firewall, gunicorn.

### 15. Project Structure
Keep the existing tree diagram from the current README.

### 16. Legal Disclaimer
Keep the existing legal section.

---

## Existing assets to reference

- `assets/banner.png` — project banner (already exists)
- Dashboard screenshots — take these yourself from `http://localhost:3001` and save to `assets/`
  - `assets/dashboard-campaigns.png` — Campaigns list page
  - `assets/dashboard-campaign-detail.png` — Campaign detail with phase timeline
  - `assets/dashboard-tools.png` — Tools page (16 available, 0 missing)
  - `assets/dashboard-ai-agents.png` — AI Agents page

## CLI outputs to capture

Run these commands and include their output as fenced code blocks in the appropriate sections:
```bash
ice9 --help
ice9 campaign --help
ice9 campaign list
ice9 campaign show a58636ec
ice9 tool list
ice9 team status
ice9 phase --help
ice9 tool --help
ice9 team --help
ice9 report --help
ice9 audit --help
```

## Important notes

- The project is at version 0.1.0
- Entry point is `ice9` (installed via pip as console_scripts)
- API runs on port 8443 by default
- Dashboard runs on port 3000 (Vite dev) and proxies `/api` to `localhost:8443`
- Default LLM provider is Ollama with llama3.2:3b
- The venv is at `/home/bellum/projects/redforge/.venv`
- Go tools are in `~/go/bin`, pip tools in `.venv/bin`
- Tool resolution: ice_9 searches venv/bin, ~/go/bin, ~/.local/bin in addition to system PATH
- Systemd services use full paths because nvm/venv aren't in the default systemd environment
- `bellum-services` script manages all services (ollama, tars, finance-tracker, ice9-api, ice9-dashboard)
- All 16 tools are currently installed and showing as available
