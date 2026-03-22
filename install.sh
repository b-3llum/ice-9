#!/bin/bash
# ============================================================
#  ice_9 installer — sets up the full platform from a fresh clone
# ============================================================
#  Usage:  ./install.sh [--no-systemd] [--no-dashboard]
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
RST='\033[0m'

header()  { echo -e "\n${CYN}━━━ $1 ━━━${RST}"; }
ok()      { echo -e "  ${GRN}✓${RST} $1"; }
warn()    { echo -e "  ${YLW}!${RST} $1"; }
fail()    { echo -e "  ${RED}✗${RST} $1"; }
die()     { fail "$1"; exit 1; }

# ── Parse flags ───────────────────────────────────────────────
INSTALL_SYSTEMD=true
INSTALL_DASHBOARD=true

for arg in "$@"; do
    case "$arg" in
        --no-systemd)   INSTALL_SYSTEMD=false ;;
        --no-dashboard) INSTALL_DASHBOARD=false ;;
        --help|-h)
            echo "Usage: ./install.sh [--no-systemd] [--no-dashboard]"
            echo ""
            echo "Options:"
            echo "  --no-systemd    Skip systemd service installation"
            echo "  --no-dashboard  Skip dashboard (Node.js) setup"
            exit 0
            ;;
        *) die "Unknown option: $arg" ;;
    esac
done

# ── Resolve paths ─────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"
DASHBOARD_DIR="${REPO_DIR}/dashboard"
DEPLOY_DIR="${REPO_DIR}/deploy"
CURRENT_USER="$(whoami)"

header "ice_9 Installer"
echo -e "  Repo:      ${CYN}${REPO_DIR}${RST}"
echo -e "  User:      ${CYN}${CURRENT_USER}${RST}"

# ── Check Python ──────────────────────────────────────────────
header "Checking prerequisites"

PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done
[[ -z "$PYTHON" ]] && die "Python 3.10+ is required but not found"

PY_VERSION=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$("$PYTHON" -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$("$PYTHON" -c 'import sys; print(sys.version_info.minor)')

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MINOR" -lt 10 ]]; then
    die "Python 3.10+ required, found ${PY_VERSION}"
fi
ok "Python ${PY_VERSION} (${PYTHON})"

# ── Check Node.js (for dashboard) ────────────────────────────
NPX_PATH=""
NODE_BIN_DIR=""
if [[ "$INSTALL_DASHBOARD" == true ]]; then
    # Find npx — check common locations
    if command -v npx &>/dev/null; then
        NPX_PATH="$(command -v npx)"
    else
        # Search nvm, fnm, and common locations
        for candidate in \
            "$HOME/.nvm/versions/node"/*/bin/npx \
            "$HOME/.fnm/node-versions"/*/installation/bin/npx \
            "$HOME/.local/share/nvm"/*/bin/npx \
            /usr/local/bin/npx \
            /usr/bin/npx; do
            if [[ -x "$candidate" ]]; then
                NPX_PATH="$candidate"
                break
            fi
        done
    fi

    if [[ -z "$NPX_PATH" ]]; then
        warn "npx not found — dashboard will not be installed"
        warn "Install Node.js 18+ and re-run, or use --no-dashboard"
        INSTALL_DASHBOARD=false
    else
        NODE_BIN_DIR="$(dirname "$NPX_PATH")"
        NODE_VERSION=$("${NODE_BIN_DIR}/node" --version 2>/dev/null || echo "unknown")
        ok "Node.js ${NODE_VERSION} (${NODE_BIN_DIR})"
    fi
fi

# ── Create virtual environment ────────────────────────────────
header "Setting up Python environment"

if [[ -d "$VENV_DIR" ]]; then
    ok "Virtual environment already exists at ${VENV_DIR}"
else
    echo -e "  Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
    ok "Created ${VENV_DIR}"
fi

# Activate
source "${VENV_DIR}/bin/activate"

# ── Install Python package ────────────────────────────────────
header "Installing ice_9"
pip install --upgrade pip -q
pip install -e "${REPO_DIR}" -q
ok "ice_9 installed ($(ice9 --help 2>/dev/null | head -1 || echo 'entry point ready'))"

# ── Verify ice9 CLI ───────────────────────────────────────────
if command -v ice9 &>/dev/null; then
    ok "ice9 CLI available"
else
    warn "ice9 not on PATH — activate venv first: source ${VENV_DIR}/bin/activate"
fi

# ── Install dashboard ────────────────────────────────────────
if [[ "$INSTALL_DASHBOARD" == true ]]; then
    header "Setting up dashboard"
    if [[ ! -d "$DASHBOARD_DIR" ]]; then
        warn "Dashboard directory not found at ${DASHBOARD_DIR}"
        INSTALL_DASHBOARD=false
    else
        cd "$DASHBOARD_DIR"
        if [[ -d "node_modules" ]]; then
            ok "node_modules already exists"
        else
            echo -e "  Installing npm dependencies..."
            PATH="${NODE_BIN_DIR}:$PATH" npm install --silent 2>/dev/null
            ok "npm dependencies installed"
        fi
        cd "$REPO_DIR"
    fi
fi

# ── Generate and install systemd services ─────────────────────
if [[ "$INSTALL_SYSTEMD" == true ]]; then
    header "Generating systemd service files"

    # Build extra PATH components
    EXTRA_PATHS=""
    # venv bin
    EXTRA_PATHS="${VENV_DIR}/bin"
    # Go bin
    [[ -d "$HOME/go/bin" ]] && EXTRA_PATHS="${EXTRA_PATHS}:${HOME}/go/bin"
    # local bin
    [[ -d "$HOME/.local/bin" ]] && EXTRA_PATHS="${EXTRA_PATHS}:${HOME}/.local/bin"
    # System
    EXTRA_PATHS="${EXTRA_PATHS}:/usr/local/bin:/usr/bin:/bin"

    # ── ice9-api.service ──
    API_SERVICE="${DEPLOY_DIR}/ice9-api.service"
    cat > "$API_SERVICE" <<UNIT
[Unit]
Description=ice_9 Red Team Orchestration API
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=exec
User=${CURRENT_USER}
Group=${CURRENT_USER}
WorkingDirectory=${REPO_DIR}
Environment=PATH=${EXTRA_PATHS}
Environment=VIRTUAL_ENV=${VENV_DIR}
EnvironmentFile=-${REPO_DIR}/.env

ExecStart=${VENV_DIR}/bin/uvicorn ice_9.api:app \\
    --host 0.0.0.0 \\
    --port 8443 \\
    --log-level info

Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    ok "Generated ${API_SERVICE}"

    # ── ice9-dashboard.service ──
    if [[ "$INSTALL_DASHBOARD" == true ]] && [[ -n "$NPX_PATH" ]]; then
        DASH_SERVICE="${DEPLOY_DIR}/ice9-dashboard.service"
        DASH_PATH="${NODE_BIN_DIR}:${DASHBOARD_DIR}/node_modules/.bin:/usr/local/bin:/usr/bin:/bin"
        cat > "$DASH_SERVICE" <<UNIT
[Unit]
Description=ice_9 Dashboard (Vite dev server)
After=ice9-api.service
Wants=ice9-api.service

[Service]
Type=exec
User=${CURRENT_USER}
Group=${CURRENT_USER}
WorkingDirectory=${DASHBOARD_DIR}
Environment=PATH=${DASH_PATH}

ExecStart=${NPX_PATH} vite --host 0.0.0.0 --port 3000

Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
        ok "Generated ${DASH_SERVICE}"
    fi

    # ── Install to systemd ──
    echo ""
    echo -e "  ${YLW}Install services to systemd? This requires sudo.${RST}"
    read -rp "  Install and enable services? [y/N]: " CONFIRM
    if [[ "${CONFIRM,,}" == "y" ]]; then
        sudo cp "${DEPLOY_DIR}/ice9-api.service" /etc/systemd/system/
        ok "Copied ice9-api.service"

        if [[ "$INSTALL_DASHBOARD" == true ]] && [[ -f "${DEPLOY_DIR}/ice9-dashboard.service" ]]; then
            sudo cp "${DEPLOY_DIR}/ice9-dashboard.service" /etc/systemd/system/
            ok "Copied ice9-dashboard.service"
        fi

        sudo systemctl daemon-reload
        ok "Daemon reloaded"

        sudo systemctl enable --now ice9-api
        ok "ice9-api enabled and started"

        if [[ "$INSTALL_DASHBOARD" == true ]]; then
            sudo systemctl enable --now ice9-dashboard
            ok "ice9-dashboard enabled and started"
        fi
    else
        echo ""
        echo -e "  Skipped. To install manually later:"
        echo -e "    ${CYN}sudo cp ${DEPLOY_DIR}/ice9-*.service /etc/systemd/system/${RST}"
        echo -e "    ${CYN}sudo systemctl daemon-reload${RST}"
        echo -e "    ${CYN}sudo systemctl enable --now ice9-api ice9-dashboard${RST}"
    fi
fi

# ── Check offensive tools ─────────────────────────────────────
header "Checking offensive tools"
echo -e "  Run ${CYN}ice9 tool list${RST} to see which tools are installed."
echo -e "  Missing tools won't break ice_9 — phases will skip unavailable tools."

# ── Summary ───────────────────────────────────────────────────
header "Installation complete"
echo ""
echo -e "  ${GRN}CLI:${RST}        source ${VENV_DIR}/bin/activate && ice9 --help"
echo -e "  ${GRN}API:${RST}        http://localhost:8443"
if [[ "$INSTALL_DASHBOARD" == true ]]; then
    echo -e "  ${GRN}Dashboard:${RST}  http://localhost:3000"
fi
echo -e "  ${GRN}Services:${RST}   ice9-services status"
echo -e "  ${GRN}Tools:${RST}      ice9 tool list"
echo ""
echo -e "  ${YLW}Quick start:${RST}"
echo -e "    ice9 campaign create -n \"My Pentest\" -s \"10.10.10.0/24\""
echo -e "    ice9 campaign list"
echo ""
