#!/bin/bash
# ============================================================
#  ice_9 installer — sets up the full platform from a fresh clone
# ============================================================
#  Usage:  ./install.sh [--no-services] [--no-dashboard]
#  Works on Linux (systemd) and macOS (launchd)
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

# ── Detect OS ─────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *)      die "Unsupported OS: $OS (Linux and macOS only)" ;;
esac

# ── Parse flags ───────────────────────────────────────────────
INSTALL_SERVICES=true
INSTALL_DASHBOARD=true

for arg in "$@"; do
    case "$arg" in
        --no-services|--no-systemd) INSTALL_SERVICES=false ;;
        --no-dashboard)             INSTALL_DASHBOARD=false ;;
        --help|-h)
            echo "Usage: ./install.sh [--no-services] [--no-dashboard]"
            echo ""
            echo "Options:"
            echo "  --no-services   Skip service installation (systemd on Linux, launchd on macOS)"
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
echo -e "  Platform:  ${CYN}${PLATFORM}${RST}"

# ── Check Python ──────────────────────────────────────────────
header "Checking prerequisites"

PYTHON=""
for cmd in python3.13 python3.12 python3.11 python3.10 python3; do
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
NPM_PATH=""
NODE_BIN_DIR=""
if [[ "$INSTALL_DASHBOARD" == true ]]; then
    if command -v npx &>/dev/null; then
        NPX_PATH="$(command -v npx)"
    else
        # Search nvm, fnm, Homebrew, and common locations
        for candidate in \
            "$HOME/.nvm/versions/node"/*/bin/npx \
            "$HOME/.fnm/node-versions"/*/installation/bin/npx \
            "$HOME/.local/share/nvm"/*/bin/npx \
            /opt/homebrew/bin/npx \
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
        if [[ "$PLATFORM" == "macos" ]]; then
            warn "Install Node.js: brew install node"
        else
            warn "Install Node.js 18+ and re-run, or use --no-dashboard"
        fi
        INSTALL_DASHBOARD=false
    else
        NODE_BIN_DIR="$(dirname "$NPX_PATH")"
        NPM_PATH="${NODE_BIN_DIR}/npm"
        NODE_VERSION=$("${NODE_BIN_DIR}/node" --version 2>/dev/null || echo "unknown")
        ok "Node.js ${NODE_VERSION} (${NODE_BIN_DIR})"
    fi
fi

# ── Check Homebrew on macOS ───────────────────────────────────
if [[ "$PLATFORM" == "macos" ]]; then
    if command -v brew &>/dev/null; then
        ok "Homebrew available"
    else
        warn "Homebrew not found — install from https://brew.sh for easy tool installation"
    fi
fi

# ── Check Ollama ──────────────────────────────────────────────
OLLAMA_RUNNING=false
if command -v ollama &>/dev/null; then
    ok "Ollama installed ($(ollama --version 2>/dev/null | head -1 || echo 'found'))"
    # Check if Ollama is actually running
    if curl -sf http://localhost:11434/api/tags &>/dev/null; then
        ok "Ollama is running"
        OLLAMA_RUNNING=true
        # Check if default model is pulled
        if ollama list 2>/dev/null | grep -q "llama3"; then
            ok "llama3 model available"
        else
            warn "No llama3 model found — pull one: ollama pull llama3.2:3b"
        fi
    else
        warn "Ollama is installed but not running"
        if [[ "$PLATFORM" == "linux" ]]; then
            warn "Start it: sudo systemctl start ollama"
        else
            warn "Start it: open the Ollama app, or run: ollama serve"
        fi
    fi
else
    warn "Ollama not found — AI features require an LLM provider"
    if [[ "$PLATFORM" == "macos" ]]; then
        warn "Install: brew install ollama  (or download from https://ollama.com)"
    else
        warn "Install: curl -fsSL https://ollama.com/install.sh | sh"
    fi
    warn "Or set ANTHROPIC_API_KEY / OPENAI_API_KEY in .env for cloud providers"
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
            PATH="${NODE_BIN_DIR}:$PATH" "$NPM_PATH" install --silent 2>/dev/null
            ok "npm dependencies installed"
        fi
        cd "$REPO_DIR"
    fi
fi

# ── Build extra PATH for services ─────────────────────────────
build_service_path() {
    local svc_path="${VENV_DIR}/bin"
    [[ -d "$HOME/go/bin" ]] && svc_path="${svc_path}:${HOME}/go/bin"
    [[ -d "$HOME/.local/bin" ]] && svc_path="${svc_path}:${HOME}/.local/bin"
    if [[ "$PLATFORM" == "macos" ]]; then
        [[ -d "/opt/homebrew/bin" ]] && svc_path="${svc_path}:/opt/homebrew/bin"
    fi
    svc_path="${svc_path}:/usr/local/bin:/usr/bin:/bin"
    echo "$svc_path"
}

# ── Generate and install services ─────────────────────────────
if [[ "$INSTALL_SERVICES" == true ]]; then
    EXTRA_PATHS="$(build_service_path)"

    if [[ "$PLATFORM" == "linux" ]]; then
        # ━━━ Linux: systemd ━━━
        header "Generating systemd service files"

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

        echo ""
        echo -e "  ${YLW}Install services to systemd? This requires sudo.${RST}"
        CONFIRM=""
        read -rp "  Install and enable services? [y/N]: " CONFIRM || true
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

    elif [[ "$PLATFORM" == "macos" ]]; then
        # ━━━ macOS: launchd ━━━
        header "Generating launchd plist files"

        PLIST_DIR="${DEPLOY_DIR}"
        LAUNCH_DIR="$HOME/Library/LaunchAgents"
        mkdir -p "$LAUNCH_DIR"

        # ── ice9-api plist ──
        API_PLIST="${PLIST_DIR}/com.ice9.api.plist"
        cat > "$API_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ice9.api</string>
    <key>ProgramArguments</key>
    <array>
        <string>${VENV_DIR}/bin/uvicorn</string>
        <string>ice_9.api:app</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>8443</string>
        <string>--log-level</string>
        <string>info</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${REPO_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${EXTRA_PATHS}</string>
        <key>VIRTUAL_ENV</key>
        <string>${VENV_DIR}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${REPO_DIR}/logs/api.log</string>
    <key>StandardErrorPath</key>
    <string>${REPO_DIR}/logs/api.error.log</string>
</dict>
</plist>
PLIST
        ok "Generated ${API_PLIST}"

        # ── ice9-dashboard plist ──
        if [[ "$INSTALL_DASHBOARD" == true ]] && [[ -n "$NPX_PATH" ]]; then
            DASH_PLIST="${PLIST_DIR}/com.ice9.dashboard.plist"
            cat > "$DASH_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ice9.dashboard</string>
    <key>ProgramArguments</key>
    <array>
        <string>${NPX_PATH}</string>
        <string>vite</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>3000</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${DASHBOARD_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${NODE_BIN_DIR}:${DASHBOARD_DIR}/node_modules/.bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${REPO_DIR}/logs/dashboard.log</string>
    <key>StandardErrorPath</key>
    <string>${REPO_DIR}/logs/dashboard.error.log</string>
</dict>
</plist>
PLIST
            ok "Generated ${DASH_PLIST}"
        fi

        # Create logs directory
        mkdir -p "${REPO_DIR}/logs"

        echo ""
        echo -e "  ${YLW}Install services to launchd?${RST}"
        CONFIRM=""
        read -rp "  Install and start services? [y/N]: " CONFIRM || true
        if [[ "${CONFIRM,,}" == "y" ]]; then
            cp "${API_PLIST}" "${LAUNCH_DIR}/"
            launchctl load "${LAUNCH_DIR}/com.ice9.api.plist" 2>/dev/null || true
            launchctl start com.ice9.api 2>/dev/null || true
            ok "ice9-api loaded and started"

            if [[ "$INSTALL_DASHBOARD" == true ]] && [[ -f "${DASH_PLIST}" ]]; then
                cp "${DASH_PLIST}" "${LAUNCH_DIR}/"
                launchctl load "${LAUNCH_DIR}/com.ice9.dashboard.plist" 2>/dev/null || true
                launchctl start com.ice9.dashboard 2>/dev/null || true
                ok "ice9-dashboard loaded and started"
            fi
        else
            echo ""
            echo -e "  Skipped. To install manually later:"
            echo -e "    ${CYN}cp ${PLIST_DIR}/com.ice9.*.plist ~/Library/LaunchAgents/${RST}"
            echo -e "    ${CYN}launchctl load ~/Library/LaunchAgents/com.ice9.api.plist${RST}"
            echo -e "    ${CYN}launchctl load ~/Library/LaunchAgents/com.ice9.dashboard.plist${RST}"
        fi
    fi
fi

# ── Check offensive tools ─────────────────────────────────────
header "Checking offensive tools"
echo -e "  Run ${CYN}ice9 tool list${RST} to see which tools are installed."
echo -e "  Missing tools won't break ice_9 — phases will skip unavailable tools."
if [[ "$PLATFORM" == "macos" ]]; then
    echo ""
    echo -e "  ${YLW}macOS note:${RST} Some tools (Responder, netexec) have limited macOS support."
    echo -e "  For full tool coverage, run ice_9 on a Linux host or VM."
fi

# ── Shell activation hint ─────────────────────────────────────
header "Shell setup"

# Detect shell config file
SHELL_RC=""
case "$(basename "${SHELL:-/bin/bash}")" in
    zsh)  SHELL_RC="$HOME/.zshrc" ;;
    bash)
        if [[ "$PLATFORM" == "macos" ]]; then
            SHELL_RC="$HOME/.bash_profile"
        else
            SHELL_RC="$HOME/.bashrc"
        fi
        ;;
    fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
esac

# Check if alias already exists
ALIAS_LINE="alias ice9='source ${VENV_DIR}/bin/activate && ice9'"
ALIAS_EXISTS=false
if [[ -n "$SHELL_RC" ]] && [[ -f "$SHELL_RC" ]] && grep -qF "alias ice9=" "$SHELL_RC" 2>/dev/null; then
    ALIAS_EXISTS=true
fi

if [[ "$ALIAS_EXISTS" == true ]]; then
    ok "Shell alias already configured in ${SHELL_RC}"
else
    echo -e "  To use ${CYN}ice9${RST} without manually activating the venv each time,"
    echo -e "  you can add a shell alias."
    echo ""
    if [[ -n "$SHELL_RC" ]]; then
        ADD_ALIAS=""
        read -rp "  Add ice9 alias to ${SHELL_RC}? [y/N]: " ADD_ALIAS || true
        if [[ "${ADD_ALIAS,,}" == "y" ]]; then
            echo "" >> "$SHELL_RC"
            echo "# ice_9 — activate venv automatically" >> "$SHELL_RC"
            echo "${ALIAS_LINE}" >> "$SHELL_RC"
            ok "Added alias to ${SHELL_RC}"
            echo -e "  Run ${CYN}source ${SHELL_RC}${RST} or open a new terminal to use it."
        else
            echo ""
            echo -e "  Skipped. To activate manually each time:"
            echo -e "    ${CYN}source ${VENV_DIR}/bin/activate${RST}"
            echo ""
            echo -e "  Or add this alias yourself:"
            echo -e "    ${CYN}${ALIAS_LINE}${RST}"
        fi
    else
        echo -e "  Add this to your shell config:"
        echo -e "    ${CYN}${ALIAS_LINE}${RST}"
    fi
fi

# ── Summary ───────────────────────────────────────────────────
header "Installation complete"
echo ""
echo -e "  ${GRN}CLI:${RST}        source ${VENV_DIR}/bin/activate && ice9 --help"
echo -e "  ${GRN}API:${RST}        http://localhost:8443"
if [[ "$INSTALL_DASHBOARD" == true ]]; then
    echo -e "  ${GRN}Dashboard:${RST}  http://localhost:3000"
fi
echo -e "  ${GRN}Services:${RST}   ./ice9-services status"
echo -e "  ${GRN}Tools:${RST}      ice9 tool list"
if [[ "$OLLAMA_RUNNING" != true ]]; then
    echo ""
    echo -e "  ${YLW}Note:${RST} Start Ollama before using AI features"
fi
echo ""
echo -e "  ${YLW}Quick start:${RST}"
echo -e "    ice9 campaign create -n \"My Pentest\" -s \"10.10.10.0/24\""
echo -e "    ice9 campaign list"
echo ""
