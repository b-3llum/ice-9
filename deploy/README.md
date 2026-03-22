# ice_9 Deployment

## Quick Setup (Development)

From the repo root:

```bash
./install.sh
```

This will:
1. Create a Python virtual environment and install ice_9
2. Install dashboard npm dependencies
3. Auto-detect your Python, Node.js, and tool paths
4. Generate systemd service files tailored to your environment
5. Optionally install and enable the services

After installation:

```bash
ice9-services status     # check services
ice9-services restart    # restart API + dashboard
ice9-services logs       # tail all logs
ice9-services logs ice9-api  # tail API logs only
```

## Manual Service Management

If you skipped the systemd step during install, you can install later:

```bash
./ice9-services install   # copy generated .service files to systemd
./ice9-services enable    # enable auto-start on boot
./ice9-services start     # start now
```

To remove:

```bash
./ice9-services uninstall
```

## Production Deployment

### 1. Create service user

```bash
sudo useradd -r -s /usr/sbin/nologin -d /opt/ice9 ice9
sudo mkdir -p /opt/ice9/{data,logs,tls}
sudo chown -R ice9:ice9 /opt/ice9
```

### 2. Install application

```bash
sudo -u ice9 bash -c '
  cd /opt/ice9
  python3 -m venv .venv
  .venv/bin/pip install -e /path/to/ice-9
'
```

### 3. TLS certificates

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /opt/ice9/tls/key.pem \
  -out /opt/ice9/tls/cert.pem \
  -days 365 -subj "/CN=ice9"
sudo chown ice9:ice9 /opt/ice9/tls/*.pem
sudo chmod 600 /opt/ice9/tls/key.pem
```

### 4. Environment file

```bash
sudo tee /opt/ice9/.env << 'EOF'
ICE9_API_KEY=your-secret-key-here
ICE9_HOME=/opt/ice9
ICE9_CORS_ORIGINS=https://your-dashboard.example.com
ANTHROPIC_API_KEY=sk-ant-...
EOF
sudo chown ice9:ice9 /opt/ice9/.env
sudo chmod 600 /opt/ice9/.env
```

### 5. Run install.sh as the ice9 user

```bash
sudo -u ice9 /path/to/ice-9/install.sh
```

### 6. Using Gunicorn (alternative)

For production, use gunicorn with the provided config instead of direct uvicorn:

```bash
.venv/bin/gunicorn ice_9.api:app -c /path/to/deploy/gunicorn.conf.py
```

Override settings via environment variables: `ICE9_BIND`, `ICE9_WORKERS`, `ICE9_TLS_KEY`, `ICE9_TLS_CERT`, `ICE9_LOG_LEVEL`.

### 7. Firewall

```bash
sudo ufw allow from 10.0.0.0/8 to any port 8443 proto tcp
sudo ufw deny 8443
```

## Generated Files

`install.sh` generates service files in this directory:
- `ice9-api.service` — API server (uvicorn on port 8443)
- `ice9-dashboard.service` — Dashboard (Vite on port 3000)

These are `.gitignore`d because they contain machine-specific paths.

## Logs

```bash
journalctl -u ice9-api -f          # systemd journal
journalctl -u ice9-dashboard -f    # dashboard logs
tail -f /opt/ice9/logs/access.log  # gunicorn access log (production)
```
