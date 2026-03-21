# ice_9 API Deployment

## Prerequisites

- Python 3.11+
- systemd (Linux)
- TLS certificate and key

## Setup

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
  .venv/bin/pip install -e /path/to/redforge
'
```

### 3. TLS certificates

Generate a self-signed cert for testing, or use your own:

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

### 5. Install and start service

```bash
sudo cp deploy/ice9-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ice9-api
```

### 6. Verify

```bash
sudo systemctl status ice9-api
curl -k https://127.0.0.1:8443/health
```

## Using Gunicorn (alternative)

Instead of the systemd unit's direct uvicorn invocation, you can use gunicorn with the provided config:

```bash
.venv/bin/gunicorn ice_9.api:app -c /path/to/deploy/gunicorn.conf.py
```

Override settings via environment variables: `ICE9_BIND`, `ICE9_WORKERS`, `ICE9_TLS_KEY`, `ICE9_TLS_CERT`, `ICE9_LOG_LEVEL`.

## Firewall

Restrict API access to trusted networks:

```bash
sudo ufw allow from 10.0.0.0/8 to any port 8443 proto tcp
sudo ufw deny 8443
```

## Logs

```bash
journalctl -u ice9-api -f          # systemd journal
tail -f /opt/ice9/logs/access.log  # gunicorn access log
```
