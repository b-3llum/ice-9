"""Gunicorn configuration for ice_9 API (alternative to direct uvicorn)."""

import multiprocessing
import os

# Server socket
bind = os.environ.get("ICE9_BIND", "127.0.0.1:8443")

# Worker processes
workers = int(os.environ.get("ICE9_WORKERS", min(multiprocessing.cpu_count(), 4)))
worker_class = "uvicorn.workers.UvicornWorker"
worker_tmp_dir = "/dev/shm"

# Timeouts
timeout = 120
graceful_timeout = 30
keepalive = 5

# TLS
keyfile = os.environ.get("ICE9_TLS_KEY", "/opt/ice9/tls/key.pem")
certfile = os.environ.get("ICE9_TLS_CERT", "/opt/ice9/tls/cert.pem")

# Logging
accesslog = os.environ.get("ICE9_ACCESS_LOG", "/opt/ice9/logs/access.log")
errorlog = os.environ.get("ICE9_ERROR_LOG", "/opt/ice9/logs/error.log")
loglevel = os.environ.get("ICE9_LOG_LEVEL", "info")

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Process naming
proc_name = "ice9-api"
