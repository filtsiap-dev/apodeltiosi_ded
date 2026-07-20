import os
from pathlib import Path

from anonymizer.config import load_env_file

# Load the project .env before reading the server knobs below, so gunicorn's
# bind/worker settings come from the same file as the application config.
# Real environment variables always take precedence.
load_env_file(Path(__file__).resolve().parent / ".env")

bind = f"{os.getenv('ANON_HOST', '0.0.0.0')}:{os.getenv('ANON_PORT', '8000')}"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
worker_class = "uvicorn_worker.UvicornWorker"   # from the `uvicorn-worker` package
timeout = int(os.getenv("ANON_GUNICORN_TIMEOUT", "900"))
graceful_timeout = int(os.getenv("ANON_GRACEFUL_TIMEOUT", "900"))
keepalive = 5
accesslog = "-"   # stdout
errorlog = "-"    # stdout
