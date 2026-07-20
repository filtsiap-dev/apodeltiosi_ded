# ded-anonymizer v2 — HTTP API container.
# Build:  docker build -t ded-anonymizer .
# Run:    docker run -p 8000:8000 -e OPENAI_API_KEY=sk-... -e ANON_MODEL=gpt-5.4-2026-03-05 ded-anonymizer
FROM python:3.11-slim

# Never write .pyc files / never buffer logs (logs go straight to `docker logs`).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first (this layer is cached until requirements.txt changes).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The application: the package, its data files, and the server config — the
# API only, no CLI. The .env file is deliberately NOT copied (see
# .dockerignore) — secrets are injected as real environment variables at run
# time, which the app reads directly.
COPY anonymizer/ anonymizer/
COPY config/ config/
COPY gunicorn.conf.py ./

EXPOSE 8000

# Liveness probe: /healthz answers without contacting OpenAI.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

# gunicorn is Linux-only — it runs here in the container even though it cannot
# run on the Windows host. WORKDIR /app makes Path('config') resolve correctly.
CMD ["gunicorn", "anonymizer.api:app", "-c", "gunicorn.conf.py"]
