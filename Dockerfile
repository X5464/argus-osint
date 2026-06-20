# ARGUS LEA — production container
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="ARGUS LEA Intelligence Platform"
LABEL org.opencontainers.image.description="Law-enforcement OSINT platform"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARGUS_DEBUG=0 \
    ARGUS_PORT=5000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY console.py .
COPY public/ ./public/
COPY data/.gitkeep ./data/

RUN mkdir -p /app/data/audit && chmod 700 /app/data

# Non-root runtime user
RUN useradd -r -u 10001 -d /app argus && chown -R argus:argus /app
USER argus

VOLUME ["/app/data", "/app/data/audit"]

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health')" || exit 1

CMD ["python", "-c", "from api.app import app; app.run(host='0.0.0.0', port=int(__import__('os').environ.get('ARGUS_PORT','5000')), debug=False)"]
