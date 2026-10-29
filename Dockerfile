FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY unifi_mcp ./unifi_mcp

# Nicht als root laufen. /data (Volume) hält Audit-Log, Pläne und Sicherungen.
RUN useradd --system --no-create-home --uid 10001 mcp \
    && mkdir -p /data /config && chown mcp /data && chmod 700 /data
USER mcp

ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_PATH=/unifi \
    DATA_DIR=/data \
    CONSOLES_FILE=/config/consoles.json \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Version aus dem Git-Tag, Commit und Build-Zeit (von GitHub Actions gesetzt) -
# get_version gibt alles zurück, damit nach einem Redeploy prüfbar ist, welcher
# Stand wirklich läuft. Ohne APP_VERSION meldet der Server "dev-<kurzer Commit>".
ARG GIT_SHA=unbekannt
ARG APP_VERSION=
ARG BUILD_TIME=
ENV GIT_SHA=$GIT_SHA \
    APP_VERSION=$APP_VERSION \
    BUILD_TIME=$BUILD_TIME

EXPOSE 8000

# /healthz liegt hinter der Bearer-Prüfung; der Check nutzt das eigene MCP_API_KEY.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-m", "unifi_mcp.healthcheck"]

CMD ["python", "-m", "unifi_mcp"]
