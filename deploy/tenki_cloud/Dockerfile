FROM python:3.11-slim

LABEL org.opencontainers.image.title="AegisAgent — Tenki Cloud SIEM & Fuzzer Hub"
LABEL org.opencontainers.image.description="Centralized forensic telemetry ingestion and distributed red-team fuzzer coordinator"
LABEL org.opencontainers.image.version="0.1.0"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir uv \
    && uv pip install --system \
        fastapi \
        uvicorn[standard] \
        pydantic>=2.0 \
        rich>=13.0 \
        wasmtime>=48.0.0

# Copy application source
COPY aegis/ ./aegis/
COPY deploy/ ./deploy/

# Expose SIEM API port
EXPOSE 8080

# Health check for Tenki Cloud orchestrator
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the server
CMD ["uvicorn", "deploy.tenki_cloud.server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
