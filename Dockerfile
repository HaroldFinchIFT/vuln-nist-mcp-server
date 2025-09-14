FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY vuln_nist_mcp_server.py .

RUN useradd -m -u 1000 mcpuser && \
    chown -R mcpuser:mcpuser /app

USER mcpuser

ENV NVD_BASE_URL="https://services.nvd.nist.gov/rest/json"
ENV NVD_VERSION="/2.0"
ENV NVD_API_TIMEOUT="10"

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

LABEL maintainer="a.brioschi@andreabrioschi.it"
LABEL description="NIST Vulnerability MCP Server"
LABEL version="1.0.0"

CMD ["python", "vuln_nist_mcp_server.py"]
