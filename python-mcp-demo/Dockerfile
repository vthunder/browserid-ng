# browserid-ng FastMCP demo (Python) — build from the REPO ROOT (like mcp-demo):
#   docker build -f python-mcp-demo/Dockerfile -t python-mcp-demo .
# Bundles the local browserid-mcp-auth package (sdk/python-mcp-auth).
# Base image pinned by digest (audit 2026-11 W7-7): the tag names the
# version a human chose, the digest makes the build reproducible. Bump by
# re-resolving the tag (multi-arch manifest list, 2026-11-03).
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

WORKDIR /app

COPY sdk/python-mcp-auth ./sdk/python-mcp-auth
COPY python-mcp-demo/requirements.txt ./python-mcp-demo/requirements.txt
RUN pip install --no-cache-dir -r python-mcp-demo/requirements.txt ./sdk/python-mcp-auth

COPY python-mcp-demo/server.py ./python-mcp-demo/server.py

ENV PORT=3400
EXPOSE 3400
WORKDIR /app/python-mcp-demo
CMD ["python", "server.py"]
