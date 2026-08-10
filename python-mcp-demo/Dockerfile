# browserid-ng FastMCP demo (Python) — build from the REPO ROOT (like mcp-demo):
#   docker build -f python-mcp-demo/Dockerfile -t python-mcp-demo .
# Bundles the local browserid-mcp-auth package (sdk/python-mcp-auth).
FROM python:3.12-slim

WORKDIR /app

COPY sdk/python-mcp-auth ./sdk/python-mcp-auth
COPY python-mcp-demo/requirements.txt ./python-mcp-demo/requirements.txt
RUN pip install --no-cache-dir -r python-mcp-demo/requirements.txt ./sdk/python-mcp-auth

COPY python-mcp-demo/server.py ./python-mcp-demo/server.py

ENV PORT=3400
EXPOSE 3400
WORKDIR /app/python-mcp-demo
CMD ["python", "server.py"]
