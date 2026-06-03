FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV NETWAY_DB_PATH=/data/netway.db
ENV NETWAY_AUDIT_LOG=/data/netway_audit.jsonl

VOLUME ["/data"]

CMD ["python", "-m", "netway.runner"]
