# NEXUS-GUARD Headless Security Daemon Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure log and report directories exist
RUN mkdir -p logs exports/reports

# Default health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "from nexus_guard.engine.fim import FileIntegrityMonitor; print('OK')" || exit 1

# Run headless CLI daemon / scanner
CMD ["python", "run_guard.py", "--headless"]
