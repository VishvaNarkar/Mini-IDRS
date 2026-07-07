# Mini-IDRS — Dockerfile
# Single image used by monitor, ids-api, and dashboard services.
# The firewall_api runs as a separate systemd service on the Linux Firewall VM.

FROM python:3.13-slim

LABEL maintainer="Vishva Narkar"
LABEL description="Mini IDRS — Intrusion Detection & Response System"

WORKDIR /app

# Install system dependencies
# libpcap-dev is required by Scapy for raw packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Create runtime directories
RUN mkdir -p runtime/logs runtime/pcaps runtime/cache

# Default command (overridden per service in docker-compose.yml)
CMD ["python", "idrs_monitor.py", "--help"]
