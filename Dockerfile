# Universal Dockerfile for Network Anomaly Detection System
FROM python:3.11-slim

# Install system dependencies (libpcap for network sniffing, tcpdump)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY cbp_network_anomaly /app/cbp_network_anomaly

WORKDIR /app/cbp_network_anomaly

# Expose Streamlit default port
EXPOSE 8501

# Configure Streamlit for headless container execution
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "dashboard/app.py"]
