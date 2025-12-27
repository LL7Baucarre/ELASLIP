FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    curl \
    whois \
    nmap \
    iputils-ping \
    traceroute \
    dnsutils \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user and grant sudo access for nmap
RUN useradd -m appuser && \
    chown -R appuser:appuser /app && \
    echo "appuser ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run the application
CMD ["python", "run.py"]
