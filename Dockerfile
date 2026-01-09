FROM python:3.11-slim

WORKDIR /app

# Accept ARG for version during build
ARG APP_VERSION=1.3.4
ENV APP_VERSION=${APP_VERSION}

# Install system dependencies including Playwright browser dependencies
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
    # Playwright dependencies for Chromium
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxext6 \
    fonts-liberation \
    fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set Playwright browsers path to a shared location accessible by all users
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers

# Install Playwright browsers to shared location
RUN mkdir -p /opt/playwright-browsers && \
    playwright install chromium && \
    chmod -R 755 /opt/playwright-browsers

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
