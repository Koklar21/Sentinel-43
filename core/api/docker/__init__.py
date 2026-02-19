# =============================================================================
# Sentinel-43 API Container
# =============================================================================
# Copyright (c) 2026 Justin
# All rights reserved.
#
# Docker initialization file for the Sentinel-43 API layer.
# This container runs the API service and imports core modules.
# =============================================================================

FROM python:3.12-slim

# Prevent Python from buffering logs
ENV PYTHONUNBUFFERED=1

# Prevent .pyc files
ENV PYTHONDONTWRITEBYTECODE=1

# Set working directory
WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
 && rm -rf /var/lib/apt/lists/*

# Copy dependency file first (better Docker caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy API source
COPY . .

# Expose API port
EXPOSE 8000

# Health check endpoint (adjust if needed)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run API server
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]