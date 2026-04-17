# Argus Agent — multi-stage Dockerfile
# Copyright (c) 2026 Kaushikkumaran
# Stage 1: build dependencies
FROM python:3.11-slim AS builder
WORKDIR /app
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --target /app/deps

# Stage 2: minimal runtime image
FROM python:3.11-slim AS runtime
WORKDIR /app

# Create non-root user
RUN groupadd -r argus && useradd -r -g argus -s /bin/false argus

# Copy dependencies and source
COPY --from=builder /app/deps /app/deps
COPY src/ /app/src/

# Set Python path
ENV PYTHONPATH="/app/deps:/app/src"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run as non-root
USER argus

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
