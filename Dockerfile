# AI-Augmented DevOps Framework
# Production-ready Docker image with security hardening

FROM python:3.11-slim AS builder

# Security: Create non-root user
RUN groupadd -r aidevops && useradd -r -g aidevops aidevops

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
COPY demo_app/requirements.txt demo_app/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim AS production

# Security: Create non-root user
RUN groupadd -r aidevops && useradd -r -g aidevops -d /app aidevops

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Set working directory
WORKDIR /app

# Copy application code
COPY ai_components/ ai_components/
COPY demo_app/ demo_app/
COPY scripts/ scripts/
COPY deployment/ deployment/
COPY docs/ docs/
COPY README.md LICENSE ./

# Create required directories
RUN mkdir -p logs reports models data && \
    chown -R aidevops:aidevops /app

# Security: Switch to non-root user
USER aidevops

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Expose port
EXPOSE 5000

# Environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=demo_app/app.py
ENV FLASK_ENV=production
ENV PORT=5000

# Start application with Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "--worker-class", "sync", "--max-requests", "1000", "--max-requests-jitter", "100", "--access-logfile", "-", "--error-logfile", "-", "demo_app.app:app"]

# Labels for metadata
LABEL maintainer="Akshay Mittal <akshay.mittal@ieee.org>"
LABEL version="1.0.0"
LABEL description="AI-Augmented DevOps Framework Demo Application"
LABEL org.opencontainers.image.source="https://github.com/akshaymittal143/ai-augmented-devops"
LABEL org.opencontainers.image.documentation="https://github.com/akshaymittal143/ai-augmented-devops#readme"
LABEL org.opencontainers.image.licenses="MIT"
