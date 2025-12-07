# Multi-stage Docker build for WAF System
# Stage 1: Base image with dependencies
FROM python:3.10-slim as base

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime image
FROM python:3.10-slim

WORKDIR /app

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from base stage
COPY --from=base /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

# Create non-root user for security
RUN groupadd -r wafuser && useradd -r -g wafuser wafuser

# Copy application code
COPY --chown=wafuser:wafuser . .

# Create necessary directories for runtime data (will be in-container only)
# These will NOT be persisted when container stops
RUN mkdir -p \
    data/parsed \
    data/tokenized \
    models/deberta-waf \
    nginx/logs \
    logs \
    reports \
    /tmp/huggingface \
    && chown -R wafuser:wafuser data models nginx logs reports /tmp/huggingface

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    TOKENIZERS_PARALLELISM=false \
    WANDB_DISABLED=true \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    PYTORCH_ENABLE_MPS_FALLBACK=1 \
    HF_HOME=/tmp/huggingface \
    TRANSFORMERS_CACHE=/tmp/huggingface \
    HF_DATASETS_CACHE=/tmp/huggingface

# Expose port for web UI
EXPOSE 5000

# Switch to non-root user
USER wafuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default command to run the WAF UI
CMD ["python", "waf_integrated_ui.py", "--port", "5000"]
