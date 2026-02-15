# ============================================================================
# Claude Security Reviewer v2.1.0 - Secure Production Docker Image
# ============================================================================
# Security hardened Dockerfile with:
# - Non-root user execution
# - Minimal base image
# - Layer caching optimization
# - Read-only filesystems support
# ============================================================================

FROM python:3.9-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies
COPY claudecode/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ============================================================================
# Runtime stage
# ============================================================================
FROM python:3.9-slim

# SECURITY: Create non-root user for application
RUN useradd -m -u 1000 -s /sbin/nologin appuser

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH

# SECURITY: Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD ["python", "server.py"]

