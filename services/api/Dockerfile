# Multi-stage production Dockerfile for CodeFort API
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv for fast, reliable package installations
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency specifications
COPY pyproject.toml README.md ./
COPY app/ ./app/

# Build wheels into /wheels
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache -e .

# Final lean runtime image
FROM python:3.12-slim AS runtime

WORKDIR /app

# Create unprivileged security user
RUN groupadd -r codefort && useradd -r -g codefort codefort

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY app/ /app/app/
COPY README.md /app/

# Set security headers and port
ENV PORT=8000
ENV ENVIRONMENT=production
ENV PYTHONUNBUFFERED=1

USER codefort

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
