# ═══════════════════════════════════════════════════════════════
# VULN: [IAC/DOCKERFILE] Insecure Dockerfile
# ═══════════════════════════════════════════════════════════════

# VULN: Using latest tag — non-deterministic builds
FROM python:latest

# VULN: Running as root (no USER directive)
# VULN: No multi-stage build

WORKDIR /app

# VULN: Copying ALL files including .env, .git, secrets
COPY . .

# VULN: Installing as root, no --no-cache-dir, no pinned versions
RUN pip install fastapi uvicorn sqlite3

# VULN: Exposing debug info via environment
ENV DEBUG=true
ENV SECRET_KEY=super-secret-key-12345-do-not-share
ENV AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
ENV DATABASE_URL=sqlite:///./production.db

# VULN: Exposing all ports, running with --reload in production
EXPOSE 8000 22 5432

# VULN: No health check defined
# VULN: No read-only filesystem
# VULN: Running with --reload (development flag in production)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
