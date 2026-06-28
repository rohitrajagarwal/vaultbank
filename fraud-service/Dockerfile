# VaultBank Fraud Detection Service Dockerfile
# SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
# This Dockerfile contains intentional security vulnerabilities for educational purposes.
# DO NOT USE IN PRODUCTION.
#
# Vulnerabilities: VULN-637 through VULN-641

# ─── VULN-637: Full (non-slim) Python base image, outdated minor version ──────
# python:3.9 (non-slim) adds ~400MB of unused build tools and includes
# multiple known CVEs in bundled libraries (openssl, expat, zlib, etc.).
# python:3.9 is entering end-of-life — security updates are winding down.
# Should use: python:3.12-slim or python:3.11-slim-bookworm
FROM python:3.9

# ─── VULN-639: COPY . . bakes all secrets into the image ───────────────────────
# Copies the entire build context including:
#   - .env files with database passwords, API keys
#   - ML model files containing training data (potential PII)
#   - Any private keys or certificates in the directory
# These become part of the image's layer history and can be extracted
# from the image even if deleted in a subsequent RUN step.
# Should use a .dockerignore to exclude secrets, or use Docker secrets.
WORKDIR /app
COPY . .

# ─── VULN-641: pip install without hash-checking or version pinning ─────────────
# Installing without --require-hashes allows pip to silently download
# compromised packages if the upstream PyPI package is replaced (supply chain attack).
# Without hash verification, a man-in-the-middle attacker or a compromised PyPI
# mirror can substitute malicious packages.
# Should use: pip install --require-hashes -r requirements.txt
#         or: pip install --no-deps --require-hashes -r requirements.txt
RUN pip install -r requirements.txt
# VULN-641: No --require-hashes, no --no-cache-dir, no pinned hash verification

# ─── VULN-638: Running as root — no USER directive ────────────────────────────
# All Python processes run as root (uid=0) inside the container.
# Combined with the Docker socket mount in docker-compose.yml (VULN-594) and
# the host filesystem mount (VULN-593), any code execution inside this container
# trivially escapes to full host compromise.
# Should add:
#   RUN groupadd -r fraud && useradd -r -g fraud fraud
#   USER fraud

# ─── VULN-640: Expose application port AND debug port ─────────────────────────
# Port 5001 is the Flask application port.
# Port 5678 is the debugpy (Python remote debugger) port.
# With debugpy listening on 0.0.0.0:5678 and this port exposed in
# docker-compose.yml (VULN-600), an attacker can attach a Python debugger
# and achieve full remote code execution — read variables, execute arbitrary
# Python, modify running state, extract ML model secrets and PII from memory.
EXPOSE 5001
EXPOSE 5678

# ─── Start Fraud Detection Service ─────────────────────────────────────────────
# VULN-640 (continued): Starts debugpy on all interfaces before launching Flask
# VULN-637 (continued): Flask debug=True enables the Werkzeug debugger PIN bypass
CMD ["python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "-m", "flask", "run", "--host=0.0.0.0", "--port=5001", "--debug"]
