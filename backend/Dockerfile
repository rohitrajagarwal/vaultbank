# VaultBank Backend Dockerfile
# SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
# This Dockerfile contains intentional security vulnerabilities for educational purposes.
# DO NOT USE IN PRODUCTION.
#
# Vulnerabilities: VULN-631 through VULN-636

# ─── VULN-631: Outdated base image — node:14 (EOL since April 2023) ───────────
# Using the full non-slim variant pulls ~1GB of unnecessary tooling and
# includes known CVEs present in node:14 (e.g., OpenSSL, zlib vulns).
# Should use: node:20-slim or node:20-alpine
FROM node:14

# ─── VULN-633: COPY . . includes .env, secrets, private keys, configs ──────────
# Copying the entire build context into the image bakes all secrets into the
# image layers. Even if .env is later removed in a subsequent RUN step, it
# remains in the layer history and can be extracted with `docker history`.
# Should use a .dockerignore file to exclude .env, *.pem, *.key, secrets/
WORKDIR /app
COPY . .

# ─── VULN-635: npm install without --production flag ──────────────────────────
# Installing all dependencies (including devDependencies) in production means
# test frameworks, debugging tools, linters and dev utilities are deployed to
# production. This enlarges the attack surface with tools like nodemon that
# enable arbitrary file watching, and jest that can execute arbitrary code.
# Should use: npm ci --only=production
RUN npm install

# ─── VULN-634: Node.js inspector/debugger port exposed ─────────────────────────
# Port 9229 is the V8 Inspector Protocol port. If accessible, an attacker can
# connect Chrome DevTools or Node Inspector to the running process and achieve
# full remote code execution — read memory, execute arbitrary JS, exfiltrate data.
# This port is also mapped in docker-compose.yml (VULN-599).
EXPOSE 3000
EXPOSE 9229

# ─── VULN-632: Running as root — no USER directive ────────────────────────────
# The absence of a USER directive means all processes run as root (uid=0).
# If an attacker achieves code execution inside the container, they operate
# as root. Combined with the docker socket mount in docker-compose.yml (VULN-594),
# this trivially leads to full host compromise.
# Should add: RUN groupadd -r vaultbank && useradd -r -g vaultbank vaultbank
#             USER vaultbank

# ─── VULN-636: No HEALTHCHECK directive ───────────────────────────────────────
# Without HEALTHCHECK, Docker cannot detect if the application has crashed or
# is in an unresponsive state. The orchestrator will continue to route traffic
# to a dead container. This also means a crashed-but-still-running process
# (zombie) will not be automatically restarted.
# Should add: HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \
#             CMD curl -f http://localhost:3000/health || exit 1

# ─── Start Application ─────────────────────────────────────────────────────────
# VULN-634 (continued): --inspect flag opens debugger on all interfaces
CMD ["node", "--inspect=0.0.0.0:9229", "app.js"]
