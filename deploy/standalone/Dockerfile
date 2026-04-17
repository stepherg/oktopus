# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Stage 1 – build all Go services
# ---------------------------------------------------------------------------
FROM docker.io/library/golang:1.24 AS builder
WORKDIR /build

# ws
COPY backend/services/mtp/ws ./mtp/ws
RUN CGO_ENABLED=0 GOOS=linux go build -C mtp/ws -o /out/ws ./cmd/ws/main.go

# ws-adapter
COPY backend/services/mtp/ws-adapter ./mtp/ws-adapter
RUN CGO_ENABLED=0 GOOS=linux go build -C mtp/ws-adapter -o /out/ws-adapter ./cmd/ws-adapter/main.go

# adapter
COPY backend/services/mtp/adapter ./mtp/adapter
RUN CGO_ENABLED=0 GOOS=linux go build -C mtp/adapter -o /out/adapter ./cmd/adapter/main.go

# controller
COPY backend/services/controller ./controller
RUN CGO_ENABLED=0 GOOS=linux go build -C controller -o /out/controller ./cmd/controller/main.go

# taas
COPY backend/services/taas ./taas
RUN CGO_ENABLED=0 GOOS=linux go build -C taas -o /out/taas ./cmd/taas/main.go

# ---------------------------------------------------------------------------
# Stage 2 – build Next.js frontend
# ---------------------------------------------------------------------------
FROM node:18-slim AS frontend-builder
WORKDIR /app
COPY frontend/ ./
# Remove local env overrides if present
RUN rm -f .env .env.local
RUN npm install
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3 – runtime image with systemd
# Ubuntu 22.04 (Jammy) is used because MongoDB publishes arm64 packages for it.
# ---------------------------------------------------------------------------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install systemd, nginx, Node.js, NATS server, and MongoDB
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd \
        systemd-sysv \
        curl \
        ca-certificates \
        gnupg \
        nginx \
    && \
    # Node.js 18 LTS
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    # NATS server — arch-native binary
    NATS_VER=2.10.18 && \
    NATS_ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/nats-io/nats-server/releases/download/v${NATS_VER}/nats-server-v${NATS_VER}-linux-${NATS_ARCH}.tar.gz" \
        | tar -xz --strip-components=1 -C /usr/local/bin "nats-server-v${NATS_VER}-linux-${NATS_ARCH}/nats-server" && \
    # MongoDB 7.0 — Ubuntu Jammy repo has both amd64 and arm64
    curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb.gpg && \
    echo "deb [ arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/mongodb.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
        > /etc/apt/sources.list.d/mongodb-org-7.0.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        mongodb-org-server \
        mongodb-mongosh && \
    # Clean up
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Mask units that conflict with running systemd inside a container
RUN systemctl mask \
        systemd-logind.service \
        getty.target \
        console-getty.service \
        sys-fs-fuse-connections.mount \
        systemd-remount-fs.service \
        dev-hugepages.mount \
        tmp.mount

# ---------------------------------------------------------------------------
# Copy built Go binaries
# ---------------------------------------------------------------------------
COPY --from=builder /out/ws          /usr/local/bin/ws
COPY --from=builder /out/ws-adapter  /usr/local/bin/ws-adapter
COPY --from=builder /out/adapter     /usr/local/bin/adapter
COPY --from=builder /out/controller  /usr/local/bin/controller
COPY --from=builder /out/taas        /usr/local/bin/taas

# ---------------------------------------------------------------------------
# Copy Next.js frontend
# ---------------------------------------------------------------------------
COPY --from=frontend-builder /app/.next        /opt/frontend/.next
COPY --from=frontend-builder /app/public       /opt/frontend/public
COPY --from=frontend-builder /app/package.json /opt/frontend/package.json
COPY --from=frontend-builder /app/package-lock.json /opt/frontend/package-lock.json
RUN cd /opt/frontend && npm install --omit=dev

# ---------------------------------------------------------------------------
# nginx config (proxies / → Next.js :3000, /api → controller :8000, /api/taas → :8001)
# ---------------------------------------------------------------------------
COPY deploy/standalone/nginx-main.conf /etc/nginx/nginx.conf
COPY deploy/standalone/nginx.conf /etc/nginx/sites-available/oktopus
RUN rm -f /etc/nginx/sites-enabled/default && \
    ln -s /etc/nginx/sites-available/oktopus /etc/nginx/sites-enabled/oktopus

# ---------------------------------------------------------------------------
# NATS config and TLS certs
# ---------------------------------------------------------------------------
COPY deploy/compose/nats_config/ /etc/nats/
COPY deploy/standalone/nats.cfg /etc/nats/

# ---------------------------------------------------------------------------
# systemd unit files
# ---------------------------------------------------------------------------
COPY deploy/standalone/systemd/nats.service         /lib/systemd/system/nats.service
COPY deploy/standalone/systemd/mongod.service       /lib/systemd/system/mongod.service
COPY deploy/standalone/systemd/ws.service           /lib/systemd/system/ws.service
COPY deploy/standalone/systemd/ws-adapter.service   /lib/systemd/system/ws-adapter.service
COPY deploy/standalone/systemd/adapter.service      /lib/systemd/system/adapter.service
COPY deploy/standalone/systemd/controller.service   /lib/systemd/system/controller.service
COPY deploy/standalone/systemd/taas.service         /lib/systemd/system/taas.service
COPY deploy/standalone/systemd/frontend.service     /lib/systemd/system/frontend.service
COPY deploy/standalone/systemd/admin-seed.service   /lib/systemd/system/admin-seed.service

# ---------------------------------------------------------------------------
# Environment file (override at runtime with -v or --env-file)
# ---------------------------------------------------------------------------
RUN mkdir -p /etc/oktopus
COPY deploy/standalone/oktopus.env /etc/oktopus/oktopus.env

# Enable all services so they start with systemd
RUN systemctl enable \
        mongod.service \
        nats.service \
        ws.service \
        ws-adapter.service \
        adapter.service \
        controller.service \
        taas.service \
        frontend.service \
        nginx.service \
        admin-seed.service

# Ports:
#   80    – nginx (frontend + API reverse proxy)
#   4222  – NATS client
#   8080  – WebSocket MTP (plain)
#   8081  – WebSocket MTP (TLS)
#   8000  – Controller REST API (also via nginx /api)
#   8001  – TaaS REST API (also via nginx /api/taas)
EXPOSE 80 4222 8080 8081 8000 8001

CMD ["/sbin/init"]
