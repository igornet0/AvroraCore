# syntax=docker/dockerfile:1.7
#
# AvroraCore DBMS image (avrora + dmc-pgwire).
# Build via Makefile.docker / compose (needs sibling AvroraClient context).

ARG RUST_VERSION=1.88
ARG NODE_VERSION=22

# ── UI ──────────────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION}-bookworm AS ui
WORKDIR /ui
COPY crates/dmc-core/ui/package.json crates/dmc-core/ui/package-lock.json ./
RUN npm ci
COPY crates/dmc-core/ui/ ./
RUN npm run build

# ── Rust binaries ───────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

# Default context = AvroraCore; named context `client` = ../AvroraClient
COPY . /src/AvroraCore
COPY --from=client . /src/AvroraClient

COPY --from=ui /ui/dist /src/AvroraCore/crates/dmc-core/ui/dist

WORKDIR /src/AvroraCore
RUN cargo build --release -p dmc-core --bin avrora \
 && cargo build --release -p dmc-pgwire --bin dmc-pgwire \
 && strip target/release/avrora target/release/dmc-pgwire

# ── Runtime ─────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini gosu \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/avrora --create-home avrora

COPY --from=builder /src/AvroraCore/target/release/avrora /usr/local/bin/avrora
COPY --from=builder /src/AvroraCore/target/release/dmc-pgwire /usr/local/bin/dmc-pgwire
COPY --from=ui /ui/dist /usr/local/share/avrora/ui
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
 && chown -R avrora:avrora /var/lib/avrora

ENV AVRORA_HOME=/var/lib/avrora \
    AVRORA_DATA=/var/lib/avrora/avrora.dbs.json \
    AVRORA_CONTROL_DIR=/var/lib/avrora/control \
    AVRORA_ADDR=0.0.0.0:18787 \
    AVRORA_CONTROL_ADDR=0.0.0.0:7432 \
    AVRORA_UI_DIST=/usr/local/share/avrora/ui \
    SQL_DATA=/var/lib/avrora/sql.dbs.json \
    SQL_MASTER_KEY=/var/lib/avrora/sql.master.key \
    SQL_ADDR=0.0.0.0:15432 \
    INVITE_HOST=127.0.0.1 \
    INVITE_PORT=7432 \
    AVRORA_UID=10001 \
    AVRORA_GID=10001

WORKDIR /var/lib/avrora
VOLUME ["/var/lib/avrora"]

EXPOSE 18787 7432 15432

# Entrypoint starts as root to fix volume ownership, then drops to avrora.
ENTRYPOINT ["tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["avrora"]
