# ── Stage 1: build the C++ backend ───────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libboost-dev \
        libboost-system-dev \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY backend/ .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    && cmake --build build --parallel "$(nproc)"

# ── Stage 2: slim runtime with nginx only ─────────────────────────────────────
# No systemd needed in Docker — the shell entrypoint starts both services.
# On the embedded target, use the systemd/ service files directly instead.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/nginx/sites-enabled/default

COPY --from=builder /src/build/backend /usr/local/bin/backend
RUN chmod 755 /usr/local/bin/backend

COPY www/          /www/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
