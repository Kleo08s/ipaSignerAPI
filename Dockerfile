# --- Build di zsign ---------------------------------------------------------
FROM debian:bookworm-slim AS zsign-build
RUN apt-get update && apt-get install -y --no-install-recommends \
      git build-essential pkg-config libssl-dev zlib1g-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /zsign \
    && cd /zsign/build/linux \
    && make clean && make \
    && cp /zsign/bin/zsign /usr/local/bin/zsign

# --- App --------------------------------------------------------------------
FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 zlib1g openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=zsign-build /usr/local/bin/zsign /usr/local/bin/zsign

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./

ENV NODE_ENV=production DATA_DIR=/data
VOLUME /data
EXPOSE 3000
CMD ["node", "server.js"]
