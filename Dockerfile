FROM node:18-bullseye

RUN apt-get update && apt-get install -y curl openjdk-17-jre-headless unzip ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund || npm install --production --no-audit --no-fund

COPY index.js ./
COPY opt/zap /opt/zap
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /opt/zap/zap.sh /app/docker-entrypoint.sh && \
    find /opt/zap -type f -name '*.sh' -exec sed -i 's/\r$//' {} \;

EXPOSE 3000 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://127.0.0.1:3000/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
