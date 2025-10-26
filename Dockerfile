# zapvault/Dockerfile
# Purpose: Single image with Java JRE, ZAP, and Node wrapper.
FROM node:18-bullseye

# Install required packages: curl, unzip, openjdk
RUN apt-get update && apt-get install -y curl openjdk-17-jre-headless unzip ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund || npm install --production --no-audit --no-fund

# Copy Node app and ZAP folder
COPY index.js ./
COPY opt/zap /opt/zap

# Fix line endings + permissions
RUN if [ -f /opt/zap/zap.sh ]; then \
      sed -i 's/\r$//' /opt/zap/zap.sh || true; \
      chmod +x /opt/zap/zap.sh; \
      find /opt/zap -type f -name '*.sh' -exec sed -i 's/\r$//' {} \; -exec chmod +x {} \; || true; \
    fi

# Expose ports (Node + ZAP)
EXPOSE 3000 8080

# Healthcheck for Render
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://127.0.0.1:3000/health || exit 1

# ========================
# 🔥 MAIN ENTRY COMMAND
# ========================
CMD ["/bin/sh","-c","/opt/zap/zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config api.disablekey=true -config scanner.clientIntegration=false & \
  sleep 15 && node index.js"]
