#!/bin/bash
set -e

echo "🚀 Starting ZAP daemon..."
/opt/zap/zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true \
  -config scanner.clientIntegration=false &

echo "⏳ Waiting for ZAP to start..."
for i in {1..60}; do
  if curl -s http://127.0.0.1:8080/JSON/core/view/version/ >/dev/null 2>&1; then
    echo "✅ ZAP is ready!"
    break
  fi
  sleep 3
done

echo "⚡ Starting Node wrapper..."
exec node index.js
