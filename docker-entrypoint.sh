#!/bin/bash
set -e

echo "==> Starting FalkorDB..."
redis-server --protected-mode no \
  --daemonize yes \
  --logfile /tmp/falkordb.log \
  --loadmodule /var/lib/falkordb/bin/falkordb.so

# Wait for FalkorDB to be ready
echo "==> Waiting for FalkorDB..."
for i in $(seq 1 30); do
  if redis-cli ping 2>/dev/null | grep -q PONG; then
    echo "    FalkorDB ready."
    break
  fi
  sleep 1
done

echo "==> Loading graph data..."
python3 load.py

# Start FalkorDB Browser in background on port 3000 with auto-connect
if [ -d "/var/lib/falkordb/browser" ]; then
  echo "==> Starting FalkorDB Browser on port 3000 with auto-connect..."
  (cd /var/lib/falkordb/browser && \
   FALKORDB_CONNECTION_URL="falkor://127.0.0.1:6379" \
   FALKORDB_AUTO_CONNECT=true \
   PORT=3000 \
   HOSTNAME="0.0.0.0" \
   ./docker-entrypoint.sh node server.js >/tmp/browser.log 2>&1) &
fi

echo "==> Starting web server on :${PORT:-8000}..."
exec python3 web.py
