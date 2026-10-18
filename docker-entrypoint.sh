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

echo "==> Starting web server on :${PORT:-8000}..."
exec python3 web.py
