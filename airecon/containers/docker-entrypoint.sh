#!/bin/bash
# AIRecon Sandbox Entrypoint
# Keeps the container alive for `docker exec` commands

echo "[airecon-sandbox] Container started."
echo "[airecon-sandbox] Tools ready at: $(date)"

# Start headless Chromium Debugging Server (CDP) for Playwright
echo "[airecon-sandbox] Starting Chromium CDP Server on port 9222..."
chromium \
    --headless=new \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --remote-debugging-port=9222 \
    --remote-debugging-address=0.0.0.0 \
    --disable-web-security \
    --remote-allow-origins="*" \
    > /dev/null 2>&1 &

# Keep container alive
exec sleep infinity
