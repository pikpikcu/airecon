#!/bin/bash
# AIRecon Sandbox Entrypoint
# Keeps the container alive for `docker exec` commands

echo "[airecon-sandbox] Container started."
echo "[airecon-sandbox] Tools ready at: $(date)"

# Chromium CDP server is started LAZILY by AIRecon when browser_action is
# first called.  Starting it here wasted 200-500 MB of RAM even when the
# browser tool was never used, reducing headroom for recon tools and
# contributing to OOM container crashes.
#
# To start Chromium manually for debugging:
#   docker exec airecon-sandbox-active chromium --headless=new --no-sandbox \
#     --disable-dev-shm-usage --disable-gpu --remote-debugging-port=9222 \
#     --remote-debugging-address=0.0.0.0 --disable-web-security \
#     --remote-allow-origins='*' --ignore-certificate-errors &
#echo "[airecon-sandbox] Starting Chromium CDP Server on port 9222..."
#chromium \
#    --headless=new \
#    --no-sandbox \
#    --disable-dev-shm-usage \
#    --disable-gpu \
#    --remote-debugging-port=9222 \
#    --remote-debugging-address=0.0.0.0 \
#    --disable-web-security \
#    --remote-allow-origins="*" \
#    --ignore-certificate-errors \
#    > /dev/null 2>&1 &

# Ensure the sandbox user can create its output subdirectories WITHOUT rewriting
# the ownership/permissions of existing files inside the host bind-mount.
# A recursive chown/chmod here would clobber the user's real files (git objects,
# secrets, source, @-referenced copies) on the host — so we only adjust the
# mount-point directory itself (non-recursive). AIRecon creates and owns its own
# per-target output subdirs (output/, command/, tools/, vulnerabilities/), which
# are therefore writable without touching anything that was already there.
if [ -d "/workspace" ]; then
    # Make the mount point group-writable + group-owned by the sandbox user so
    # the agent can mkdir its target folders. NOT recursive — existing host
    # files keep their original ownership and permissions.
    sudo chown pentester:pentester /workspace 2>/dev/null || true
    sudo chmod 0775 /workspace 2>/dev/null || true
    echo "[airecon-sandbox] Workspace mount-point writable (existing files untouched)."
fi

# Keep container alive
exec sleep infinity
