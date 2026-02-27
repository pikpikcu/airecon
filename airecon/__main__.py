"""AIRecon CLI entry point."""

from __future__ import annotations

import argparse
import sys
import logging


def main() -> None:

    import importlib.metadata
    
    try:
        version = importlib.metadata.version("airecon")
    except importlib.metadata.PackageNotFoundError:
        version = "0.1.4"

    parser = argparse.ArgumentParser(
        prog="airecon",
        description="AIRecon — AI-powered security reconnaissance",
    )
    # Global arguments
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {version}")
    parser.add_argument("--config", default=None, help="Path to custom configuration file (default: ~/.airecon/config.json)")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # proxy subcommand
    proxy_parser = subparsers.add_parser("proxy", help="Start proxy server only")
    proxy_parser.add_argument("--host", default=None, help="Host to bind to")
    proxy_parser.add_argument("--port", type=int, default=None, help="Port to bind to")
    proxy_parser.add_argument("--config", default=None, help="Path to custom configuration file")

    # tui subcommand
    tui_parser = subparsers.add_parser("start", help="Start TUI client (also starts proxy)")
    tui_parser.add_argument("--no-proxy", action="store_true", help="Don't auto-start proxy")
    tui_parser.add_argument("--proxy-url", default="http://127.0.0.1:3000", help="Proxy URL")
    tui_parser.add_argument("--config", default=None, help="Path to custom configuration file")

    # status subcommand
    status_parser = subparsers.add_parser("status", help="Check status of services")
    status_parser.add_argument("--config", default=None, help="Path to custom configuration file")

    # clean subcommand
    clean_parser = subparsers.add_parser(
        "clean",
        help="Clean Docker build cache, orphan containers, and unused volumes"
    )
    clean_parser.add_argument(
        "--all", "-a", action="store_true",
        help="Full clean: also remove the airecon-sandbox image (requires full rebuild next time)"
    )
    clean_parser.add_argument(
        "--keep-storage", default="3gb",
        help="Minimum build cache to keep for fast rebuilds (default: 3gb). Use 0 to remove all."
    )

    args = parser.parse_args()

    # Initialize config globally with the provided path (if any)
    # This ensures subsequent calls to get_config() return the correct instance
    from airecon.proxy.config import get_config
    get_config(args.config)

    if args.command == "proxy":
        _run_proxy(args)
    elif args.command == "start":
        _run_tui(args)
    elif args.command == "status":
        _run_status(args)
    elif args.command == "clean":
        _run_clean(args)
    else:
        parser.print_help()
        sys.exit(1)


def _run_proxy(args) -> None:
    """Start the proxy server."""
    import atexit
    atexit.register(_unload_model_safely)
    import os
    import airecon.proxy.config as _cfg_module

    # Set env vars BEFORE resetting the singleton so they are picked up
    if args.host:
        os.environ["AIRECON_PROXY_HOST"] = args.host
    if args.port:
        os.environ["AIRECON_PROXY_PORT"] = str(args.port)

    # Reset singleton so the env-var overrides take effect
    if args.host or args.port:
        _cfg_module._config = None
        _cfg_module.get_config(getattr(args, "config", None))

    from airecon.proxy.server import run_server
    run_server()


def _run_tui(args) -> None:
    """Start TUI (optionally with embedded proxy)."""
    import atexit
    atexit.register(_unload_model_safely)
    import threading

    # Ensure config is loaded
    from airecon.proxy.config import get_config
    cfg = get_config() 

    # ----- DOCKER AUTO-BUILD CHECK -----
    import asyncio
    from airecon.proxy.docker import DockerEngine
    
    print("\n[AIRecon] Checking Docker Sandbox environment...", flush=True)
    engine = DockerEngine()
    build_success = asyncio.run(engine.ensure_image())
    if not build_success:
        print(f"\n\033[31m[!] Critical: Failed to find or build the Docker image ('airecon-sandbox').\033[0m")
        print("Please check Docker is installed and running, or build manually:")
        print(f"  docker build -t airecon-sandbox {engine.DOCKERFILE_DIR}")
        sys.exit(1)
    # -----------------------------------

    if not args.no_proxy:
        # Start proxy in background thread
        _proxy_error: list[str] = []

        def start_proxy():
            import logging
            import traceback
            # Suppress proxy logs (they go to stderr and mess with TUI)
            # We use CRITICAL to be absolutely sure nothing leaks
            logging.getLogger("airecon").setLevel(logging.CRITICAL)
            logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
            logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)
            logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)
            logging.getLogger("httpx").setLevel(logging.CRITICAL)
            logging.getLogger("httpcore").setLevel(logging.CRITICAL)

            try:
                from airecon.proxy.server import run_server
                run_server()
            except Exception as e:
                _proxy_error.append(str(e))
                with open("airecon_proxy_crash.log", "w") as f:
                    traceback.print_exc(file=f)

        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()

        # Wait for proxy to be ready (MCP connection takes ~5s)
        import time
        import urllib.request
        
        # Use config or args for URL
        proxy_url = args.proxy_url.rstrip("/")
        # If user didn't override proxy_url, use config default
        if args.proxy_url == "http://127.0.0.1:3000":
             proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"

        print(f"Starting AIRecon proxy at {proxy_url}... ", end="", flush=True)

        for attempt in range(40):  # up to 20 seconds
            # Check if proxy thread crashed immediately
            if _proxy_error:
                print(f"\n[!] Proxy failed to start: {_proxy_error[0]}")
                print("    Check airecon_proxy_crash.log for details.")
                sys.exit(1)

            try:
                req = urllib.request.urlopen(f"{proxy_url}/api/status", timeout=2)
                import json
                data = json.loads(req.read())
                # Proxy is responding — services may still be initializing
                docker_ok = data.get("docker", {}).get("connected", False)
                ollama_ok = data.get("ollama", {}).get("connected", False)
                if docker_ok and ollama_ok:
                    print("ready!")
                else:
                    print("proxy running.")
                break
            except Exception:
                print(".", end="", flush=True)
                time.sleep(0.5)
        else:
            if _proxy_error:
                print(f"\n[!] Proxy crashed: {_proxy_error[0]}")
                print("    Check airecon_proxy_crash.log for details.")
                sys.exit(1)
            print(" (proxy did not respond — check for port conflicts)")

    from airecon.tui.app import AIReconApp
    
    # If using custom config, the proxy_url arg might need to follow config unless overridden
    # But for TUI client, args.proxy_url is the target. 
    # Logic: If config changed port, TUI should know.
    # We used args.proxy_url default "http://127.0.0.1:3000". 
    # If config says port 4000, we should probably use that unless user explicitly said --proxy-url ...
    
    final_proxy_url = args.proxy_url
    if final_proxy_url == "http://127.0.0.1:3000" and not args.no_proxy:
         # Use config values if default was kept
         final_proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"

    # logs globally before starting anything
    logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore").setLevel(logging.CRITICAL)
    logging.getLogger("multipart").setLevel(logging.CRITICAL)

    app = AIReconApp(proxy_url=final_proxy_url)
    try:
        app.run()
    except Exception as e:
        # If TUI crashes, we want to see why, but maybe to a file
        with open("airecon_crash.log", "w") as f:
            import traceback
            traceback.print_exc(file=f)
        print(f"AIRecon TUI crashed! Check airecon_crash.log for details.\nError: {e}")
        sys.exit(1)


def _run_status(args) -> None:
    """Check status of all services."""
    import asyncio
    import httpx
    
    async def check():
        from airecon.proxy.config import get_config
        import importlib.metadata
        cfg = get_config()

        try:
            version = importlib.metadata.version("airecon")
        except importlib.metadata.PackageNotFoundError:
            version = "0.1.4"

        # Colors
        G  = "\033[32m"   # green
        R  = "\033[31m"   # red
        Y  = "\033[33m"   # yellow
        C  = "\033[36m"   # cyan
        B  = "\033[1m"    # bold
        D  = "\033[2m"    # dim
        X  = "\033[0m"    # reset
        ON  = f"{G}● online{X}"
        OFF = f"{R}● offline{X}"

        W = 74  # box width

        print()
        print(f"  {C}╔{'═' * W}╗{X}")
        print(f"  {C}║{X}  {B}▄▖▄▖▄▖                                          {X}  {C}║{X}")
        print(f"  {C}║{X}  {B}▌▌▐ ▙▘█▌▛▘▛▌▛▌                                  {X}  {C}║{X}")
        print(f"  {C}║{X}  {B}▛▌▟▖▌▌▙▖▙▖▙▌▌▌                                  {X}  {C}║{X}")
        print(f"  {C}║{X}  {D}v{version} — AI-Powered Security Reconnaissance{X}        {C}║{X}")
        print(f"  {C}╠{'═' * W}╣{X}")

        # ── Ollama ──
        ollama_status = OFF
        model_names = []
        active_model = cfg.ollama_model
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{cfg.ollama_url}/api/tags")
                models = resp.json().get("models", [])
                model_names = [m["name"] for m in models]
                ollama_status = ON
        except Exception:
            pass

        print(f"  {C}║{X}")
        print(f"  {C}║{X}  {B}Ollama{X}        {ollama_status}")
        print(f"  {C}║{X}  {D}Endpoint:{X}     {cfg.ollama_url}")
        print(f"  {C}║{X}  {D}Active Model:{X} {Y}{active_model}{X}")
        if model_names:
            # Show models in a compact grid (3 per line)
            print(f"  {C}║{X}  {D}Available:{X}    ", end="")
            for i, name in enumerate(model_names):
                if i > 0 and i % 3 == 0:
                    print(f"\n  {C}║{X}               ", end="")
                if i % 3 > 0:
                    print("  ", end="")
                if name == active_model:
                    print(f"{G}{name}{X}", end="")
                else:
                    print(f"{D}{name}{X}", end="")
            print()

        # ── Docker ──
        print(f"  {C}║{X}")
        docker_status = OFF
        docker_detail = ""
        try:
            import subprocess as sp
            result = sp.run(
                ["docker", "ps", "--filter", "name=airecon-sandbox-active", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=3,
            )
            if result.stdout.strip():
                docker_status = f"{G}● running{X}"
                docker_detail = result.stdout.strip()
            else:
                docker_status = f"{Y}● standby{X}"
                docker_detail = "Container starts on first tool call"
        except Exception:
            docker_status = f"{R}● not found{X}"
            docker_detail = "Docker is not installed or not in PATH"

        print(f"  {C}║{X}  {B}Docker{X}        {docker_status}")
        if docker_detail:
            print(f"  {C}║{X}  {D}Detail:{X}       {docker_detail}")

        # ── Proxy ──
        print(f"  {C}║{X}")
        proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"
        proxy_status = OFF
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{proxy_url}/api/status")
                if resp.status_code == 200:
                    proxy_status = ON
        except Exception:
            pass

        print(f"  {C}║{X}  {B}Proxy{X}         {proxy_status}")
        print(f"  {C}║{X}  {D}Endpoint:{X}     {proxy_url}")

        print(f"  {C}║{X}")
        print(f"  {C}╚{'═' * W}╝{X}")
        print()

    asyncio.run(check())


def _unload_model_safely():
    """Attempt to unload model safely on exit using curl (most robust)."""
    try:
        from airecon.proxy.config import get_config
        import subprocess
        import json
        
        # Try to get loaded config, or load default
        try:
            cfg = get_config()
        except:
            # Fallback if config completely fails
            return

        url = cfg.ollama_url.rstrip("/")
        model = cfg.ollama_model
        
        print("\n[AIRecon] Cleaning up Docker Sandbox...", end="", flush=True)
        subprocess.run(["docker", "rm", "-f", "airecon-sandbox-active"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        print("Done.")
        
        print(f"[AIRecon] Unloading model '{model}' (releasing VRAM)... ", end="", flush=True)
        
        # Construct curl command
        # curl -X POST http://localhost:11434/api/generate -d '{"model": "...", "keep_alive": 0}'
        cmd = [
            "curl", "-s", "-X", "POST", f"{url}/api/generate",
            "-d", json.dumps({"model": model, "keep_alive": 0})
        ]
        
        # Run with timeout
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        print("Done.")

    except Exception as e:
            try:
                import urllib.request
                import json
                
                print("\n[AIRecon] Cleaning up Docker Sandbox...", end="", flush=True)
                import subprocess
                subprocess.run(["docker", "rm", "-f", "airecon-sandbox-active"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                print("Done.")
                
                print(f"[AIRecon] Unloading model (releasing VRAM)... ", end="", flush=True)
                
                # Fetch config again strictly for the urllib try block
                from airecon.proxy.config import get_config
                cfg = get_config()
                url = cfg.ollama_url.rstrip("/")
                model = cfg.ollama_model

                data = json.dumps({"model": model, "keep_alive": 0}).encode("utf-8")
                req = urllib.request.Request(f"{url}/api/generate", data=data, method="POST")
                urllib.request.urlopen(req, timeout=2)
                print("Done (via urllib).")
            except Exception:
                print("Failed.")



def _run_clean(args) -> None:
    """Clean Docker build cache, orphan containers, and unused volumes."""
    import subprocess
    import shutil

    CYAN  = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED   = "\033[91m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"
    CHECK = "✅"
    WARN  = "⚠️ "
    BROOM = "🧹"

    if not shutil.which("docker"):
        print(f"{RED}[!] Docker is not installed or not in PATH.{RESET}")
        sys.exit(1)

    def run(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )

    def get_docker_df() -> dict:
        """Return dict with Docker disk usage totals."""
        r = run(["docker", "system", "df", "--format", "{{json .}}"], capture=True)
        # docker system df --format json outputs multiple lines (one per type)
        totals = {"images": "?", "containers": "?", "volumes": "?", "cache": "?"}
        if r.returncode == 0:
            import json
            for line in r.stdout.decode(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    t = obj.get("Type", "")
                    size = obj.get("TotalCount", "?")
                    reclaimable = obj.get("Reclaimable", "?")
                    if "Image" in t:
                        totals["images"] = reclaimable
                    elif "Container" in t:
                        totals["containers"] = reclaimable
                    elif "Volume" in t:
                        totals["volumes"] = reclaimable
                    elif "Cache" in t or "Build" in t:
                        totals["cache"] = reclaimable
                except Exception:
                    pass
        return totals

    print(f"\n{BOLD}{BROOM} AIRecon Docker Cleanup{RESET}")
    print("─" * 48)

    # ── Show before state ──
    print(f"\n{CYAN}[Before Cleanup]{RESET}")
    run(["docker", "system", "df"])

    freed_items: list[str] = []

    # ── 1. Remove any leftover airecon containers ──
    print(f"\n{YELLOW}[1/4] Removing orphan airecon containers...{RESET}", end=" ", flush=True)
    containers = run(
        ["docker", "ps", "-a", "-q", "--filter", "name=airecon-sandbox"],
        capture=True
    )
    ids = containers.stdout.decode().strip().split() if containers.returncode == 0 else []
    if ids:
        for cid in ids:
            run(["docker", "rm", "-f", cid])
        print(f"{CHECK} Removed {len(ids)} container(s)")
        freed_items.append(f"{len(ids)} orphan container(s)")
    else:
        print(f"None found.")

    # ── 2. Prune build cache ──
    keep = getattr(args, "keep_storage", "3gb")
    if keep == "0":
        cache_cmd = ["docker", "builder", "prune", "-af"]
        label = "all build cache"
    else:
        cache_cmd = ["docker", "builder", "prune", "-f", f"--keep-storage={keep}"]
        label = f"build cache (keeping {keep} for fast rebuilds)"

    print(f"{YELLOW}[2/4] Pruning {label}...{RESET}", end=" ", flush=True)
    result = run(cache_cmd, capture=True)
    if result.returncode == 0:
        output = result.stdout.decode(errors="replace")
        # Try to parse the freed space line from docker output
        freed_line = next((l for l in output.splitlines() if "freed" in l.lower() or "Total" in l), "")
        print(f"{CHECK} {freed_line.strip() or 'Done'}")
        freed_items.append("build cache layers")
    else:
        print(f"{WARN} Failed (non-critical)")

    # ── 3. Prune unused volumes ──
    print(f"{YELLOW}[3/4] Pruning unused Docker volumes...{RESET}", end=" ", flush=True)
    vol_result = run(["docker", "volume", "prune", "-f"], capture=True)
    if vol_result.returncode == 0:
        vol_out = vol_result.stdout.decode(errors="replace")
        freed_vol = next((l for l in vol_out.splitlines() if "freed" in l.lower() or "Total" in l), "")
        print(f"{CHECK} {freed_vol.strip() or 'Done'}")
        freed_items.append("unused volumes")
    else:
        print(f"{WARN} Failed (non-critical)")

    # ── 4. Optionally remove sandbox image ──
    full_clean = getattr(args, "all", False)
    if full_clean:
        print(f"{YELLOW}[4/4] Removing airecon-sandbox image (--all flag)...{RESET}", end=" ", flush=True)
        img_result = run(["docker", "rmi", "-f", "airecon-sandbox"], capture=True)
        if img_result.returncode == 0:
            print(f"{CHECK} Removed. Next `airecon start` will rebuild (~10-20 min).")
            freed_items.append("airecon-sandbox image (12.5GB)")
        else:
            print(f"Not found or already removed.")
    else:
        print(f"{YELLOW}[4/4] Sandbox image kept{RESET} (use --all to remove it too)")

    # ── Show after state ──
    print(f"\n{CYAN}[After Cleanup]{RESET}")
    run(["docker", "system", "df"])

    print(f"\n{GREEN}{BOLD}{CHECK} Cleanup complete!{RESET}")
    if freed_items:
        for item in freed_items:
            print(f"   • Freed: {item}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
