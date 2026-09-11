from __future__ import annotations

import argparse
import logging
import sys

from airecon._version import __version__

logger = logging.getLogger("airecon.cli")


def _print_banner() -> None:
    C = "\033[36m"
    B = "\033[1m"
    D = "\033[2m"
    Y = "\033[33m"
    X = "\033[0m"

    print()
    print(f"  {B}   █████████   █████ ███████████             {X}")                           
    print(f"  {B}  ███▒▒▒▒▒███ ▒▒███ ▒▒███▒▒▒▒▒███              {X}")                        
    print(f"  {B} ▒███    ▒███  ▒███  ▒███    ▒███   ██████   ██████   ██████  ████████  {X}")
    print(f"  {B} ▒███████████  ▒███  ▒██████████   ███▒▒███ ███▒▒███ ███▒▒███▒▒███▒▒███ {X}")
    print(f"  {B} ▒███▒▒▒▒▒███  ▒███  ▒███▒▒▒▒▒███ ▒███████ ▒███ ▒▒▒ ▒███ ▒███ ▒███ ▒███ {X}")
    print(f"  {B} ▒███    ▒███  ▒███  ▒███    ▒███ ▒███▒▒▒  ▒███  ███▒███ ▒███ ▒███ ▒███ {X}")
    print(f"  {B} █████   █████ █████ █████   █████▒▒██████ ▒▒██████ ▒▒██████  ████ █████ {X}")
    print(f"  {B} ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒   ▒▒▒▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒ ▒▒▒▒▒ {X}")                                                                                                                              
    print()
    print(f"  {D}          v{__version__} — AI-Powered Security Reconnaissance{X}")
    print()
    print(f"  {D}Quick start:{X} {C}airecon start{X}")
    print(f"  {D}See all options:{X} {Y}airecon -h{X}")
    print()
    print(f"  {D}For more information visit {C}https://pikpikcu.github.io/airecon/{X}")
    print()


def main() -> None:

    version = __version__

    parser = argparse.ArgumentParser(
        prog="airecon",
        description="AIRecon — AI-powered security reconnaissance",
    )
    parser.add_argument(
        "--version", "-v", action="version", version=f"%(prog)s {version}"
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to custom configuration file (default: ~/.airecon/config.yaml)",
    )
    parser.add_argument(
        "--list", action="store_true", help="List all saved sessions and exit"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    proxy_parser = subparsers.add_parser("proxy", help="Start proxy server only")
    proxy_parser.add_argument("--host", default=None, help="Host to bind to")
    proxy_parser.add_argument("--port", type=int, default=None, help="Port to bind to")
    proxy_parser.add_argument(
        "--config", default=None, help="Path to custom configuration file"
    )
    proxy_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging to /tmp/airecon/debug.log",
    )
    tui_parser = subparsers.add_parser(
        "start", help="Start TUI client (also starts proxy)"
    )
    tui_parser.add_argument(
        "--no-proxy", action="store_true", help="Don't auto-start proxy"
    )
    tui_parser.add_argument(
        "--proxy-url", default="http://127.0.0.1:3000", help="Proxy URL"
    )
    tui_parser.add_argument(
        "--config", default=None, help="Path to custom configuration file"
    )
    tui_parser.add_argument(
        "--session",
        default=None,
        metavar="SESSION_ID",
        help="Resume a previous session by ID (e.g. airecon start --session 1740842400_a3b4c5d6)",
    )
    tui_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging to /tmp/airecon/debug.log",
    )
    status_parser = subparsers.add_parser("status", help="Check status of services")
    status_parser.add_argument(
        "--config", default=None, help="Path to custom configuration file"
    )
    clean_parser = subparsers.add_parser(
        "clean", help="Clean Docker build cache, orphan containers, and unused volumes"
    )
    clean_parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Full clean: also remove the airecon-sandbox image (requires full rebuild next time)",
    )
    clean_parser.add_argument(
        "--keep-storage",
        default="3gb",
        help="Minimum build cache to keep for fast rebuilds (default: 3gb). Use 0 to remove all.",
    )

    args = parser.parse_args()
    from airecon.proxy.config import get_config

    get_config(args.config)

    if getattr(args, "list", False):
        _run_list_sessions()
        sys.exit(0)

    if args.command == "proxy":
        _run_proxy(args)
    elif args.command == "start":
        _run_tui(args)
    elif args.command == "status":
        _run_status(args)
    elif args.command == "clean":
        _run_clean(args)
    else:
        _print_banner()
        sys.exit(1)


def _run_proxy(args) -> None:
    if getattr(args, "debug", False):
        from airecon.logger import setup_logging

        setup_logging(is_tui=False)

    import atexit

    atexit.register(_unload_model_safely)
    import os

    import airecon.proxy.config as _cfg_module

    if args.host:
        os.environ["AIRECON_PROXY_HOST"] = args.host
    if args.port:
        os.environ["AIRECON_PROXY_PORT"] = str(args.port)

    if args.host or args.port:
        _cfg_module._config = None
        _cfg_module.get_config(getattr(args, "config", None))

    from airecon.proxy.server import run_server

    run_server()


def _run_tui(args) -> None:
    if getattr(args, "debug", False):
        import os

        os.environ["AIRECON_DEBUG"] = "1"
        from airecon.logger import setup_logging

        setup_logging(is_tui=True)

    import atexit
    import os

    atexit.register(_unload_model_safely)
    from airecon.proxy.config import get_config

    cfg = get_config()
    if getattr(args, "session", None):
        os.environ["AIRECON_SESSION_ID"] = args.session
    else:
        os.environ.pop("AIRECON_SESSION_ID", None)

    final_proxy_url = args.proxy_url
    if final_proxy_url == "http://127.0.0.1:3000" and not args.no_proxy:
        final_proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"

    logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore").setLevel(logging.CRITICAL)
    logging.getLogger("multipart").setLevel(logging.CRITICAL)
    if not getattr(args, "debug", False):
        logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)
    from airecon.tui.app import AIReconApp

    app = AIReconApp(
        proxy_url=final_proxy_url,
        no_proxy=args.no_proxy,
        session_id=getattr(args, "session", None),
    )
    try:
        app.run()
    except Exception as e:
        import tempfile
        import traceback
        from pathlib import Path

        crash_log = Path(tempfile.gettempdir()) / "airecon_crash.log"
        with open(crash_log, "w") as f:
            traceback.print_exc(file=f)
        print(f"AIRecon TUI crashed! Check {crash_log} for details.\nError: {e}")
        sys.exit(1)


def _run_status(args) -> None:
    import asyncio
    import re as _re
    import httpx

    async def check():
        from airecon._version import __version__ as version
        from airecon.proxy.config import get_config

        cfg = get_config()

        G = "\033[32m"
        R = "\033[31m"
        Y = "\033[33m"
        C = "\033[36m"
        B = "\033[1m"
        D = "\033[2m"
        X = "\033[0m"
        ON = f"{G}● online{X}"
        OFF = f"{R}● offline{X}"

        W = 74
        _ANSI = _re.compile(r"\033\[[0-9;]*m")

        def _vlen(s: str) -> int:
            return len(_ANSI.sub("", s))

        def _row(content: str = "") -> str:
            pad = max(0, W - _vlen(content))
            return f"  {C}║{X}{content}{' ' * pad}{C}║{X}"

        print()
        print(f"  {C}╔{'═' * W}╗{X}")
        print(_row(f"  {B}▄▖▄▖▄▖{X}"))
        print(_row(f"  {B}▌▌▐ ▙▘█▌▛▘▛▌▛▌{X}"))
        print(_row(f"  {B}▛▌▟▖▌▌▙▖▙▖▙▌▌▌{X}"))
        print(_row(f"  {D}v{version} — AI-Powered Security Reconnaissance{X}"))
        print(f"  {C}╠{'═' * W}╣{X}")

        llm_status = OFF
        model_names: list[str] = []
        active_model = cfg.openai_model
        try:
            _headers = {}
            if cfg.openai_api_key:
                _headers["Authorization"] = f"Bearer {cfg.openai_api_key}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{cfg.openai_base_url.rstrip('/')}/models", headers=_headers
                )
                resp.raise_for_status()
                models = resp.json().get("data", [])
                model_names = [m.get("id", "") for m in models if isinstance(m, dict)]
                llm_status = ON
        except Exception as e:
            logger.debug("LLM status check failed: %s", e)

        print(_row())
        print(_row(f"  {B}LLM Gateway{X}   {llm_status}"))
        print(_row(f"  {D}Endpoint:{X}     {cfg.openai_base_url}"))
        print(_row(f"  {D}Active Model:{X} {Y}{active_model}{X}"))
        if model_names:
            label = f"  {D}Available:{X}    "
            indent = " " * _vlen(label)
            line_content = label
            for i, name in enumerate(model_names):
                cell = f"{G}{name}{X}" if name == active_model else f"{D}{name}{X}"
                if i > 0 and i % 3 == 0:
                    print(_row(line_content))
                    line_content = indent
                elif i % 3 > 0:
                    line_content += "  "
                line_content += cell
            print(_row(line_content))

        print(_row())
        docker_status = OFF
        docker_detail = ""
        try:
            import shutil
            import subprocess as sp  # nosec B404

            _docker = shutil.which("docker") or "docker"
            result = sp.run(  # nosec B603
                [
                    _docker,
                    "ps",
                    "--filter",
                    "name=airecon-sandbox-active",
                    "--format",
                    "{{.Status}}",
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.stdout.strip():
                docker_status = f"{G}● running{X}"
                docker_detail = result.stdout.strip()
            else:
                docker_status = f"{Y}● standby{X}"
                docker_detail = "Container starts on first tool call"
        except Exception as e:
            logger.debug("Docker status check failed: %s", e)
            docker_status = f"{R}● not found{X}"
            docker_detail = "Docker is not installed or not in PATH"

        print(_row(f"  {B}Docker{X}        {docker_status}"))
        if docker_detail:
            print(_row(f"  {D}Detail:{X}       {docker_detail}"))

        print(_row())
        searxng_status = OFF
        searxng_detail = ""
        try:
            import shutil
            import subprocess as sp  # nosec B404

            _docker = shutil.which("docker") or "docker"
            result = sp.run(  # nosec B603
                [
                    _docker,
                    "ps",
                    "--filter",
                    "name=airecon-searxng",
                    "--filter",
                    "status=running",
                    "--format",
                    "{{.Status}}",
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.stdout.strip():
                searxng_configured = bool(cfg.searxng_url)
                searxng_status = (
                    f"{G}● running{X}"
                    if searxng_configured
                    else f"{Y}● running (unconfigured){X}"
                )
                searxng_detail = (
                    cfg.searxng_url or "http://localhost:8080 (auto-managed)"
                )
            else:
                searxng_status = f"{Y}● stopped{X}"
                searxng_detail = "Starts automatically with 'airecon start'"
        except Exception as e:
            logger.debug("SearXNG status check failed: %s", e)
            searxng_status = f"{Y}● unknown{X}"
            searxng_detail = "Docker not available"

        print(_row(f"  {B}SearXNG{X}       {searxng_status}"))
        if searxng_detail:
            print(_row(f"  {D}Endpoint:{X}     {searxng_detail}"))

        print(_row())
        proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"
        proxy_status = OFF
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{proxy_url}/api/status")
                if resp.status_code == 200:
                    proxy_status = ON
        except Exception as e:
            logger.debug("Proxy status check failed: %s", e)

        print(_row(f"  {B}Proxy{X}         {proxy_status}"))
        print(_row(f"  {D}Endpoint:{X}     {proxy_url}"))

        print(_row())
        print(f"  {C}╚{'═' * W}╝{X}")
        print()

    asyncio.run(check())

def _unload_model_safely():
    import json
    import shutil
    import subprocess  # nosec B404
    import urllib.request

    C = "\033[36m"
    G = "\033[32m"
    Y = "\033[33m"
    R = "\033[31m"
    D = "\033[2m"
    B = "\033[1m"
    X = "\033[0m"
    W = 54
    INNER_W = W + 2

    def _row(content: str = "") -> str:
        import re
        import unicodedata

        ansi_re = re.compile(r"\033\[[0-9;]*m")

        def display_width(s: str) -> int:
            plain = ansi_re.sub("", s)
            width = 0
            for ch in plain:
                if unicodedata.combining(ch):
                    continue
                width += 2 if unicodedata.east_asian_width(ch) in {"W", "F"} else 1
            return width

        visible = display_width(content)
        pad = max(0, INNER_W - visible)
        return f"  {C}║{X}{content}{' ' * pad}{C}║{X}"

    def _divider() -> None:
        print(f"  {C}╠{'═' * (W + 2)}╣{X}")

    _KEY_COL = 12
    _SERVICE_COL = 20

    def _kv(label: str, value: str) -> str:
        return _row(f"  {D}{label:<{_KEY_COL}}{X} {value}")

    def _svc(icon: str, name: str, state: str) -> str:
        return _row(f"  {icon} {name:<{_SERVICE_COL}} {D}{state}{X}")

    def _fmt_tokens(n: int) -> str:
        if n >= 1_000_000_000:
            return f"{n / 1_000_000_000:.3f}B"
        if n >= 1_000_000:
            return f"{n / 1_000_000:.3f}M"
        if n >= 1_000:
            return f"{n / 1_000:.1f}k"
        return str(n)

    try:
        from airecon.proxy.config import get_config

        cfg = get_config()
    except BaseException:
        return

    proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"
    _docker = shutil.which("docker") or "docker"
    session_info: dict = {}
    agent_stats: dict = {}
    import time as _time

    _time.sleep(0.3)
    try:
        resp = urllib.request.urlopen(f"{proxy_url}/api/status", timeout=3)  # nosec B310
        data = json.loads(resp.read())
        agent_stats = data.get("agent", {})
    except Exception as e:
        logger.debug("Failed to fetch proxy status: %s", e)
    try:
        resp2 = urllib.request.urlopen(f"{proxy_url}/api/session/current", timeout=3)  # nosec B310
        session_info = json.loads(resp2.read()).get("session") or {}
    except Exception as e:
        logger.debug("Failed to fetch current session: %s", e)

    if not session_info:
        try:
            from pathlib import Path as _Path

            _sessions_dir = _Path.home() / ".airecon" / "sessions"
            if _sessions_dir.exists():
                _files = sorted(
                    _sessions_dir.glob("*.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if _files:
                    with open(_files[0]) as _sf:
                        _sd = json.load(_sf)
                    import time as _t

                    _age = _t.time() - _files[0].stat().st_mtime
                    if _age < 86400 and _sd.get("target"):
                        session_info = {
                            "session_id": _sd.get("session_id", ""),
                            "target": _sd.get("target", ""),
                            "scan_count": _sd.get("scan_count", 0),
                            "subdomains": len(_sd.get("subdomains", [])),
                            "live_hosts": len(_sd.get("live_hosts", [])),
                            "vulnerabilities": len(_sd.get("vulnerabilities", [])),
                        }
        except Exception as e:
            logger.debug("Failed to load recent session file: %s", e)

    token_usage = agent_stats.get("token_usage", {})
    tool_counts = agent_stats.get("tool_counts", {})
    cumulative_tokens = token_usage.get("cumulative", token_usage.get("used", 0))
    exec_count = tool_counts.get("exec", 0)
    total_tools = sum(tool_counts.values()) if tool_counts else 0

    print()
    print(f"  {C}╔{'═' * (W + 2)}╗{X}")
    print(_row())
    print(_row(f"  {B}Session Summary{X}"))
    print(_row())
    _divider()
    print(_row())

    if session_info:
        sid = session_info.get("session_id", "—")
        target = session_info.get("target") or "—"
        scans = session_info.get("scan_count", 0)
        subdomains = session_info.get("subdomains", 0)
        live_hosts = session_info.get("live_hosts", 0)
        vulns = session_info.get("vulnerabilities", 0)
        print(_kv("Session", f"{C}{sid}{X}"))
        print(_kv("Target", f"{B}{target}{X}"))
        print(_kv("Scans", f"{Y}{scans}{X}"))
        if subdomains:
            print(_kv("Subdomains", f"{G}{subdomains}{X}"))
        if live_hosts:
            print(_kv("Live Hosts", f"{G}{live_hosts}{X}"))
        if vulns:
            print(_kv("Findings", f"{R}{vulns}{X}"))
    else:
        print(_kv("Session", f"{D}none{X}"))

    print(_row())
    _divider()
    print(_row())

    tok_color = (
        G
        if cumulative_tokens < 1_000_000
        else (Y if cumulative_tokens < 5_000_000 else R)
    )
    print(_kv("Tokens used", f"{tok_color}{_fmt_tokens(cumulative_tokens)}{X}"))
    print(_kv("Tool calls", f"{Y}{total_tools}{X}  {D}(call: {exec_count}){X}"))

    print(_row())
    _divider()
    print(_row())

    print(_row(f"  {D}Stopping sandbox container…{X}"), end="\r", flush=True)
    try:
        subprocess.run(  # nosec B603
            [_docker, "rm", "-f", "airecon-sandbox-active"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        print(_svc(f"{G}✓{X}", "Docker Sandbox", "stopped"))
    except Exception:
        print(_svc(f"{Y}!{X}", "Docker Sandbox", "unavailable"))

    try:
        if (
            not cfg.searxng_url
            or "localhost" in cfg.searxng_url
            or "127.0.0.1" in cfg.searxng_url
        ):
            from airecon.proxy.searxng import CONTAINER_NAME as _SX_NAME

            subprocess.run(  # nosec B603
                [_docker, "rm", "-f", _SX_NAME],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            print(_svc(f"{G}✓{X}", "SearXNG", "stopped"))
    except Exception as e:
        logger.debug("SearXNG shutdown failed: %s", e)

    # Remote OpenAI-compatible gateways are stateless — no local VRAM to release.

    print(_row())
    print(f"  {C}╚{'═' * (W + 2)}╝{X}")
    print()


def _run_list_sessions() -> None:
    from airecon.proxy.agent.session import list_sessions

    C = "\033[36m"
    B = "\033[1m"
    D = "\033[2m"
    G = "\033[32m"
    Y = "\033[33m"
    X = "\033[0m"

    sessions = list_sessions()

    print()
    if not sessions:
        print(f"  {D}No saved sessions found.{X}")
        print(f"  Start a new session: {C}airecon start{X}")
        print()
        return

    print(
        f"  {B}{'SESSION ID':<28} {'TARGET':<24} {'SCANS':>5}  {'SUBS':>4}  {'VULNS':>5}  CREATED{X}"
    )
    print(f"  {'─' * 28} {'─' * 24} {'─' * 5}  {'─' * 4}  {'─' * 5}  {'─' * 10}")

    for s in sessions:
        sid = s["session_id"]
        target = s["target"] or f"{D}(no target){X}"
        scans = s["scan_count"]
        subs = s.get("subdomains", 0)
        vulns = s.get("vulnerabilities", 0)
        created = s.get("created_at", "")[:10]

        vuln_str = f"{Y}{vulns:>5}{X}" if vulns > 0 else f"{D}{vulns:>5}{X}"
        print(
            f"  {G}{sid:<28}{X} {target:<24} {scans:>5}  {subs:>4}  {vuln_str}  {D}{created}{X}"
        )

    print()
    print(f"  Resume: {C}airecon start --session <id>{X}")
    print()


def _run_clean(args) -> None:
    import shutil
    import subprocess  # nosec B404

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    CHECK = "✅"
    WARN = "⚠️ "
    BROOM = "🧹"

    if not shutil.which("docker"):
        print(f"{RED}[!] Docker is not installed or not in PATH.{RESET}")
        sys.exit(1)

    def run(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(  # nosec B603
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )

    print(f"\n{BOLD}{BROOM} AIRecon Docker Cleanup{RESET}")
    print("─" * 48)

    print(f"\n{CYAN}[Before Cleanup]{RESET}")
    run(["docker", "system", "df"])

    freed_items: list[str] = []

    print(
        f"\n{YELLOW}[1/4] Removing orphan airecon containers...{RESET}",
        end=" ",
        flush=True,
    )
    containers = run(
        ["docker", "ps", "-a", "-q", "--filter", "name=airecon"], capture=True
    )
    ids = (
        containers.stdout.decode().strip().split() if containers.returncode == 0 else []
    )
    if ids:
        for cid in ids:
            run(["docker", "rm", "-f", cid])
        print(f"{CHECK} Removed {len(ids)} container(s)")
        freed_items.append(f"{len(ids)} orphan container(s)")
    else:
        print("None found.")

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
        freed_line = next(
            (
                line
                for line in output.splitlines()
                if "freed" in line.lower() or "Total" in line
            ),
            "",
        )
        print(f"{CHECK} {freed_line.strip() or 'Done'}")
        freed_items.append("build cache layers")
    else:
        print(f"{WARN} Failed (non-critical)")

    print(f"{YELLOW}[3/4] Pruning unused Docker volumes...{RESET}", end=" ", flush=True)
    vol_result = run(["docker", "volume", "prune", "-f"], capture=True)
    if vol_result.returncode == 0:
        vol_out = vol_result.stdout.decode(errors="replace")
        freed_vol = next(
            (
                line
                for line in vol_out.splitlines()
                if "freed" in line.lower() or "Total" in line
            ),
            "",
        )
        print(f"{CHECK} {freed_vol.strip() or 'Done'}")
        freed_items.append("unused volumes")
    else:
        print(f"{WARN} Failed (non-critical)")

    full_clean = getattr(args, "all", False)
    if full_clean:
        print(
            f"{YELLOW}[4/4] Removing airecon-sandbox image (--all flag)...{RESET}",
            end=" ",
            flush=True,
        )
        img_result = run(["docker", "rmi", "-f", "airecon-sandbox"], capture=True)
        if img_result.returncode == 0:
            print(f"{CHECK} Removed. Next `airecon start` will rebuild (~10-20 min).")
            freed_items.append("airecon-sandbox image (12.5GB)")
        else:
            print("Not found or already removed.")
    else:
        print(f"{YELLOW}[4/4] Sandbox image kept{RESET} (use --all to remove it too)")

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
