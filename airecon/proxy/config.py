"""Configuration management for AIRecon proxy."""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

APP_DIR_NAME = ".airecon"
CONFIG_FILENAME = "config.json"


_workspace_root_cache: Path | None = None


def get_workspace_root() -> Path:
    """Return workspace root = <CWD>/workspace/ captured at first call (startup).

    Using CWD lets users place workspaces wherever they run `airecon start`,
    making monitoring easy: the workspace folder appears right beside where
    the command was launched.  The path is cached after the first call so
    it stays consistent even if os.getcwd() ever changes later in the process.
    """
    global _workspace_root_cache
    if _workspace_root_cache is None:
        _workspace_root_cache = Path.cwd() / "workspace"
        _workspace_root_cache.mkdir(parents=True, exist_ok=True)
    return _workspace_root_cache


DEFAULT_CONFIG = {
    "ollama_url": "http://127.0.0.1:11434",
    # Qwen3.5:122b — 122B parameter model with 128K context and extended thinking.
    # Tuned for maximum reasoning depth and autonomous pentesting coverage.
    "ollama_model": "qwen3.5:122b",
    # 2400s — 122B parameter inference takes longer than smaller models.
    "ollama_timeout": 2400.0,
    # 131072 = full 128K context window supported by Qwen3.5:122b.
    # WARNING: KV cache at 131K ctx ≈ 31 GB extra VRAM for 122B model.
    # Lower to 32768 if VRAM crashes occur frequently.
    "ollama_num_ctx": 131072,
    # 32768 = 32K — used for CTF mode and summary calls to cap KV cache VRAM.
    # KV cache at 32K ctx ≈ 8 GB (vs 31 GB at 131K) — 4x reduction.
    "ollama_num_ctx_small": 32768,
    # Low temperature keeps reasoning deterministic and reduces hallucination.
    "ollama_temperature": 0.15,
    # 32768 tokens for deep thinking + detailed tool-call responses.
    "ollama_num_predict": 32768,
    "ollama_enable_thinking": True,
    "ollama_supports_thinking": True,
    "ollama_supports_native_tools": True,
    # Maximum concurrent Ollama requests from this AIRecon process.
    # Keep 1 for stability on large models; increase only if server has headroom.
    "ollama_max_concurrent_requests": 1,
    # Protect the first N tokens (system prompt) from Ollama's KV-cache eviction.
    # Set to >= system prompt token count (~8K for AIRecon) so the model never
    # loses scope/rules due to Ollama-level truncation in long sessions.
    "ollama_num_keep": 8192,
    # Repeat penalty — prevents model from getting stuck in repetition loops
    # during long recon sessions when KV cache pressure causes flat probability.
    # 1.05 is conservative; range 1.0 (off) – 1.2 (aggressive).
    "ollama_repeat_penalty": 1.05,
    "proxy_host": "127.0.0.1",
    "proxy_port": 3000,
    "command_timeout": 900.0,
    "docker_image": "airecon-sandbox",
    "docker_auto_build": True,
    "tool_response_role": "tool",
    "deep_recon_autostart": True,
    # 800 iterations — 122B model can sustain long chains without degrading.
    "agent_max_tool_iterations": 800,
    "agent_repeat_tool_call_limit": 2,
    "agent_missing_tool_retry_limit": 2,
    "agent_plan_revision_interval": 30,
    "agent_exploration_mode": True,
    # 0.9 — push exploration hard; 122B model handles branching paths well.
    "agent_exploration_intensity": 0.9,
    "agent_exploration_temperature": 0.35,
    "agent_stagnation_threshold": 2,
    "agent_tool_diversity_window": 8,
    "agent_max_same_tool_streak": 3,
    "allow_destructive_testing": False,
    "browser_page_load_delay": 1.0,
    # Browser action timeout in seconds (applies to each browser coroutine).
    "browser_action_timeout": 120,
    # -1 = keep model loaded in VRAM indefinitely (dedicated server).
    # Use "60m" if sharing a machine with other workloads.
    # Must be int (-1, 0) or a duration string with unit ("60m", "1h").
    # The bare string "-1" is invalid — Ollama rejects it with HTTP 400.
    "ollama_keep_alive": -1,
    "searxng_url": "http://localhost:8080",
    "searxng_engines": "google,bing,duckduckgo,brave,google_news,github,stackoverflow",
    "vuln_similarity_threshold": 0.7,
    # Phase transition depth requirements for RECON phase.
    # Agent must discover >= N subdomains before RECON→ANALYSIS transition.
    "pipeline_recon_min_subdomains": 3,
    # Agent must collect >= N URLs before RECON→ANALYSIS transition.
    "pipeline_recon_min_urls": 1,
    # Soft timeout (iterations) — force RECON→ANALYSIS after this many iterations
    # regardless of depth criteria, to prevent infinite RECON loops.
    "pipeline_recon_soft_timeout": 30,
}


@dataclass(frozen=True)
class Config:
    """Application configuration loaded from ~/.airecon/config.json."""

    # Ollama
    ollama_url: str
    ollama_model: str

    # Proxy server
    proxy_host: str
    proxy_port: int

    # Timeouts (seconds)
    ollama_timeout: float
    command_timeout: float

    # Ollama Model Options
    ollama_num_ctx: int
    ollama_num_ctx_small: int
    ollama_temperature: float
    ollama_num_predict: int
    ollama_enable_thinking: bool
    ollama_supports_thinking: bool
    ollama_supports_native_tools: bool
    ollama_max_concurrent_requests: int
    ollama_num_keep: int
    ollama_repeat_penalty: float

    # Docker sandbox
    docker_image: str
    docker_auto_build: bool

    # Tooling behavior
    tool_response_role: str

    # Deep recon behavior
    deep_recon_autostart: bool

    # Agent loop controls
    agent_max_tool_iterations: int
    agent_repeat_tool_call_limit: int
    agent_missing_tool_retry_limit: int
    agent_plan_revision_interval: int
    agent_exploration_mode: bool
    agent_exploration_intensity: float
    agent_exploration_temperature: float
    agent_stagnation_threshold: int
    agent_tool_diversity_window: int
    agent_max_same_tool_streak: int

    # Safety
    allow_destructive_testing: bool

    # Browser
    browser_page_load_delay: float
    # Timeout (seconds) for each browser coroutine dispatched via run_coroutine_threadsafe.
    browser_action_timeout: int

    # Ollama model keep_alive (how long to keep model in VRAM)
    # int: -1 = infinite, 0 = unload immediately; str must include unit ("60m")
    ollama_keep_alive: int | str

    # SearXNG self-hosted search (leave empty to use DuckDuckGo fallback)
    searxng_url: str
    searxng_engines: str

    # Vulnerability deduplication threshold (0.0-1.0, default 0.7)
    vuln_similarity_threshold: float

    # Phase transition depth requirements
    pipeline_recon_min_subdomains: int
    pipeline_recon_min_urls: int
    pipeline_recon_soft_timeout: int

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> Config:
        """Load config from specified path or default ~/.airecon/config.json."""
        if config_path:
            config_file = Path(config_path)
            # If explicit path given, it MUST exist (or we let it error/warn?)
            # Valid decision: If user provides path, we try to load it. If
            # missing, we error.
        else:
            home_dir = Path.home()
            config_dir = home_dir / APP_DIR_NAME
            config_file = config_dir / CONFIG_FILENAME

            # Ensure directory exists only for default path
            if not config_dir.exists():
                config_dir.mkdir(parents=True, exist_ok=True)

        current_config = DEFAULT_CONFIG.copy()

        # Load or Create
        if config_file.exists():
            try:
                with open(config_file, "r") as f:
                    user_config = json.load(f)
                    # Merge user config into defaults
                    current_config.update(user_config)
            except Exception as e:
                logger.error(
                    "Failed to load config from %s: %s. "
                    "Resetting to defaults and rewriting config file.",
                    config_file, e,
                )
                # Rewrite corrupt config with defaults so next startup is clean
                try:
                    with open(config_file, "w") as f:
                        json.dump(DEFAULT_CONFIG, f, indent=4)
                    logger.info("Config file reset to defaults at %s", config_file)
                except Exception as write_err:
                    logger.error("Could not rewrite config file: %s", write_err)
        else:
            # Only generate default if using the default path
            if config_path is None:
                logger.info(
                    f"No config found. Generating default config at {config_file}")
                try:
                    with open(config_file, "w") as f:
                        json.dump(DEFAULT_CONFIG, f, indent=4)
                except Exception as e:
                    logger.error(f"Failed to write default config: {e}")
            else:
                logger.warning(
                    f"Configuration file not found at {config_file}. Using default configuration settings.")

        # Override with Environment Variables (Optional, for temporary
        # overrides)
        for key in current_config:
            env_key = f"AIRECON_{key.upper()}"
            if env_key in os.environ:
                val = os.environ[env_key]
                default_val = DEFAULT_CONFIG.get(key)
                if isinstance(default_val, bool):
                    current_config[key] = val.lower() in ("true", "1", "yes")
                elif isinstance(default_val, int):
                    try:
                        current_config[key] = int(val)
                    except (ValueError, TypeError):
                        logger.warning("AIRECON_%s env var %r is not a valid int — ignored", key.upper(), val)
                elif isinstance(default_val, float):
                    try:
                        current_config[key] = float(val)
                    except (ValueError, TypeError):
                        logger.warning("AIRECON_%s env var %r is not a valid float — ignored", key.upper(), val)
                else:
                    current_config[key] = val

        return cls.load_with_defaults(current_config)

    @classmethod
    def load_with_defaults(cls, raw: dict) -> Config:
        """Construct Config from a raw dict safely.

        - Unknown keys (old/removed fields) are silently ignored.
        - Missing keys fall back to DEFAULT_CONFIG values.
        - Wrong-typed values are coerced to the expected type (e.g. "3000" → 3000).

        This prevents cryptic dataclass errors when users have outdated
        config files that contain fields no longer in the dataclass, or
        when new fields are added without a migration step.
        """
        known_fields = {f.name for f in dataclasses.fields(cls)}
        merged = {k: DEFAULT_CONFIG[k] for k in known_fields if k in DEFAULT_CONFIG}
        merged.update({k: v for k, v in raw.items() if k in known_fields})
        unknown = set(raw) - known_fields
        if unknown:
            logger.warning(
                "Config: ignoring unknown fields (possibly from an older config): %s",
                ", ".join(sorted(unknown)),
            )

        # Type coercion: ensure each value matches the type of its default.
        for key in list(merged):
            default_val = DEFAULT_CONFIG.get(key)
            if default_val is None:
                continue
            expected_type = type(default_val)
            val = merged[key]
            if not isinstance(val, expected_type):
                try:
                    if expected_type is bool:
                        if isinstance(val, str):
                            merged[key] = val.lower() in ("true", "1", "yes")
                        else:
                            merged[key] = bool(val)
                    else:
                        merged[key] = expected_type(val)
                    logger.warning(
                        "Config: coerced '%s' from %s to %s",
                        key, type(val).__name__, expected_type.__name__,
                    )
                except (ValueError, TypeError):
                    logger.warning(
                        "Config: could not coerce '%s' value %r to %s — using default %r",
                        key, val, expected_type.__name__, default_val,
                    )
                    merged[key] = default_val

        # Bounds validation: reset out-of-range values to defaults.
        _BOUNDS: dict[str, tuple[float | None, float | None]] = {
            "vuln_similarity_threshold": (0.0, 1.0),
            "ollama_timeout": (1.0, None),
            "command_timeout": (1.0, None),
            "agent_max_tool_iterations": (1, None),
            "agent_repeat_tool_call_limit": (1, None),
            "agent_missing_tool_retry_limit": (0, None),
            "agent_plan_revision_interval": (1, None),
            "agent_exploration_intensity": (0.0, 1.0),
            "agent_exploration_temperature": (0.0, 2.0),
            "agent_stagnation_threshold": (1, None),
            "agent_tool_diversity_window": (3, None),
            "agent_max_same_tool_streak": (1, None),
            "ollama_num_ctx": (1024, None),
            "ollama_num_ctx_small": (1024, None),
            "ollama_num_predict": (1, None),
            "ollama_max_concurrent_requests": (1, None),
            "ollama_num_keep": (0, None),
            "ollama_repeat_penalty": (1.0, 2.0),
            "browser_action_timeout": (5, None),
            "pipeline_recon_min_subdomains": (0, None),
            "pipeline_recon_min_urls": (0, None),
            "pipeline_recon_soft_timeout": (5, None),
        }
        for bkey, (lo, hi) in _BOUNDS.items():
            bval = merged.get(bkey)
            if bval is None:
                continue
            out_of_range = (lo is not None and bval < lo) or (hi is not None and bval > hi)
            if out_of_range:
                default_bval = DEFAULT_CONFIG[bkey]
                logger.warning(
                    "Config: '%s' value %r is out of allowed range [%s, %s] — using default %r",
                    bkey, bval, lo, hi, default_bval,
                )
                merged[bkey] = default_bval

        return cls(**merged)


# Singleton
_config: Config | None = None
_config_mtime: float = 0.0
_config_path: Path | None = None


def _get_config_path(config_path: str | Path | None = None) -> Path:
    """Resolve the config file path."""
    if config_path:
        return Path(config_path)
    return Path.home() / APP_DIR_NAME / CONFIG_FILENAME


def get_config(config_path: str | None = None) -> Config:
    """Get or create the global config instance.

    Auto-reloads if the config file has been modified since last load.
    """
    global _config, _config_mtime, _config_path

    if _config_path is None:
        _config_path = _get_config_path(config_path)

    # Check if config file was modified (hot-reload)
    if _config is not None:
        try:
            current_mtime = (
                _config_path.stat().st_mtime if _config_path.exists() else 0.0
            )
            if current_mtime > _config_mtime:
                logger.info(
                    f"Config file changed — reloading from {_config_path}")
                _config = Config.load(_config_path)
                _config_mtime = current_mtime
        except Exception:  # nosec B110 - keep existing config if stat fails
            pass

    if _config is None:
        _config = Config.load(config_path)
        try:
            _config_mtime = (
                _config_path.stat().st_mtime if _config_path.exists() else 0.0
            )
        except Exception:
            _config_mtime = 0.0

    return _config


def reload_config() -> Config:
    """Force reload config from disk. Returns the new config."""
    global _config, _config_mtime
    _config = None
    _config_mtime = 0.0
    return get_config()
