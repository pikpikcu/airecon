"""Configuration management for AIRecon proxy."""

from __future__ import annotations

import os
import sys
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    "ollama_model": "qwen3.5:122b",
    "ollama_timeout": 1900.0,
    "ollama_num_ctx": 131072,
    "ollama_temperature": 0.6,
    "ollama_num_predict": 16384,
    "ollama_enable_thinking": True,
    "proxy_host": "127.0.0.1",
    "proxy_port": 3000,
    "command_timeout": 900.0,
    "docker_image": "airecon-sandbox",
    "docker_auto_build": True,
    "tool_response_role": "tool",
    "deep_recon_autostart": True,
    "agent_max_tool_iterations": 500,
    "agent_repeat_tool_call_limit": 2,
    "agent_missing_tool_retry_limit": 2,
    "allow_destructive_testing": True,
    "browser_page_load_delay": 1.0,
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
    ollama_temperature: float
    ollama_num_predict: int
    ollama_enable_thinking: bool

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

    # Safety
    allow_destructive_testing: bool

    # Browser
    browser_page_load_delay: float

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> Config:
        """Load config from specified path or default ~/.airecon/config.json."""
        if config_path:
            config_file = Path(config_path)
            # If explicit path given, it MUST exist (or we let it error/warn?)
            # Valid decision: If user provides path, we try to load it. If missing, we error.
        else:
            home_dir = Path.home()
            config_dir = home_dir / APP_DIR_NAME
            config_file = config_dir / CONFIG_FILENAME

            # Ensure directory exists only for default path
            if not config_dir.exists():
                # print(f"DEBUG: Creating config directory at {config_dir}")
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
                print(f"ERROR: Failed to load config from {config_file}: {e}")
                print("Using default configuration.")
        else:
            # Only generate default if using the default path
            if config_path is None:
                print(f"INFO: No config found. Generating default config at {config_file}")
                try:
                    with open(config_file, "w") as f:
                        json.dump(DEFAULT_CONFIG, f, indent=4)
                except Exception as e:
                    print(f"ERROR: Failed to write default config: {e}")
            else:
                print(f"WARNING: Configuration file not found at {config_file}")
                print("Using default configuration settings.")

        # Override with Environment Variables (Optional, for temporary overrides)
        for key in current_config:
            env_key = f"AIRECON_{key.upper()}"
            if env_key in os.environ:
                 val = os.environ[env_key]
                 default_val = DEFAULT_CONFIG.get(key)
                 if isinstance(default_val, bool):
                     current_config[key] = val.lower() in ("true", "1", "yes")
                 elif isinstance(default_val, int):
                     try: current_config[key] = int(val)
                     except: pass
                 elif isinstance(default_val, float):
                     try: current_config[key] = float(val)
                     except: pass
                 else:
                     current_config[key] = val

        return cls(**current_config)


# Singleton
_config: Config | None = None


def get_config(config_path: str | None = None) -> Config:
    """Get or create the global config instance, optionally loading from a path."""
    global _config
    if _config is None:
        _config = Config.load(config_path)
    return _config

