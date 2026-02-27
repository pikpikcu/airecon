"""Logging configuration for AIRecon."""

import logging
import os
import sys
from pathlib import Path

def setup_logging(log_file: str = "log/log.txt", level: int = logging.DEBUG) -> None:
    """Setup logging to file and optionally stderr."""
    
    # Create log directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Handlers
    handlers = [
        logging.FileHandler(log_path, mode='a', encoding='utf-8'),
    ]

    # Only add stream handler if NOT running TUI (to avoid breaking UI)
    # We can heuristically check if "tui" is in sys.argv
    if "tui" not in sys.argv:
        handlers.append(logging.StreamHandler())

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True  # Overwrite existing config
    )

    # Suppress noisy third-party logs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("markdown_it").setLevel(logging.WARNING)

    # Ensure our loggers are at DEBUG
    logging.getLogger("airecon").setLevel(logging.DEBUG)
    
    # Log startup
    logging.info("="*60)
    logging.info(f"AIRecon Logging Started. Writing to {log_path.absolute()}")
    logging.info("="*60)
