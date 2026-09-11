from __future__ import annotations

try:
    from importlib.metadata import version

    __version__ = version("airecon")
except Exception:
    __version__ = "1.7.1-beta"
