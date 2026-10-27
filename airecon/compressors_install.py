"""Install optional, checksum-pinned compressors without shell installers or hooks.

Usage: python -m airecon.compressors_install [--prefix PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
from urllib.request import urlopen


MANIFEST = Path(__file__).parent / "proxy" / "data" / "compressors.json"


def verify_asset(data: bytes, expected: str) -> None:
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Compressor download checksum mismatch")


def binary_from_asset(name: str, data: bytes, archive: bool) -> bytes:
    if not archive:
        return data
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == name]
        if len(members) != 1 or members[0].size > 100 * 1024 * 1024:
            raise ValueError("Unexpected compressor archive layout")
        stream = tar.extractfile(members[0])
        if stream is None:
            raise ValueError("Compressor binary missing from archive")
        return stream.read()


def install(prefix: Path, system: str | None = None, machine: str | None = None) -> dict:
    machine = machine or platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    key = f"{system or platform.system().lower()}-{machine}"
    manifest = json.loads(MANIFEST.read_text())
    if any(key not in spec["assets"] for spec in manifest.values()):
        raise ValueError(f"No pinned compressor assets for {key}; built-in compaction remains available")
    prefix.mkdir(parents=True, exist_ok=True)
    receipt = {}
    for name, spec in manifest.items():
        asset = spec["assets"][key]
        with urlopen(asset["url"], timeout=60) as response:  # nosec B310 — pinned HTTPS release URLs
            data = response.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024:
            raise ValueError("Compressor asset exceeds download limit")
        verify_asset(data, asset["sha256"])
        binary = binary_from_asset(name, data, asset["url"].endswith(".tar.gz"))
        destination = prefix / name
        if destination.exists() and destination.read_bytes() != binary:
            raise FileExistsError(f"Refusing to replace a different existing binary: {destination}")
        if not destination.exists():
            with tempfile.NamedTemporaryFile(dir=prefix, prefix=f".{name}-", delete=False) as stream:
                temporary = Path(stream.name)
                try:
                    stream.write(binary)
                    stream.flush()
                    os.fsync(stream.fileno())
                    temporary.chmod(0o755)
                    os.replace(temporary, destination)
                finally:
                    temporary.unlink(missing_ok=True)
        receipt[name] = {"version": spec["version"], "asset_sha256": asset["sha256"],
                         "binary_sha256": hashlib.sha256(binary).hexdigest(), "path": str(destination)}
        print(f"Installed {name} {spec['version']} (SHA-256 verified)")
    receipt_path = prefix / "compressors-installed.json"
    receipt_path.write_text(json.dumps(receipt, indent=2))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".airecon" / "bin")
    args = parser.parse_args()
    install(args.prefix)


if __name__ == "__main__":
    main()
