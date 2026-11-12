"""Direct source invocation must not silently import another installed AIRecon."""
from pathlib import Path
import os
import subprocess
import sys


def test_direct_source_entrypoint_prefers_its_own_package(tmp_path):
    root = Path(__file__).resolve().parents[1]
    decoy = tmp_path / "installed" / "airecon"
    decoy.mkdir(parents=True)
    (decoy / "__init__.py").write_text("", encoding="utf-8")
    (decoy / "_version.py").write_text("__version__ = 'WRONG_INSTALLED_COPY'\n", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(decoy.parent), "HOME": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(root / "airecon" / "__main__.py"), "--version"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "WRONG_INSTALLED_COPY" not in result.stdout
    assert result.stdout.startswith("airecon ")
