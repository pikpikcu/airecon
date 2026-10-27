"""Safety and fidelity boundaries for optional native compressors."""
from __future__ import annotations

import hashlib
import io

import subprocess
import tarfile
from types import SimpleNamespace

import pytest

from airecon.compressors_install import binary_from_asset, verify_asset
from airecon.proxy.context_budget import ArtifactCompressor, ContextBudgetError, pack_history


@pytest.mark.parametrize("backend", ["rtk", "caveman"])
def test_real_adapter_argv_preserves_critical_finding_and_exact_recovery(tmp_path, monkeypatch, backend):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="short preview\n")
    monkeypatch.setattr("airecon.proxy.context_budget.subprocess.run", run)
    compressor = ArtifactCompressor(tmp_path, rtk="/test/rtk" if backend == "rtk" else "", caveman="/test/caveman" if backend == "caveman" else "")
    raw = "INFO noise\n" * 1000 + "[critical] CVE-2026-0001 https://example.test/api\n" + "INFO noise\n" * 1000
    preview, ref = compressor.preview(raw, 1200)
    assert compressor.last_backend == backend
    assert "[critical] CVE-2026-0001 https://example.test/api" in preview
    assert compressor.load(ref) == raw
    argv, kwargs = calls[0]
    assert argv[1:] == (["pipe"] if backend == "rtk" else ["compress"])
    assert kwargs["input"] == raw
    assert kwargs["env"]["DO_NOT_TRACK"] == "1"
    assert kwargs["timeout"] == 3
    assert "shell" not in kwargs


@pytest.mark.parametrize("failure", ["missing", "timeout", "empty", "failed", "larger"])
def test_external_failure_keeps_recoverable_builtin_preview(tmp_path, monkeypatch, failure):
    raw = "line of fixture output\n" * 500
    def run(*args, **kwargs):
        if failure == "missing":
            raise FileNotFoundError
        if failure == "timeout":
            raise subprocess.TimeoutExpired("fixture", 3)
        return SimpleNamespace(returncode=1 if failure == "failed" else 0, stdout=raw * 2 if failure == "larger" else "")
    monkeypatch.setattr("airecon.proxy.context_budget.subprocess.run", run)
    compressor = ArtifactCompressor(tmp_path, rtk="/test/missing", caveman="")
    preview, ref = compressor.preview(raw, 1000)
    assert len(preview.encode()) <= 1000
    assert compressor.load(ref) == raw
    assert compressor.last_backend == "builtin"


def test_repeated_compaction_uses_original_not_previous_lossy_preview(tmp_path):
    compressor = ArtifactCompressor(tmp_path, rtk="", caveman="")
    raw = "noise\n" * 1000 + "[high] exact finding\n" + "noise\n" * 1000
    first, ref = compressor.preview(raw, 2000)
    second, same = compressor.preview(first, 700, reference=ref, external=False)
    assert ref == same
    assert compressor.load(same) == raw
    assert "exact finding" in second
    assert len(second.encode()) <= 700


def test_storage_failure_leaves_original_history_unchanged(tmp_path, monkeypatch):
    compressor = ArtifactCompressor(tmp_path, rtk="", caveman="")
    def fail(*args):
        raise OSError("disk full")
    monkeypatch.setattr(compressor, "save", fail)
    messages = [{"role": "user", "content": "Do not access /payments."}, {"role": "assistant", "content": "noise " * 5000}]
    with pytest.raises(OSError, match="disk full"):
        pack_history(messages, [], 3000, compressor)
    assert messages[1]["content"] == "noise " * 5000


def test_recovery_rejects_traversal_and_corrupted_original(tmp_path):
    compressor = ArtifactCompressor(tmp_path, rtk="", caveman="")
    with pytest.raises(OSError):
        compressor.load("../../outside")
    ref = compressor.save("original")
    (tmp_path / ref).write_text("tampered")
    with pytest.raises(OSError, match="checksum"):
        compressor.load(ref)


def test_read_output_is_not_destructively_transformed(tmp_path):
    raw = "line with spaces  \n" * 1000
    messages = [
        {"role": "user", "content": "Read exactly"},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "read_1", "function": {"name": "read_file", "arguments": {}}}]},
        {"role": "tool", "tool_call_id": "read_1", "name": "read_file", "content": raw},
    ]
    compressor = ArtifactCompressor(tmp_path, rtk="", caveman="")
    with pytest.raises(ContextBudgetError):
        pack_history(messages, [], 2000, compressor)
    assert messages[-1]["content"] == raw


def test_asset_verification_rejects_changed_bytes():
    expected = hashlib.sha256(b"trusted").hexdigest()
    verify_asset(b"trusted", expected)
    with pytest.raises(ValueError, match="checksum"):
        verify_asset(b"modified", expected)


def test_archive_extracts_only_the_binary_without_writing_member_paths(tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        member = tarfile.TarInfo("../../rtk")
        member.size = 3
        tar.addfile(member, io.BytesIO(b"bin"))
    assert binary_from_asset("rtk", stream.getvalue(), True) == b"bin"
    assert list(tmp_path.iterdir()) == []


def test_session_reference_cannot_escape_through_symlink(tmp_path):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "output").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        ArtifactCompressor(root, rtk="", caveman="").save("secret fixture")
    assert not list(outside.iterdir())
