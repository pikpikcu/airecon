"""Host workspace paths must be remapped to the sandbox mount.

The Docker sandbox mounts the host workspace root at /workspace. Models
routinely emit the HOST absolute path instead, which does not exist inside the
container, so every `execute` failed with "Permission denied" (mkdir of
/home/<user>) or "No such file or directory" (cd into the host path).
"""
from __future__ import annotations

import pytest

from airecon.proxy.agent.executors_dispatch import _DispatchExecutorMixin as D


@pytest.fixture
def host_root(monkeypatch):
    root = "/home/testuser/Tools/airecon/workspace"
    monkeypatch.setattr(
        "airecon.proxy.agent.executors_dispatch.get_workspace_root",
        lambda: __import__("pathlib").Path(root),
    )
    return root


def test_host_absolute_path_is_remapped_to_sandbox_mount(host_root):
    cmd = f"mkdir -p {host_root}/example.com/recon && echo ok"
    assert D._rewrite_host_workspace_paths(cmd) == (
        "mkdir -p /workspace/example.com/recon && echo ok"
    )


def test_cd_into_host_path_is_remapped(host_root):
    cmd = f"cd {host_root}/example.com && subfinder -d example.com -silent"
    assert D._rewrite_host_workspace_paths(cmd) == (
        "cd /workspace/example.com && subfinder -d example.com -silent"
    )


def test_trailing_slash_host_root_is_remapped(host_root):
    assert D._rewrite_host_workspace_paths(
        f"ls {host_root}/"
    ) == "ls /workspace/"


def test_rewrite_is_idempotent(host_root):
    once = D._rewrite_host_workspace_paths(f"cd {host_root}/t && ls")
    assert D._rewrite_host_workspace_paths(once) == once


def test_commands_without_host_paths_are_untouched(host_root):
    for cmd in (
        "subfinder -d example.com -silent -o recon/subs.txt",
        "curl -s https://example.com/api",
        "cd /workspace/example.com && ls output",
    ):
        assert D._rewrite_host_workspace_paths(cmd) == cmd


def test_normalize_collapses_remapped_host_path_to_relative(host_root):
    # After remapping, /workspace/<target>/ is stripped because the sandbox
    # already cds into the target dir.
    out = D._normalize_workspace_paths(
        f"mkdir -p {host_root}/example.com/recon", "example.com"
    )
    assert "/home/testuser" not in out
    assert out == "mkdir -p recon"


def test_normalize_still_handles_plain_container_paths(host_root):
    assert D._normalize_workspace_paths(
        "mkdir -p /workspace/example.com/output", "example.com"
    ) == "mkdir -p output"


def test_normalize_does_not_break_urls(host_root):
    cmd = "curl -s https://crt.sh/?q=%25.example.com -o crtsh.json"
    assert D._normalize_workspace_paths(cmd, "example.com") == cmd


def test_other_users_root_is_untouched(host_root):
    cmd = "cd /home/someoneelse/Tools/airecon/workspace/t && ls"
    assert D._rewrite_host_workspace_paths(cmd) == cmd


def test_prefix_sibling_of_host_root_is_untouched(host_root):
    cmd = f"cp -r {host_root}-backup/old ."
    assert D._rewrite_host_workspace_paths(cmd) == cmd


def test_reported_literal_command_is_remapped(host_root):
    # The exact command shape from the incident report.
    assert D._rewrite_host_workspace_paths(
        f"cd {host_root}/ && ls -la"
    ) == "cd /workspace/ && ls -la"


# ---------------------------------------------------------------------------
# No-active-target dispatch must still remap host paths before the engine
# ---------------------------------------------------------------------------

from types import SimpleNamespace  # noqa: E402

import airecon.proxy.agent.executors_dispatch as ed  # noqa: E402


class _RecordingEngine:
    def __init__(self):
        self.calls = []

    async def execute_tool(self, tool_name, arguments, on_output=None):
        self.calls.append((tool_name, dict(arguments)))
        return {"success": True, "stdout": "", "stderr": "", "exit_code": 0}


class _AgentHarness(D):
    def __init__(self, engine, active_target=""):
        self.engine = engine
        self.state = SimpleNamespace(
            active_target=active_target,
            tool_history=[],
            tool_counts={"total": 0, "exec": 0},
            _stop_requested=False,
            add_dead_host=lambda h: False,
            add_failure=lambda **kw: "f1",
            get_failure_summary=lambda: {},
        )
        self._executed_tool_counts = {}
        self._last_output_file = None
        self._session = None

    def _save_tool_output(self, *a, **kw):
        return None

    def _is_recon_phase_repeat_blocked(self, *a, **kw):
        return False

    def _extract_command_binary(self, cmd=""):
        return (cmd or "").split()[0] if cmd else ""


def _patch_config(monkeypatch):
    monkeypatch.setattr(
        ed,
        "get_config",
        lambda: SimpleNamespace(agent_repeat_tool_call_limit=3),
        raising=True,
    )


@pytest.mark.asyncio
async def test_no_active_target_still_remaps_host_path(monkeypatch):
    """Regression: dispatch used to skip remap when active_target was empty,
    forwarding the HOST path verbatim into the container bash -c payload."""
    from pathlib import Path

    host_root = "/home/testuser/Tools/airecon/workspace"
    monkeypatch.setattr(
        ed, "get_workspace_root", lambda: Path(host_root), raising=True
    )
    _patch_config(monkeypatch)
    engine = _RecordingEngine()
    agent = _AgentHarness(engine, active_target="")

    ok, _dur, result, _f = await agent._execute_tool_and_record(
        "execute", {"command": f"cd {host_root}/ && ls -la"}
    )

    assert ok is True
    _tool, args = engine.calls[0]
    assert host_root not in args["command"], args["command"]
    assert args["command"] == "cd /workspace/ && ls -la"


@pytest.mark.asyncio
async def test_no_active_target_does_not_cd_prepend(monkeypatch):
    """No target: remap only — the /workspace/<target> cd-prepend stays
    target-dependent and must not fire with an empty target."""
    from pathlib import Path

    host_root = "/home/testuser/Tools/airecon/workspace"
    monkeypatch.setattr(
        ed, "get_workspace_root", lambda: Path(host_root), raising=True
    )
    _patch_config(monkeypatch)
    engine = _RecordingEngine()
    agent = _AgentHarness(engine, active_target="")

    await agent._execute_tool_and_record(
        "execute", {"command": f"echo hi > {host_root}/note.txt"}
    )

    _tool, args = engine.calls[0]
    assert args["command"] == "echo hi > /workspace/note.txt"
    assert not args["command"].startswith("cd /workspace/")


@pytest.mark.asyncio
async def test_dispatch_preserves_request_body_and_remaps_output_operand(monkeypatch):
    """Dispatch shares the engine's operand-only remap: a host path inside a
    JSON body or python -c source is data and must reach the engine verbatim."""
    from pathlib import Path

    host_root = "/home/testuser/Tools/airecon/workspace"
    monkeypatch.setattr(
        ed, "get_workspace_root", lambda: Path(host_root), raising=True
    )
    _patch_config(monkeypatch)
    cases = {
        f"cat {host_root}/req.json | curl -d '{{\"p\":\"{host_root}/x\"}}' -o {host_root}/out.json": (
            f"cat /workspace/req.json | curl -d '{{\"p\":\"{host_root}/x\"}}' -o /workspace/out.json"
        ),
        f"python3 -c 'print(\"{host_root}/x\")' > {host_root}/py.txt": (
            f"python3 -c 'print(\"{host_root}/x\")' > /workspace/py.txt"
        ),
    }
    for command, expected in cases.items():
        engine = _RecordingEngine()
        agent = _AgentHarness(engine, active_target="")
        await agent._execute_tool_and_record("execute", {"command": command})
        _tool, args = engine.calls[0]
        assert args["command"] == expected


# ---------------------------------------------------------------------------
# Active target: the relative-path cleanup touches filesystem operands only.
#
# With a target set, dispatch runs the command from /workspace/<target> and
# collapses operands that name that directory again. The payload also carries
# data that can spell the same text - request bodies, URLs, inline source,
# heredoc bodies - and those bytes must reach `docker exec` unchanged.
#
# Every case runs the production path _execute_tool_and_record -> DockerEngine
# with process spawning intercepted: no Docker, no shell, nothing executes.
# ---------------------------------------------------------------------------

import os  # noqa: E402
import subprocess  # noqa: E402
from unittest.mock import AsyncMock  # noqa: E402

import airecon.proxy.docker as docker_mod  # noqa: E402

TARGET = "example.test"
WS = f"/workspace/{TARGET}"


async def _active_target_payload(monkeypatch, tmp_path, command, target=TARGET):
    """The command dispatch hands to ``docker exec`` when a target is active."""
    monkeypatch.setattr(ed, "get_workspace_root", lambda: tmp_path, raising=True)
    monkeypatch.setattr(docker_mod, "get_workspace_root", lambda: tmp_path, raising=True)
    _patch_config(monkeypatch)
    spawn = AsyncMock(side_effect=OSError("spawn intercepted by test"))
    monkeypatch.setattr(docker_mod.asyncio, "create_subprocess_exec", spawn)
    other_spawns = []
    for owner, name in (
        (docker_mod.asyncio, "create_subprocess_shell"),
        (subprocess, "Popen"),
        (os, "system"),
    ):
        monkeypatch.setattr(
            owner, name, lambda *a, _name=name, **kw: other_spawns.append((_name, a))
        )
    engine = docker_mod.DockerEngine()
    engine._connected = True
    engine._container_name = "target-repair-mocked-container"
    agent = _AgentHarness(engine, active_target=target)

    ok, _dur, result, _f = await agent._execute_tool_and_record(
        "execute", {"command": command}
    )

    assert ok is False and result["success"] is False
    assert other_spawns == []
    spawn.assert_awaited_once()  # one process: a single docker exec
    argv = spawn.call_args.args
    assert argv[:2] == ("docker", "exec")
    assert argv[-4:-1] == ("bash", "--login", "-c")  # one payload, last argument
    prefix = f"cd /workspace/{target} && "
    assert argv[-1].startswith(prefix), argv[-1]
    sent = argv[-1][len(prefix):]
    assert D._normalize_workspace_paths(sent, target) == sent, "not idempotent"
    return sent


async def test_active_target_preserves_json_request_body(monkeypatch, tmp_path):
    body = f"'{{\"p\":\"{WS}/output/evidence.json\"}}'"
    sent = await _active_target_payload(
        monkeypatch,
        tmp_path,
        f"curl https://example.invalid --data-raw {body} -o {WS}/output/response.json",
    )
    assert sent == f"curl https://example.invalid --data-raw {body} -o output/response.json"


async def test_active_target_preserves_url_path(monkeypatch, tmp_path):
    for url in (
        f"'https://example.invalid{WS}/api'",
        f"https://example.invalid{WS}/api?next={WS}/x",
    ):
        sent = await _active_target_payload(
            monkeypatch, tmp_path, f"curl -s {url} -o {WS}/output/response.json"
        )
        assert sent == f"curl -s {url} -o output/response.json"


async def test_active_target_preserves_inline_source(monkeypatch, tmp_path):
    source = f"'import json; print(json.load(open(\"{WS}/output/evidence.json\")))'"
    sent = await _active_target_payload(
        monkeypatch, tmp_path, f"python3 -c {source} > {WS}/output/summary.txt"
    )
    assert sent == f"python3 -c {source} > output/summary.txt"

    inline_shell = f"bash -c 'ls {WS}/output | wc -l'"
    assert await _active_target_payload(monkeypatch, tmp_path, inline_shell) == inline_shell


async def test_active_target_preserves_heredoc_data(monkeypatch, tmp_path):
    body = (
        f"OUT = \"{WS}/output/result.json\"\n"
        f"BASE = \"https://{TARGET}/{TARGET}/api\"\n"
        f"print(open(\"{TARGET}/output/seed.txt\").read())\n"
    )
    sent = await _active_target_payload(
        monkeypatch,
        tmp_path,
        f"cat > {WS}/tools/probe.py <<'EOF'\n{body}EOF\npython3 {WS}/tools/probe.py",
    )
    assert sent == f"cat > tools/probe.py <<'EOF'\n{body}EOF\npython3 tools/probe.py"


async def test_active_target_preserves_double_and_bare_target_data(monkeypatch, tmp_path):
    cases = {
        # A URL path and a form value that repeat the target name are data.
        (
            f"mkdir -p {TARGET}/output && curl -s https://{TARGET}/{TARGET}/api "
            f"-d 'ref={TARGET}/{TARGET}/x' -o {TARGET}/output/api.json"
        ): (
            f"mkdir -p output && curl -s https://{TARGET}/{TARGET}/api "
            f"-d 'ref={TARGET}/{TARGET}/x' -o output/api.json"
        ),
        # A URL after a file command is not that command's operand.
        f"ls output && curl -s https://{TARGET}/api": f"ls output && curl -s https://{TARGET}/api",
        # Text and patterns are data; only the redirection target is a file.
        f"echo {TARGET}/login >> {TARGET}/output/urls.txt": (
            f"echo {TARGET}/login >> output/urls.txt"
        ),
        f"grep -o {TARGET}/admin output/urls.txt": f"grep -o {TARGET}/admin output/urls.txt",
    }
    for command, expected in cases.items():
        assert await _active_target_payload(monkeypatch, tmp_path, command) == expected


async def test_active_target_output_operands_normalize(monkeypatch, tmp_path):
    cases = {
        f"nmap -sV {TARGET} -oN {WS}/output/nmap.txt": f"nmap -sV {TARGET} -oN output/nmap.txt",
        f"subfinder -d {TARGET} -silent --output={WS}/output/subs.txt": (
            f"subfinder -d {TARGET} -silent --output=output/subs.txt"
        ),
        (
            f"httpx -l {TARGET}/output/subs.txt -o {TARGET}/output/live.txt "
            f"2>> {TARGET}/output/err.log | tee {WS}/{TARGET}/output/live.log"
        ): "httpx -l output/subs.txt -o output/live.txt 2>> output/err.log | tee output/live.log",
        # Host path -> container path -> relative to the target directory.
        f"mkdir -p {tmp_path}/{TARGET}/output/shots": "mkdir -p output/shots",
        f"cat \"{WS}/output/a b.txt\" > './{TARGET}/output/c d.txt'": (
            "cat \"output/a b.txt\" > 'output/c d.txt'"
        ),
        # The target directory itself stays absolute: an empty operand is not a path.
        f"cp output/a.txt {WS}/": f"cp output/a.txt {WS}/",
        f"ls -la {WS}": f"ls -la {WS}",
    }
    for command, expected in cases.items():
        assert await _active_target_payload(monkeypatch, tmp_path, command) == expected
