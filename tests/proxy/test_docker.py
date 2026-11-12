import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.docker import DockerEngine, rewrite_host_workspace_paths


@pytest.fixture
def docker_engine():
    engine = DockerEngine()
    return engine


@pytest.mark.asyncio
async def test_ensure_image_skip_if_exists(docker_engine, mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.wait = AsyncMock()

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    result = await docker_engine.ensure_image()
    assert result is True
    asyncio.create_subprocess_exec.assert_called_with(
        "docker",
        "image",
        "inspect",
        docker_engine.IMAGE_NAME,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )


@pytest.mark.asyncio
async def test_start_container_success(docker_engine, mocker):
    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    mocker.patch(
        "airecon.proxy.docker.get_workspace_root", return_value="/tmp/test_workspace"
    )

    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    result = await docker_engine.start_container()

    assert result is True
    assert docker_engine.is_connected is True
    assert docker_engine._container_id == "abcdef123456"


@pytest.mark.asyncio
async def test_execute_success(docker_engine, mocker):
    docker_engine._connected = True
    docker_engine._container_name = "test-container"

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.wait = AsyncMock()

    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(side_effect=[b"Command output test\n", b""])
    mock_stderr = AsyncMock()
    mock_stderr.read = AsyncMock(return_value=b"")

    mock_proc.stdout = mock_stdout
    mock_proc.stderr = mock_stderr

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    result = await docker_engine.execute("echo 'test'")

    assert result["success"] is True
    assert "Command output test\n" in result["stdout"]
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_execute_timeout(docker_engine, mocker):
    docker_engine._connected = True
    docker_engine._container_name = "test-container"

    mock_proc = AsyncMock()
    mock_proc.returncode = None
    mock_proc.wait = AsyncMock(side_effect=asyncio.TimeoutError())

    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_stderr = AsyncMock()
    mock_stderr.read = AsyncMock(side_effect=asyncio.TimeoutError())

    mock_proc.stdout = mock_stdout
    mock_proc.stderr = mock_stderr
    mock_proc.kill = MagicMock()

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)

    result = await docker_engine.execute("sleep 100", timeout=0.1)

    assert result["success"] is False
    assert result["exit_code"] == -1
    assert "timed out" in result["error"]
    mock_proc.kill.assert_called_once()


def _make_exec_mock(
    mocker, docker_engine, returncode: int, stdout: bytes, stderr: bytes = b""
):
    docker_engine._connected = True
    docker_engine._container_name = "test-container"

    mock_proc = AsyncMock()
    mock_proc.returncode = returncode
    mock_proc.wait = AsyncMock()

    mock_stdout = AsyncMock()
    mock_stdout.read = AsyncMock(side_effect=[stdout, b""])
    mock_stderr = AsyncMock()
    mock_stderr.read = AsyncMock(side_effect=[stderr, b""])

    mock_proc.stdout = mock_stdout
    mock_proc.stderr = mock_stderr

    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    return mock_proc


@pytest.mark.asyncio
async def test_execute_exit1_with_stdout_is_partial_success(docker_engine, mocker):
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=1,
        stdout=b"Location: https://example.com/author/foo/\r\n",
    )
    result = await docker_engine.execute(
        "for i in 1 2 3; do curl -sk -I https://example.com/?p=$i | grep -i location; done"
    )

    assert result["success"] is True
    assert result["exit_code"] == 1
    assert "Location" in result["stdout"]


@pytest.mark.asyncio
async def test_execute_exit1_empty_stdout_is_failure(docker_engine, mocker):
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=1,
        stdout=b"",
        stderr=b"grep: invalid option",
    )
    result = await docker_engine.execute("grep --bad-flag foo")

    assert result["success"] is False
    assert result["exit_code"] == 1


@pytest.mark.asyncio
async def test_execute_exit2_with_stdout_is_failure(docker_engine, mocker):
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=2,
        stdout=b"some partial output",
        stderr=b"command error",
    )
    result = await docker_engine.execute("somecommand --bad")

    assert result["success"] is False
    assert result["exit_code"] == 2


@pytest.mark.asyncio
async def test_execute_exit0_no_stdout_is_success(docker_engine, mocker):
    _make_exec_mock(
        mocker,
        docker_engine,
        returncode=0,
        stdout=b"",
    )
    result = await docker_engine.execute("touch /tmp/test")

    assert result["success"] is True
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_start_container_tracks_background_task(docker_engine, mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value="/tmp/test")
    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    await docker_engine.start_container()

    assert len(docker_engine._background_tasks) == 1
    task = list(docker_engine._background_tasks)[0]
    assert isinstance(task, asyncio.Task)


@pytest.mark.asyncio
async def test_stop_container_cancels_background_tasks(docker_engine, mocker):
    """CRITICAL: stop_container must cancel and await background tasks to prevent leaks."""
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))
    mock_proc.wait = AsyncMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value="/tmp/test")
    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    await docker_engine.start_container()
    assert len(docker_engine._background_tasks) == 1

    await docker_engine.stop_container()

    assert len(docker_engine._background_tasks) == 0
    assert docker_engine._connected is False


@pytest.mark.asyncio
async def test_force_stop_with_straggler_processes(docker_engine, mocker):
    docker_engine._container_name = "test-container"
    docker_engine._connected = True

    mock_proc1 = AsyncMock()
    mock_proc1.returncode = None
    mock_proc1.kill = MagicMock(side_effect=ProcessLookupError("Process not found"))
    mock_proc1.wait = AsyncMock()

    mock_proc2 = AsyncMock()
    mock_proc2.returncode = 0
    mock_proc2.kill = MagicMock()
    mock_proc2.wait = AsyncMock()

    docker_engine._active_procs = {mock_proc1, mock_proc2}

    mock_pkill_proc = AsyncMock()
    mock_pkill_proc.wait = AsyncMock()

    call_count = [0]

    def create_proc(*args, **kwargs):
        call_count[0] += 1
        return mock_pkill_proc

    mocker.patch("asyncio.create_subprocess_exec", side_effect=create_proc)

    await docker_engine.force_stop()

    assert len(docker_engine._active_procs) == 0


HOST_ROOT = "/home/testuser/Tools/airecon/workspace"
REPORTED_CMD = f"cd {HOST_ROOT}/ && ls -la"


@pytest.fixture
def host_root(mocker):
    from pathlib import Path

    mocker.patch(
        "airecon.proxy.docker.get_workspace_root",
        return_value=Path(HOST_ROOT),
    )
    return HOST_ROOT


def _spawn_recorder(mocker, sink, *, fail=False):
    """Record every spawned argv; never run anything on the host."""

    async def fake_exec(*argv, **kwargs):
        sink.append(list(argv))
        if fail:
            raise OSError("simulated spawn failure")
        proc = MagicMock()
        proc.returncode = 0
        proc.pid = 4242

        async def _read(n=-1):
            return b""

        async def _wait():
            return 0

        proc.stdout = SimpleStream(_read)
        proc.stderr = SimpleStream(_read)
        proc.wait = _wait
        proc.kill = lambda: None
        return proc

    mocker.patch("asyncio.create_subprocess_exec", side_effect=fake_exec)


class SimpleStream:
    def __init__(self, read):
        self._read = read

    async def read(self, n=-1):
        return await self._read(n)


def _connected(engine):
    engine._connected = True
    engine._container_name = "airecon-sandbox-active"


def test_boundary_helper_remaps_reported_literal_command(host_root):
    assert rewrite_host_workspace_paths(REPORTED_CMD) == "cd /workspace/ && ls -la"


def test_boundary_helper_other_root_untouched(host_root):
    cmd = "cd /home/otheruser/Tools/airecon/workspace/ && ls"
    assert rewrite_host_workspace_paths(cmd) == cmd


def test_boundary_helper_prefix_sibling_untouched(host_root):
    cmd = f"ls {HOST_ROOT}-backup/old"
    assert rewrite_host_workspace_paths(cmd) == cmd


def test_boundary_helper_idempotent(host_root):
    once = rewrite_host_workspace_paths(REPORTED_CMD)
    assert rewrite_host_workspace_paths(once) == once == "cd /workspace/ && ls -la"


def test_boundary_helper_preserves_urls_and_tokens(host_root):
    data = (
        f"curl -s 'https://api.example.com{HOST_ROOT}/jobs?a=/x' "
        f"-d '{{\"p\":\"{HOST_ROOT}/tok\"}}' -o "
    )
    assert rewrite_host_workspace_paths(f"{data}{HOST_ROOT}/out.json") == (
        f"{data}/workspace/out.json"
    )


@pytest.mark.asyncio
async def test_engine_execute_remaps_reported_host_path(mocker, host_root):
    """DockerEngine.execute must remap the host path before building argv."""
    sink = []
    _spawn_recorder(mocker, sink)
    engine = DockerEngine()
    _connected(engine)

    result = await engine.execute(REPORTED_CMD)

    assert result["success"] is True
    argv = sink[0]
    assert argv[0] == "docker" and argv[1] == "exec"
    assert argv[-4:-2] == ["bash", "--login"]
    assert argv[-2] == "-c"
    assert argv[-1] == "cd /workspace/ && ls -la"
    assert HOST_ROOT not in argv[-1]


@pytest.mark.asyncio
async def test_engine_execute_tool_gets_identical_remap(mocker, host_root):
    sink = []
    _spawn_recorder(mocker, sink)
    engine = DockerEngine()
    _connected(engine)
    mocker.patch.object(
        engine, "cfg", MagicMock(command_timeout=30)
    )

    result = await engine.execute_tool("execute", {"command": REPORTED_CMD})

    assert result["success"] is True
    assert sink[0][-1] == "cd /workspace/ && ls -la"


@pytest.mark.asyncio
async def test_engine_execute_tool_no_target_dependency(mocker, host_root):
    """Remap must not depend on any active target state on the engine."""
    sink = []
    _spawn_recorder(mocker, sink)
    engine = DockerEngine()
    _connected(engine)
    mocker.patch.object(engine, "cfg", MagicMock(command_timeout=30))
    result = await engine.execute_tool(
        "execute", {"command": f"ls {HOST_ROOT}/example.com/output"}
    )
    assert result["success"] is True
    assert sink[0][-1] == "ls /workspace/example.com/output"


@pytest.mark.asyncio
async def test_disconnected_engine_errors_without_spawn(mocker, host_root):
    sink = []
    _spawn_recorder(mocker, sink)
    engine = DockerEngine()
    engine._connected = False
    engine._container_name = None

    result = await engine.execute(REPORTED_CMD)

    assert result["success"] is False
    assert "not running" in result["error"]
    assert sink == [], "no host fallback spawn when disconnected"


@pytest.mark.asyncio
async def test_spawn_failure_returns_error_never_host_shell(mocker, host_root):
    sink = []
    _spawn_recorder(mocker, sink, fail=True)
    engine = DockerEngine()
    _connected(engine)

    result = await engine.execute(REPORTED_CMD)

    assert result["success"] is False
    assert sink and all(a[0] == "docker" for a in sink), "only docker argv attempts"


@pytest.mark.asyncio
async def test_tool_stderr_does_not_recover_a_running_container(docker_engine, mocker):
    docker_engine._container_name = "airecon-sandbox-active"
    mocker.patch("shutil.which", return_value="/usr/bin/docker")
    proc = AsyncMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"true\n", b""))
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    assert await docker_engine._should_recover_container("curl: (56) connection reset by peer") is False


@pytest.mark.asyncio
async def test_stopped_container_still_recovers_on_docker_eof(docker_engine, mocker):
    docker_engine._container_name = "airecon-sandbox-active"
    mocker.patch("shutil.which", return_value="/usr/bin/docker")
    proc = AsyncMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"false\n", b""))
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    assert await docker_engine._should_recover_container("unexpected EOF") is True


@pytest.mark.asyncio
@pytest.mark.parametrize("status,stdout,stderr,expected", [
    (1, b"", b"cannot connect to the Docker daemon", False),
    (0, b"unrecognized", b"", False),
    (1, b"", b"Error: No such object: airecon-sandbox-active", True),
])
async def test_recovery_requires_confirmed_container_loss(docker_engine, mocker, status, stdout, stderr, expected):
    docker_engine._container_name = "airecon-sandbox-active"
    mocker.patch("shutil.which", return_value="/usr/bin/docker")
    proc = AsyncMock()
    proc.returncode = status
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    assert await docker_engine._should_recover_container("broken pipe") is expected
