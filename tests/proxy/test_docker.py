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
    # create_subprocess_exec should be called with "docker image inspect"
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

    # Mocking get_workspace_root to prevent folder creation during test
    mocker.patch(
        "airecon.proxy.docker.get_workspace_root", return_value="/tmp/test_workspace"
    )

    # Needs to bypass the `apt update` background task waiting around
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

    # Stream readers need mock data yielding
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
    # returncode=None means the process is still running — required so the
    # TimeoutError handler's `if proc.returncode is None: proc.kill()` branch fires.
    mock_proc.returncode = None
    # Making the process block forever until timeout
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


# ---------------------------------------------------------------------------
# exit_code=1 partial-success tests (grep/find pipeline false-negative fix)
# ---------------------------------------------------------------------------


def _make_exec_mock(
    mocker, docker_engine, returncode: int, stdout: bytes, stderr: bytes = b""
):
    """Helper: set up docker_engine.execute() with given returncode + output."""
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
    """exit_code=1 + non-empty stdout → success=True (bash pipeline grep case)."""
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
    """exit_code=1 + empty stdout → success=False (real error)."""
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
    """exit_code=2 (real error) → success=False even if stdout has content."""
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
    """exit_code=0 + empty stdout → success=True (normal zero-exit)."""
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
    """CRITICAL: Background apt-get update task should be tracked for cleanup."""
    mocker.patch("shutil.which", return_value="/usr/bin/docker")

    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"abcdef1234567890\n", b""))
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value="/tmp/test")
    mocker.patch.object(docker_engine, "execute", new_callable=AsyncMock)

    await docker_engine.start_container()

    # Background task should be tracked
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

    # Background tasks should be cleared after stop
    assert len(docker_engine._background_tasks) == 0
    assert docker_engine._connected is False


@pytest.mark.asyncio
async def test_force_stop_with_straggler_processes(docker_engine, mocker):
    """CRITICAL: force_stop must handle straggler processes gracefully."""
    docker_engine._container_name = "test-container"
    docker_engine._connected = True

    # Mock active processes
    mock_proc1 = AsyncMock()
    mock_proc1.returncode = None
    mock_proc1.kill = MagicMock(side_effect=ProcessLookupError("Process not found"))
    mock_proc1.wait = AsyncMock()

    mock_proc2 = AsyncMock()
    mock_proc2.returncode = 0
    mock_proc2.kill = MagicMock()
    mock_proc2.wait = AsyncMock()

    docker_engine._active_procs = {mock_proc1, mock_proc2}

    # Mock docker exec command for pkill
    mock_pkill_proc = AsyncMock()
    mock_pkill_proc.wait = AsyncMock()

    call_count = [0]

    def create_proc(*args, **kwargs):
        call_count[0] += 1
        # First call is pkill, second is docker rm (not used here)
        return mock_pkill_proc

    mocker.patch("asyncio.create_subprocess_exec", side_effect=create_proc)

    # force_stop should not raise even with straggler processes
    await docker_engine.force_stop()

    # All processes should be cleared
    assert len(docker_engine._active_procs) == 0
    # Note: force_stop doesn't set _connected=False, only stop_container does


# ---------------------------------------------------------------------------
# Host workspace path normalization at the Docker execution boundary
# ---------------------------------------------------------------------------

HOST_ROOT = "/home/testuser/Tools/airecon/workspace"
REPORTED_CMD = f"cd {HOST_ROOT}/ && ls -la"  # synthetic reproduction of the reported command shape


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
    # URL and body carry the host root as data; only the -o operand is a path.
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
    # single bash payload, remapped to the container mount
    assert argv[-4:-2] == ["bash", "--login"]
    assert argv[-2] == "-c"
    assert argv[-1] == "cd /workspace/ && ls -la"
    assert HOST_ROOT not in argv[-1]


@pytest.mark.asyncio
async def test_engine_execute_tool_gets_identical_remap(mocker, host_root):
    """execute_tool (the /shell + observer ingress) normalizes identically."""
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
    # no target concept exists on the engine; command with target subdir still remaps
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
