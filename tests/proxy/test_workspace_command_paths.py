"""Host→/workspace remapping touches filesystem operands only.

The sandbox mounts the host workspace at /workspace, so a host path used as a
file operand is remapped at the DockerEngine.execute boundary. A bash payload
also carries data — URLs, request bodies, inline source, patterns, comments,
heredoc bodies — and those bytes must reach the container unchanged even when
they contain the host workspace root.

Every case runs the production path execute_tool → execute with the
subprocess spawn intercepted: no Docker, no shell, nothing executes.
"""
from __future__ import annotations

import shlex
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from airecon.proxy.agent.executors_observe import _ObserveExecutorMixin
from airecon.proxy.agent.models import AgentState
from airecon.proxy.docker import DockerEngine, rewrite_host_workspace_paths

ROOT = "/home/testuser/Tools/airecon/workspace"


@pytest.fixture
def engine(mocker):
    mocker.patch("airecon.proxy.docker.get_workspace_root", return_value=Path(ROOT))
    engine = DockerEngine()
    engine._connected = True
    engine._container_name = "path-repair-mocked-container"
    return engine


async def _sent(engine, mocker, command: str) -> str:
    """The bash payload execute_tool hands to ``docker exec`` (spawn intercepted)."""
    spawn = AsyncMock(side_effect=OSError("spawn intercepted by test"))
    mocker.patch("airecon.proxy.docker.asyncio.create_subprocess_exec", spawn)
    result = await engine.execute_tool("execute", {"command": command})
    assert result["success"] is False
    spawn.assert_awaited_once()
    argv = spawn.call_args.args
    assert argv[:2] == ("docker", "exec")
    assert argv[-4:-1] == ("bash", "--login", "-c")
    payload = argv[-1]
    assert rewrite_host_workspace_paths(command) == payload, "helper and engine disagree"
    assert rewrite_host_workspace_paths(payload) == payload, "not idempotent"
    return payload


# --- opaque data: bytes must be preserved -----------------------------------


async def test_url_containing_host_root_is_preserved(engine, mocker):
    for cmd in (
        f"curl 'https://example.test{ROOT}/x'",
        f"curl -s https://example.test{ROOT}/x",
        f"curl -s 'https://example.test/download?file={ROOT}/x'",
    ):
        assert await _sent(engine, mocker, cmd) == cmd


async def test_json_body_preserved_while_output_operand_remaps(engine, mocker):
    body = f"'{{\"p\":\"{ROOT}/x\"}}'"
    cmd = f"curl https://example.test -d {body} -o {ROOT}/out.json"
    assert await _sent(engine, mocker, cmd) == (
        f"curl https://example.test -d {body} -o /workspace/out.json"
    )
    # Same body in double quotes with escapes, a URL fragment, a continuation.
    escaped = f'"{{\\"p\\":\\"{ROOT}/x\\"}}"'
    cmd = f"curl https://example.test/#{ROOT} -d {escaped} \\\n  -o {ROOT}/out.json"
    assert await _sent(engine, mocker, cmd) == (
        f"curl https://example.test/#{ROOT} -d {escaped} \\\n  -o /workspace/out.json"
    )


async def test_bare_path_request_body_is_preserved(engine, mocker):
    # The body is a whole unquoted word that IS a host path: still data.
    cmd = f"curl -X POST --data-raw {ROOT}/x -H 'X-File: {ROOT}/x' https://example.test"
    assert await _sent(engine, mocker, cmd) == cmd


async def test_python_c_source_is_preserved(engine, mocker):
    for cmd in (
        f"python -c 'print(\"{ROOT}/x\")'",
        f"python3 -c \"open('{ROOT}/x').read()\" {ROOT}/argv-data",
        f"bash -c 'cd {ROOT}/t && ls'",
    ):
        assert await _sent(engine, mocker, cmd) == cmd


async def test_unrelated_absolute_prefix_is_preserved(engine, mocker):
    for cmd in (
        f"cat /archive{ROOT}/x",
        f"ls {ROOT}-backup/old",
        f"cat {ROOT}.json",
        f"cd /mnt{ROOT} && ls",
    ):
        assert await _sent(engine, mocker, cmd) == cmd


async def test_data_words_of_text_commands_are_preserved(engine, mocker):
    for cmd in (
        f"echo {ROOT}/x",
        f"echo \"{ROOT}/x\"",
        f"printf '%s\\n' {ROOT}/x",
        f"grep -o {ROOT}/x scan.log",
        f"sed -e s#{ROOT}/x#y# notes.txt",
        f"find . -path '{ROOT}/*' -exec grep {ROOT}/x {{}} \\;",
        f"OUT={ROOT}/x",
        f"cat <<< {ROOT}/x",
    ):
        assert await _sent(engine, mocker, cmd) == cmd


async def test_shell_comment_is_preserved(engine, mocker):
    cmd = f"# notes live in {ROOT}/t\nls {ROOT}/t # was {ROOT}/t\necho done"
    assert await _sent(engine, mocker, cmd) == (
        f"# notes live in {ROOT}/t\nls /workspace/t # was {ROOT}/t\necho done"
    )


async def test_heredoc_body_is_preserved(engine, mocker):
    body = f"cd {ROOT}/t\ncat {ROOT}/t/a > {ROOT}/t/b\n"
    for opener, closer in (("<<'EOF'", "EOF"), ("<<EOF", "EOF"), ("<<-\"END\"", "\tEND")):
        cmd = f"cat {opener} > {ROOT}/t/run.sh\n{body}{closer}\ncat {ROOT}/t/run.sh"
        assert await _sent(engine, mocker, cmd) == (
            f"cat {opener} > /workspace/t/run.sh\n{body}{closer}\ncat /workspace/t/run.sh"
        )


async def test_unterminated_heredoc_and_quote_leave_the_rest_unchanged(engine, mocker):
    heredoc = f"cat <<EOF\ncat {ROOT}/t/a\n"
    assert await _sent(engine, mocker, heredoc) == heredoc
    quote = f"ls {ROOT}/t; echo 'cat {ROOT}/t/a"
    assert await _sent(engine, mocker, quote) == f"ls /workspace/t; echo 'cat {ROOT}/t/a"


async def test_unmodelled_substitution_leaves_the_tail_unchanged(engine, mocker):
    for tail in (
        f"echo $(cat {ROOT}/t/b) > {ROOT}/t/c",
        f"echo `cat {ROOT}/t/b` > {ROOT}/t/c",
        f"diff <(sort {ROOT}/t/b) {ROOT}/t/c",
        f"echo \"${{X:-\"cat {ROOT}/t/b\"}}\" > {ROOT}/t/c",
    ):
        assert await _sent(engine, mocker, f"cat {ROOT}/t/a && {tail}") == (
            f"cat /workspace/t/a && {tail}"
        )


async def test_unmodelled_compound_syntax_is_preserved(engine, mocker):
    # Words that open these constructs are not commands; nothing after is touched.
    for cmd in (
        f"paths=({ROOT}/a {ROOT}/b); cat {ROOT}/a",
        f"case $P in ({ROOT}/a) cat {ROOT}/a;; esac",
        f"[[ $P > {ROOT}/a || {ROOT}/b == $P ]] && cat {ROOT}/a",
    ):
        assert await _sent(engine, mocker, cmd) == cmd


async def test_ansi_c_quoted_data_does_not_derail_later_operands(engine, mocker):
    cmd = f"curl -d $'don\\'t cat {ROOT}/x' https://example.test -o {ROOT}/out.json"
    assert await _sent(engine, mocker, cmd) == (
        f"curl -d $'don\\'t cat {ROOT}/x' https://example.test -o /workspace/out.json"
    )


# --- recognized filesystem operands: remapped -------------------------------


async def test_cd_operand_remaps(engine, mocker):
    assert await _sent(engine, mocker, f"cd {ROOT}/ && ls -la") == "cd /workspace/ && ls -la"
    assert await _sent(engine, mocker, f"cd {ROOT}") == "cd /workspace"
    assert await _sent(engine, mocker, f"(cd {ROOT}/t; ls)|wc -l") == "(cd /workspace/t; ls)|wc -l"


async def test_output_operands_remap(engine, mocker):
    cases = {
        f"echo hi > {ROOT}/note.txt": "echo hi > /workspace/note.txt",
        f"nmap -sV example.test -oN {ROOT}/t/nmap.txt 2>>{ROOT}/t/err.log": (
            "nmap -sV example.test -oN /workspace/t/nmap.txt 2>>/workspace/t/err.log"
        ),
        f"subfinder -d example.test --output={ROOT}/t/subs.txt &> {ROOT}/t/log": (
            "subfinder -d example.test --output=/workspace/t/subs.txt &> /workspace/t/log"
        ),
        f"ls {ROOT}/t | tee {ROOT}/t/listing.txt": (
            "ls /workspace/t | tee /workspace/t/listing.txt"
        ),
        f"sort < {ROOT}/t/in.txt": "sort < /workspace/t/in.txt",
        f"nuclei -l {ROOT}/t/live.txt -o {ROOT}/t/n.txt 2>&1 | tee -a {ROOT}/t/n.log": (
            "nuclei -l /workspace/t/live.txt -o /workspace/t/n.txt 2>&1 | tee -a /workspace/t/n.log"
        ),
        # The string comparison is data; the file operand after ``then`` is not.
        f"if [ \"$P\" = {ROOT}/x ]; then cat {ROOT}/x; fi": (
            f"if [ \"$P\" = {ROOT}/x ]; then cat /workspace/x; fi"
        ),
    }
    for cmd, expected in cases.items():
        assert await _sent(engine, mocker, cmd) == expected


async def test_quoted_operands_remap_inside_their_quotes(engine, mocker):
    cases = {
        f"cd \"{ROOT}/my target\" && ls": "cd \"/workspace/my target\" && ls",
        f"cat '{ROOT}/a b.txt'": "cat '/workspace/a b.txt'",
        f"mkdir -p \"{ROOT}\"/t/{{output,tools}}": "mkdir -p \"/workspace\"/t/{output,tools}",
        f"curl -s https://example.test -o \"{ROOT}/$T/out.json\"": (
            "curl -s https://example.test -o \"/workspace/$T/out.json\""
        ),
    }
    for cmd, expected in cases.items():
        assert await _sent(engine, mocker, cmd) == expected


async def test_escaped_operand_remaps_and_keeps_its_escapes(engine, mocker):
    assert await _sent(engine, mocker, f"cat {ROOT}/my\\ dir/a\\ b.txt") == (
        "cat /workspace/my\\ dir/a\\ b.txt"
    )
    # A quote that opens inside the root cannot be replaced without unbalancing it.
    split = ROOT[:-9] + "'workspace'/x"
    assert await _sent(engine, mocker, f"cat {split}") == f"cat {split}"


async def test_scripts_and_find_start_paths_remap_but_their_arguments_do_not(engine, mocker):
    cases = {
        f"python3 {ROOT}/t/tools/x.py {ROOT}/argv-data": (
            f"python3 /workspace/t/tools/x.py {ROOT}/argv-data"
        ),
        f"chmod +x {ROOT}/t/run.sh && {ROOT}/t/run.sh": (
            "chmod +x /workspace/t/run.sh && /workspace/t/run.sh"
        ),
        f"find {ROOT}/t -name '*.txt' -newer {ROOT}/t/mark": (
            f"find /workspace/t -name '*.txt' -newer {ROOT}/t/mark"
        ),
    }
    for cmd, expected in cases.items():
        assert await _sent(engine, mocker, cmd) == expected


# --- http_observe: the production caller that quotes URL/body/headers -------


class _ObserveAgent(_ObserveExecutorMixin):
    def __init__(self, engine):
        self.state = AgentState()
        self.state.active_target = "example.test"
        self._session = None
        self._last_output_file = None
        self.engine = engine

    def _str_arg(self, arguments, key):
        value = arguments.get(key)
        return str(value).strip() if value is not None else ""


@pytest.mark.parametrize(
    "body", [f'{{"p":"{ROOT}/x"}}', f"{ROOT}/x"], ids=["json-body", "bare-path-body"]
)
async def test_http_observe_url_body_and_headers_reach_docker_unchanged(engine, mocker, body):
    spawn = AsyncMock(side_effect=OSError("spawn intercepted by test"))
    mocker.patch("airecon.proxy.docker.asyncio.create_subprocess_exec", spawn)
    url = f"https://example.test{ROOT}/x?next={ROOT}/y"
    header = f"{ROOT}/x"

    ok, _duration, result, _file = await _ObserveAgent(engine)._execute_http_observe_tool(
        "http_observe",
        {"url": url, "method": "POST", "body": body, "headers": {"X-File": header}, "timeout": 10},
    )

    assert ok is False and result["success"] is False
    spawn.assert_awaited_once()
    argv = spawn.call_args.args
    assert argv[:2] == ("docker", "exec")
    curl = shlex.split(argv[-1])
    assert curl[0] == "curl"
    assert curl[-1] == url
    assert curl[curl.index("--data-raw") + 1] == body
    assert curl[curl.index("-H") + 1] == f"X-File: {header}"
    assert "/workspace" not in argv[-1].replace(ROOT, "")
