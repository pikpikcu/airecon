import asyncio
import sys

import pytest

from airecon.proxy import mcp


@pytest.mark.asyncio
async def test_stdio_server_is_reaped_after_success(monkeypatch):
    created = []
    spawn = asyncio.create_subprocess_exec

    async def capture(*args, **kwargs):
        proc = await spawn(*args, **kwargs)
        created.append(proc)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    source = (
        "import json,sys,time\n"
        "for line in sys.stdin:\n"
        " request=json.loads(line)\n"
        " if 'id' in request:\n"
        "  result={'tools': []} if request['method']=='tools/list' else {}\n"
        "  print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}), flush=True)\n"
        "  if request['method']=='tools/list':\n"
        "   time.sleep(60)\n"
    )
    try:
        ok, result = await mcp._mcp_stdio_request(
            {"command": sys.executable, "args": ["-u", "-c", source]},
            "tools/list",
            {},
        )
        assert ok and result == {"tools": []}
        assert created[0].returncode is not None
    finally:
        for proc in created:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()


@pytest.mark.asyncio
async def test_stdio_server_is_reaped_when_cancelled_during_cleanup(monkeypatch):
    created = []
    waiting = asyncio.Event()
    spawn = asyncio.create_subprocess_exec

    async def capture(*args, **kwargs):
        proc = await spawn(*args, **kwargs)
        created.append(proc)
        original_wait = proc.wait

        async def wait():
            waiting.set()
            return await original_wait()

        proc.wait = wait
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    source = (
        "import json,sys,time\n"
        "for line in sys.stdin:\n"
        " request=json.loads(line)\n"
        " if 'id' in request:\n"
        "  print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{}}), flush=True)\n"
        "  if request['method']=='tools/list': time.sleep(60)\n"
    )
    request = asyncio.create_task(mcp._mcp_stdio_request(
        {"command": sys.executable, "args": ["-u", "-c", source]}, "tools/list", {},
    ))
    try:
        await asyncio.wait_for(waiting.wait(), timeout=5)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert created[0].returncode is not None
    finally:
        if not request.done():
            request.cancel()
            await asyncio.gather(request, return_exceptions=True)
        for proc in created:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()
