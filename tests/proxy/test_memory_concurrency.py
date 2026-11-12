import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from airecon.proxy import memory


@pytest.fixture
def managers(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(memory, "MEMORY_DB", tmp_path / "memory.db")
    monkeypatch.setattr(memory, "_MEMORY_CONN", None, raising=False)
    opened = []

    def create():
        manager = memory.MemoryManager()
        manager.connect()
        opened.append(manager)
        return manager

    yield create
    for manager in opened:
        manager.close()


def pattern():
    return {
        "technique_name": "fixture_pattern", "description": "Local fixture",
        "times_used": 2, "success_rate": 1.0,
    }


def test_closing_one_manager_does_not_invalidate_another(managers):
    first, second = managers(), managers()
    first.close()
    second.save_pattern(pattern())
    assert second.get_patterns()[0]["times_used"] == 2


def test_repeated_connect_retains_owned_connection(managers):
    manager = managers()
    connection = manager.conn
    manager.connect()
    assert manager.conn is connection


def test_concurrent_pattern_updates_do_not_lose_usage(managers):
    first, second = managers(), managers()
    first.save_pattern(pattern())
    read_started = threading.Event()
    resume = threading.Event()
    second_done = threading.Event()
    original = first.conn

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor
            self.pause = False

        def execute(self, sql, *args):
            self.pause = "SELECT id, times_used, times_successful FROM patterns" in sql
            return self.cursor.execute(sql, *args)

        def fetchone(self):
            row = self.cursor.fetchone()
            if self.pause:
                read_started.set()
                assert resume.wait(5)
            return row

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class Connection:
        def cursor(self):
            return Cursor(original.cursor())

        def __enter__(self):
            return original.__enter__()

        def __exit__(self, *args):
            return original.__exit__(*args)

        def __getattr__(self, name):
            return getattr(original, name)

    first.conn = Connection()

    def update_second():
        try:
            second.save_pattern(pattern())
        finally:
            second_done.set()

    with ThreadPoolExecutor(max_workers=2) as workers:
        one = workers.submit(first.save_pattern, pattern())
        try:
            assert read_started.wait(5)
            two = workers.submit(update_second)
            second_done.wait(0.1)
        finally:
            resume.set()
        one.result(timeout=5)
        two.result(timeout=5)
    assert second.get_patterns()[0]["times_used"] == 6


def test_failed_batch_is_rolled_back_before_the_next_operation(managers):
    manager = managers()
    with pytest.raises((TypeError, ValueError)):
        manager.bump_utility("fixture", [1, object()])
    assert manager.get_utility("fixture") == {}
    manager.bump_utility("fixture", [2])
    assert set(manager.get_utility("fixture")) == {2}


def test_parallel_utility_writes_persist_all_updates(managers):
    manager = managers()
    with ThreadPoolExecutor(max_workers=8) as workers:
        futures = [workers.submit(manager.bump_utility, "fixture", [1]) for _ in range(128)]
        for future in futures:
            future.result(timeout=10)
    assert manager.get_utility("fixture")[1]["recalls"] == 128


def test_singleton_retries_after_a_failed_connection(managers, monkeypatch):
    monkeypatch.setattr(memory, "_memory_manager", None)
    original = memory.get_memory_db
    attempts = 0

    def connect():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("fixture initialization failure")
        return original()

    monkeypatch.setattr(memory, "get_memory_db", connect)
    try:
        with pytest.raises(OSError):
            memory.get_memory_manager()
        manager = memory.get_memory_manager()
        assert manager.conn is not None
        assert attempts == 2
    finally:
        if memory._memory_manager is not None:
            memory._memory_manager.close()


def test_connection_factory_closes_on_schema_failure(managers, monkeypatch):
    import sqlite3

    original = sqlite3.connect
    connections = []

    def connect(*args, **kwargs):
        conn = original(*args, **kwargs)
        connections.append(conn)
        return conn

    def fail(conn):
        raise RuntimeError("fixture schema failure")

    monkeypatch.setattr(memory.sqlite3, "connect", connect)
    monkeypatch.setattr(memory, "_init_schema", fail)
    with pytest.raises(RuntimeError, match="schema failure"):
        memory.get_memory_db()
    try:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
    finally:
        connections[0].close()


def test_busy_writer_does_not_block_reads_on_another_manager(managers):
    import sqlite3

    writer, reader = managers(), managers()
    original = writer.conn
    entered = threading.Event()

    class Connection:
        def execute(self, sql, *args):
            if sql == "BEGIN IMMEDIATE":
                entered.set()
            return original.execute(sql, *args)

        def __enter__(self):
            return original.__enter__()

        def __exit__(self, *args):
            return original.__exit__(*args)

        def __getattr__(self, name):
            return getattr(original, name)

    writer.conn = Connection()
    blocker = sqlite3.connect(memory.MEMORY_DB)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            writing = workers.submit(writer.bump_utility, "fixture", [1])
            try:
                assert entered.wait(2)
                reading = workers.submit(reader.get_utility, "fixture")
                assert reading.result(timeout=0.25) == {}
            finally:
                blocker.rollback()
            writing.result(timeout=2)
    finally:
        blocker.close()
