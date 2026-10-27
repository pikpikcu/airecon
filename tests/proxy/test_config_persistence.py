"""Configuration updates must preserve the active file and explicit options."""
import asyncio

import pytest
import yaml

import airecon.proxy.config as config


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config.Path, "home", lambda: tmp_path / "home")
    for key, value in [("_config", None), ("_config_path", None), ("_config_mtime", 0.0), ("_config_reload_lock", None)]:
        monkeypatch.setattr(config, key, value)
    return tmp_path / "custom.yaml"


def test_updates_write_active_config_and_preserve_explicit_options(isolated_config):
    path = isolated_config
    path.write_text(yaml.safe_dump({"openai_model": "custom", "docker_image": "custom-image",
                                    "openai_supports_native_tools": False, "fuzzer_threads": 3}))
    config.reload_config(str(path))
    updated = config.update_config_values({"scope_enforcement": "block"})
    persisted = yaml.safe_load(path.read_text())
    assert persisted["scope_enforcement"] == "block"
    assert updated.scope_enforcement == "block"
    assert config.reload_config(str(path)).scope_enforcement == "block"
    assert persisted["docker_image"] == "custom-image"
    assert persisted["fuzzer_threads"] == 3
    assert persisted["openai_supports_native_tools"] is False
    assert not (config.Path.home() / ".airecon/config.yaml").exists()


@pytest.mark.parametrize("async_load", [False, True])
def test_reload_without_path_keeps_active_custom_config(isolated_config, async_load):
    path = isolated_config
    path.write_text(yaml.safe_dump({"openai_model": "custom", "proxy_port": 4123}))
    config.reload_config(str(path))
    config._config = None
    loaded = asyncio.run(config.get_config_async()) if async_load else config.get_config()
    assert loaded.proxy_port == 4123
    assert loaded.openai_model == "custom"
    assert not (config.Path.home() / ".airecon/config.yaml").exists()


def test_persistence_errors_are_not_reported_as_success(isolated_config, monkeypatch):
    config.reload_config(str(isolated_config))
    def fail(*args, **kwargs):
        raise OSError("audit disk failure")
    monkeypatch.setattr(config, "_write_yaml_with_comments", fail)
    with pytest.raises(OSError, match="audit disk failure"):
        config.update_config_values({"scope_enforcement": "block"})


def test_protocol_memory_options_survive_utf8_updates(isolated_config):
    config.reload_config(str(isolated_config))
    values = {"llm_provider": "anthropic", "embedding_model": "fixture-日本語",
              "intelligence_semantic_recall": False, "intelligence_utility_floor": 0.3}
    loaded = config.update_config_values(values)
    assert all(getattr(loaded, k) == v for k, v in values.items())
    assert all(yaml.safe_load(isolated_config.read_text(encoding="utf-8"))[k] == v for k, v in values.items())


def test_windows_replace_retries_preserve_atomic_write(isolated_config, monkeypatch):
    config.reload_config(str(isolated_config))
    original = config.os.replace
    failures = []
    def locked_once(source, destination):
        if not failures:
            failures.append(True)
            error = PermissionError("fixture sharing lock")
            error.winerror = 32
            raise error
        return original(source, destination)
    monkeypatch.setattr(config.os, "replace", locked_once)
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    assert config.update_config_values({"openai_model": "fixture更新"}).openai_model == "fixture更新"
    assert not list(isolated_config.parent.glob(f".{isolated_config.name}.*.tmp"))


def test_failed_replace_never_truncates_existing_config(isolated_config, monkeypatch):
    config.reload_config(str(isolated_config))
    config.update_config_values({"openai_model": "original"})
    before = isolated_config.read_bytes()
    def locked(*args):
        error = PermissionError("fixture permanent lock")
        error.winerror = 32
        raise error
    monkeypatch.setattr(config.os, "replace", locked)
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    with pytest.raises(PermissionError):
        config.update_config_values({"openai_model": "not persisted"})
    assert isolated_config.read_bytes() == before
    assert not list(isolated_config.parent.glob(f".{isolated_config.name}.*.tmp"))
