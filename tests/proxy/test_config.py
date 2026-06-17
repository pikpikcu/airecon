"""Config tests updated for YAML format."""

import json
import yaml
from airecon.proxy.config import Config, DEFAULT_CONFIG


def test_config_default_initialization(tmp_path):
    # Using a fake path ensures it starts from defaults
    cfg = Config.load(tmp_path / "missing_config.yaml")
    assert cfg.openai_model == DEFAULT_CONFIG["openai_model"]
    assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]
    assert cfg.agent_exploration_mode is True
    assert cfg.agent_stagnation_threshold >= 1
    assert cfg.agent_tool_diversity_window >= 3
    assert cfg.session_persistence_enabled is True


def test_config_file_loading(tmp_path):
    config_file = tmp_path / "config.yaml"
    custom_settings = {
        "openai_model": "test-model:latest",
        "proxy_port": 8080,
    }
    with open(config_file, "w") as f:
        yaml.dump(custom_settings, f)

    cfg = Config.load(config_file)

    # Custom values should be present
    assert cfg.openai_model == "test-model:latest"
    assert cfg.proxy_port == 8080

    # Missing values should fall back to default
    assert cfg.docker_image == DEFAULT_CONFIG["docker_image"]
    assert cfg.llm_timeout == DEFAULT_CONFIG["llm_timeout"]


def test_config_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRECON_PROXY_PORT", "9999")
    monkeypatch.setenv("AIRECON_LLM_ENABLE_THINKING", "false")
    monkeypatch.setenv("AIRECON_COMMAND_TIMEOUT", "120.5")

    cfg = Config.load(tmp_path / "missing_config.yaml")

    assert cfg.proxy_port == 9999
    assert cfg.llm_enable_thinking is False
    assert cfg.command_timeout == 120.5


def test_config_invalid_env_types_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRECON_PROXY_PORT", "not-a-number")

    cfg = Config.load(tmp_path / "missing_config.yaml")
    # Should ignore the invalid int conversion and keep default
    assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]


# ---------------------------------------------------------------------------
# Issue #13: Corrupt config file rewrite
# ---------------------------------------------------------------------------


class TestCorruptConfigRewrite:
    def test_corrupt_yaml_rewritten_with_defaults(self, tmp_path):
        """A corrupt config.yaml must be overwritten with DEFAULT_CONFIG."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("{invalid yaml!!!")

        cfg = Config.load(config_file)

        # Should fall back to defaults
        assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]
        assert cfg.openai_model == DEFAULT_CONFIG["openai_model"]

        # The file must have been rewritten with valid YAML defaults
        with open(config_file) as f:
            rewritten = yaml.safe_load(f)
        assert rewritten["proxy_port"] == DEFAULT_CONFIG["proxy_port"]

    def test_empty_file_rewritten_with_defaults(self, tmp_path):
        """An empty config file (None from yaml.safe_load) must be rewritten."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        cfg = Config.load(config_file)

        assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]
        with open(config_file) as f:
            rewritten = yaml.safe_load(f)
        # Empty file is rewritten with defaults, so should be a dict
        assert rewritten is not None
        assert isinstance(rewritten, dict)
        assert "proxy_port" in rewritten

    def test_partial_corrupt_yaml_rewritten(self, tmp_path):
        """Truncated YAML must trigger rewrite."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("proxy_port: 9000\nopenai_model: [unclosed")

        cfg = Config.load(config_file)

        # Defaults used since file is corrupt
        assert cfg.openai_model == DEFAULT_CONFIG["openai_model"]
        # File is rewritten with clean defaults
        with open(config_file) as f:
            rewritten = yaml.safe_load(f)
        assert rewritten["openai_model"] == DEFAULT_CONFIG["openai_model"]


# ---------------------------------------------------------------------------
# Issue #13: Type coercion in load_with_defaults
# ---------------------------------------------------------------------------


class TestLoadWithDefaultsTypeCoercion:
    def test_string_int_coerced(self):
        """proxy_port as string '3000' must be coerced to int 3000."""
        raw = {**DEFAULT_CONFIG, "proxy_port": "3000"}
        cfg = Config.load_with_defaults(raw)
        assert cfg.proxy_port == 3000
        assert isinstance(cfg.proxy_port, int)

    def test_string_float_coerced(self):
        """llm_timeout as string '600.0' must be coerced to float."""
        raw = {**DEFAULT_CONFIG, "llm_timeout": "600.0"}
        cfg = Config.load_with_defaults(raw)
        assert cfg.llm_timeout == 600.0
        assert isinstance(cfg.llm_timeout, float)

    def test_string_bool_true_coerced(self, tmp_path):
        """'true' string for bool field must become True."""
        raw = {**DEFAULT_CONFIG, "docker_auto_build": "true"}
        cfg = Config.load_with_defaults(raw)
        assert cfg.docker_auto_build is True

    def test_string_bool_false_coerced(self):
        """'false' string for bool field must become False."""
        raw = {**DEFAULT_CONFIG, "llm_enable_thinking": "false"}
        cfg = Config.load_with_defaults(raw)
        assert cfg.llm_enable_thinking is False

    def test_string_bool_yes_coerced(self):
        """'yes' string for bool field must become True."""
        raw = {**DEFAULT_CONFIG, "allow_destructive_testing": "yes"}
        cfg = Config.load_with_defaults(raw)
        assert cfg.allow_destructive_testing is True

    def test_unconvertible_value_falls_back_to_default(self):
        """Non-numeric string for int field must fall back to default."""
        raw = {**DEFAULT_CONFIG, "proxy_port": "not-a-port"}
        cfg = Config.load_with_defaults(raw)
        assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]

    def test_correct_type_not_modified(self):
        """Values already of the correct type must not be changed."""
        raw = {**DEFAULT_CONFIG, "proxy_port": 8888}
        cfg = Config.load_with_defaults(raw)
        assert cfg.proxy_port == 8888

    def test_unknown_keys_ignored(self):
        """Unknown keys from an old config file must be silently dropped."""
        raw = {**DEFAULT_CONFIG, "old_deprecated_setting": "foo", "another_stale": 42}
        cfg = Config.load_with_defaults(raw)
        assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]
        assert not hasattr(cfg, "old_deprecated_setting")

    def test_missing_keys_use_defaults(self):
        """If a key is absent from raw dict, DEFAULT_CONFIG value is used."""
        raw = {"proxy_port": 4444}  # missing all other keys
        cfg = Config.load_with_defaults(raw)
        assert cfg.proxy_port == 4444
        assert cfg.openai_model == DEFAULT_CONFIG["openai_model"]
        assert cfg.docker_image == DEFAULT_CONFIG["docker_image"]

    def test_int_to_float_coerced(self):
        """Int value for float field (e.g. timeout=900 not 900.0) must coerce."""
        raw = {**DEFAULT_CONFIG, "llm_timeout": 900}
        cfg = Config.load_with_defaults(raw)
        assert cfg.llm_timeout == 900.0
        assert isinstance(cfg.llm_timeout, float)

    def test_config_file_with_wrong_types_loads_correctly(self, tmp_path):
        """End-to-end: config.json with wrong types must coerce on load."""
        config_file = tmp_path / "config.json"
        bad_typed = {
            "proxy_port": "5000",  # string → int
            "llm_timeout": "300",  # string → float
            "docker_auto_build": "false",  # string → bool
        }
        with open(config_file, "w") as f:
            json.dump(bad_typed, f)

        cfg = Config.load(config_file)

        assert cfg.proxy_port == 5000
        assert isinstance(cfg.proxy_port, int)
        assert cfg.llm_timeout == 300.0
        assert isinstance(cfg.llm_timeout, float)
        assert cfg.docker_auto_build is False

    def test_agent_max_conversation_auto_derives_from_llm_ctx(self, tmp_path):
        """When not explicitly configured, cap must follow llm_context_window."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"llm_context_window": 8192}), encoding="utf-8")
        cfg = Config.load(config_file)
        assert cfg.llm_context_window == 8192
        assert cfg.agent_max_conversation_messages == 100  # max(100, 8192//128)

    def test_agent_max_conversation_explicit_value_is_preserved(self, tmp_path):
        """Explicit cap should override auto-derivation."""
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps(
                {
                    "llm_context_window": 8192,
                    "agent_max_conversation_messages": 333,
                }
            ),
            encoding="utf-8",
        )
        cfg = Config.load(config_file)
        assert cfg.llm_context_window == 8192
        assert cfg.agent_max_conversation_messages == 333

    def test_agent_recon_mode_valid_values(self):
        cfg_standard = Config.load_with_defaults({**DEFAULT_CONFIG, "agent_recon_mode": "standard"})
        cfg_full = Config.load_with_defaults({**DEFAULT_CONFIG, "agent_recon_mode": "FULL"})
        assert cfg_standard.agent_recon_mode == "standard"
        assert cfg_full.agent_recon_mode == "full"

    def test_agent_recon_mode_invalid_falls_back_to_default(self):
        cfg = Config.load_with_defaults({**DEFAULT_CONFIG, "agent_recon_mode": "aggressive"})
        assert cfg.agent_recon_mode == DEFAULT_CONFIG["agent_recon_mode"]
