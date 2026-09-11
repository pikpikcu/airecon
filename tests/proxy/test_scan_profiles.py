"""Tests for data-driven scan profiles (config baseline layer)."""

from __future__ import annotations

from airecon.proxy.config import Config, _load_scan_profile


def _cfg(**raw):
    raw.setdefault("openai_model", "m")
    return Config.load_with_defaults(raw)


def test_standard_profile_is_identity():
    # 'standard' must not change defaults (non-breaking).
    default = _cfg()
    standard = _cfg(scan_profile="standard")
    assert default.agent_max_tool_iterations == standard.agent_max_tool_iterations
    assert default.agent_recon_mode == standard.agent_recon_mode


def test_deep_profile_raises_intensity():
    deep = _cfg(scan_profile="deep")
    assert deep.agent_max_tool_iterations == 1200
    assert deep.agent_recon_mode == "full"
    assert deep.agent_exploration_intensity == 0.95


def test_quick_profile_lowers_budget():
    quick = _cfg(scan_profile="quick")
    assert quick.agent_max_tool_iterations == 200
    assert quick.agent_exploration_mode is False


def test_user_config_overrides_profile():
    # Explicit user key wins over the profile baseline.
    c = _cfg(scan_profile="deep", agent_max_tool_iterations=50)
    assert c.agent_max_tool_iterations == 50


def test_unknown_profile_is_safe():
    c = _cfg(scan_profile="does-not-exist")
    # Falls back to defaults (empty override set).
    assert c.agent_max_tool_iterations == _cfg().agent_max_tool_iterations


def test_profiles_only_reference_real_config_keys():
    known = {f.name for f in Config.__dataclass_fields__.values()}
    for name in ("quick", "deep", "stealth", "ctf", "bugbounty"):
        for key in _load_scan_profile(name):
            assert key in known, f"profile '{name}' references unknown key '{key}'"
