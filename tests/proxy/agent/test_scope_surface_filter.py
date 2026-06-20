"""Attack-surface scope filtering.

Sessions showed the testable surface (urls/live_hosts/injection_points) polluted
with out-of-scope third-party hosts (login.microsoftonline.com, googleapis.com,
w3.org, example.org) — the dominant reason analysis/exploit underperformed
regardless of model. These tests lock in that only in-scope assets are ingested.
"""

from __future__ import annotations

from airecon.proxy.agent.session import (
    SessionData,
    ParsedOutput,
    update_from_parsed_output,
    url_in_target_scope,
)


def test_scope_helper_anchors_on_target_apex():
    t = "example.com"
    assert url_in_target_scope("https://api.example.com/v1?id=1", t) is True
    assert url_in_target_scope("https://admin.apps.example.com/x", t) is True
    assert url_in_target_scope("example.com:443", t) is True
    for bad in (
        "https://login.microsoftonline.com/oauth2/authorize?client_id=x",
        "https://firebasestorage.googleapis.com/v0/b/x",
        "http://www.w3.org/2000/svg",
        "https://www.google.com/recaptcha/api.js?hl=x",
        "https://example.org?PARAM=VAL",
    ):
        assert url_in_target_scope(bad, t) is False, bad


def test_allowlist_is_honored():
    assert (
        url_in_target_scope(
            "https://firebasestorage.googleapis.com/x",
            "example.com",
            ["firebasestorage.googleapis.com"],
        )
        is True
    )


def test_no_target_disables_filtering():
    # CTF / unscoped runs must not be affected.
    assert url_in_target_scope("http://10.0.0.5/x", "") is True


def test_ingestion_drops_out_of_scope_urls_and_injection_points():
    s = SessionData(session_id="t", target="example.com")
    parsed = ParsedOutput(tool="httpx", summary="")
    parsed.items = [
        # plain URLs (no [status]) hit the injection-point extraction path
        "https://api.example.com/v1?id=1",
        "https://login.microsoftonline.com/x/oauth2/v2.0/authorize?client_id=abc",
        "https://firebasestorage.googleapis.com/v0/b/proj?alt=media",
        "http://www.w3.org/2000/svg",
    ]
    update_from_parsed_output(s, parsed)

    # only the example.com asset survived
    assert any("api.example.com" in u for u in s.urls)
    assert not any("microsoftonline" in u for u in s.urls)
    assert not any("googleapis" in u for u in s.urls)
    assert not any("w3.org" in u for u in s.urls)

    inj_hosts = " ".join(p.get("url", "") for p in s.injection_points)
    assert "example.com" in inj_hosts
    assert "microsoftonline" not in inj_hosts
    assert "googleapis" not in inj_hosts
