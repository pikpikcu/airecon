"""The cross-session memory brain must learn only from VERIFIED/high-confidence
findings — so the agent gets smarter over time, not dumber from false positives.
"""

from __future__ import annotations

import types

from airecon.proxy.agent.loop_state import _StateMixin


class _FakeMem:
    def __init__(self):
        self.saved = []

    def save_finding(self, f):
        self.saved.append(f)


def _stub(vulns):
    s = types.SimpleNamespace()
    s._session = types.SimpleNamespace(
        session_id="sess1", target="acme.test", vulnerabilities=vulns
    )
    s._memory_manager = _FakeMem()
    s._persisted_memory_finding_keys = set()
    return s


def test_only_verified_findings_are_learned():
    vulns = [
        {"type": "sqli", "url": "/a", "parameter": "id", "description": "verified one",
         "verified": True},
        {"type": "xss", "url": "/b", "parameter": "q", "description": "high conf",
         "verified_confidence": 0.9},
        {"type": "idor", "url": "/c", "parameter": "uid", "description": "unverified low",
         "verified_confidence": 0.2},
        {"type": "ssrf", "url": "/d", "parameter": "u", "description": "no verification info"},
    ]
    s = _stub(vulns)
    saved = _StateMixin._save_new_findings_to_memory(s)
    learned_types = {f["type"] for f in s._memory_manager.saved}
    assert saved == 2
    assert learned_types == {"sqli", "xss"}  # only verified/high-conf
    assert "idor" not in learned_types and "ssrf" not in learned_types


def test_disabling_gate_learns_all(monkeypatch):
    import airecon.proxy.config as cfg_mod

    real = cfg_mod.get_config()

    class _Cfg:
        def __getattr__(self, name):
            if name == "intelligence_learn_only_verified":
                return False
            return getattr(real, name)

    monkeypatch.setattr("airecon.proxy.config.get_config", lambda: _Cfg())
    vulns = [
        {"type": "a", "url": "/1", "parameter": "p", "description": "x"},
        {"type": "b", "url": "/2", "parameter": "p", "description": "y"},
    ]
    s = _stub(vulns)
    saved = _StateMixin._save_new_findings_to_memory(s)
    assert saved == 2  # gate off -> learns everything
