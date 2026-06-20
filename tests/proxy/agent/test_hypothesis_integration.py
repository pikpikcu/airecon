"""Integration tests for the activated hypothesis engine.

Covers:
1. _auto_form_hypotheses() — auto-populates queue from CVE, vuln signals, ports
2. Chain advancement → hypothesis status update (pending/testing → confirmed)
3. Confirmed hypotheses → included in plan_chains() as synthetic vulns
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_loop():
    from airecon.proxy.agent.loop import AgentLoop

    llm_mock = MagicMock()
    engine_mock = MagicMock()
    engine_mock.discover_tools = MagicMock(return_value=[])
    engine_mock.tools_to_llm_format = MagicMock(return_value=[])

    with patch("airecon.proxy.agent.loop.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = 200
        cfg.llm_context_window = 4096
        mock_cfg.return_value = cfg
        loop = AgentLoop(llm=llm_mock, engine=engine_mock)

    return loop


def _make_mixin():
    """Return a minimal _ObjectivesMixin instance with a real AgentState."""
    from airecon.proxy.agent.loop_objectives import _ObjectivesMixin
    from airecon.proxy.agent.models import AgentState

    class _Stub(_ObjectivesMixin):
        def __init__(self):
            self.state = AgentState()
            self._session = None
            self._consecutive_failures = 0
            self.pipeline = None

    return _Stub()


# ── 1. _auto_form_hypotheses: CVE → hypothesis ────────────────────────────────


class TestAutoFormHypotheses:
    def test_cve_in_output_creates_hypothesis(self):
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="ANALYSIS",
            tool_name="execute",
            arguments={"command": "searchsploit apache"},
            result_text="CVE-2021-41773 path traversal on Apache 2.4.49",
        )
        assert len(m.state.hypothesis_queue) >= 1
        cve_hyps = [h for h in m.state.hypothesis_queue if "CVE-2021-41773" in h["claim"]]
        assert cve_hyps
        assert cve_hyps[0]["status"] == "pending"
        assert cve_hyps[0]["phase"] == "ANALYSIS"

    def test_sqli_signal_creates_hypothesis(self):
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "sqlmap -u http://target.com/login"},
            result_text="Parameter 'id' appears to be vulnerable to SQL injection",
        )
        assert any("SQL INJECTION" in h["claim"] for h in m.state.hypothesis_queue)

    def test_xss_signal_creates_hypothesis(self):
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "dalfox url http://target.com/search"},
            result_text="[POC] Reflected XSS found in parameter q",
        )
        xss_hyps = [h for h in m.state.hypothesis_queue if "XSS" in h["claim"]]
        assert xss_hyps, "No XSS hypothesis formed"
        assert "xss" in xss_hyps[0]["tags"]
        assert "confirm" in xss_hyps[0]["test_plan"].lower()

    def test_false_signal_not_added(self):
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={},
            result_text="Testing for SQL injection on endpoint /api/users",
        )
        # "testing for" is a false-signal — must not create hypothesis
        sqli_hyps = [
            h for h in m.state.hypothesis_queue if "SQL_INJECTION" in h["claim"]
        ]
        assert sqli_hyps == []

    def test_open_port_in_recon_creates_hypothesis(self):
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="RECON",
            tool_name="execute",
            arguments={"command": "nmap -sV target.com"},
            result_text="80/open tcp http Apache 2.4.49 — known XSS\n443/open tcp https\n22/open tcp ssh OpenSSH",
        )
        # Port hypotheses are formed when a vuln pattern matches first,
        # leaving capacity (< _MAX_HYPO_PER_CALL) for the port entry.
        port_hyps = [
            h for h in m.state.hypothesis_queue if "port" in h["claim"].lower()
        ]
        assert port_hyps, "Port hypothesis should form when vuln signal matches"
        assert "80" in port_hyps[0]["claim"]

    def test_open_port_in_exploit_not_added(self):
        """Port hypotheses are RECON-only."""
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={},
            result_text="80/open tcp http",
        )
        port_hyps = [
            h for h in m.state.hypothesis_queue if "port" in h["claim"].lower()
        ]
        assert port_hyps == []

    def test_max_two_hypotheses_per_call(self):
        """At most 2 hypotheses formed per _auto_form_hypotheses call."""
        m = _make_mixin()
        blob = (
            "CVE-2021-41773 path traversal. "
            "CVE-2021-42013 remote code execution. "
            "CVE-2022-22965 Spring4Shell RCE. "
            "SQL injection detected on /login. "
            "XSS found in search parameter."
        )
        m._auto_form_hypotheses("EXPLOIT", "execute", {}, blob)
        assert len(m.state.hypothesis_queue) <= 2

    def test_dedup_prevents_same_hypothesis_twice(self):
        """Same signal on two consecutive calls must not double the queue."""
        m = _make_mixin()
        blob = "CVE-2021-41773 path traversal"
        m._auto_form_hypotheses("ANALYSIS", "execute", {}, blob)
        m._auto_form_hypotheses("ANALYSIS", "execute", {}, blob)
        cve_hyps = [
            h for h in m.state.hypothesis_queue if "CVE-2021-41773" in h["claim"]
        ]
        assert len(cve_hyps) == 1

    def test_no_hypotheses_on_empty_result(self):
        m = _make_mixin()
        m._auto_form_hypotheses("RECON", "execute", {}, "")
        assert m.state.hypothesis_queue == []

    def test_endpoint_url_extracted_into_claim(self):
        """URL from command appears in the hypothesis claim."""
        m = _make_mixin()
        m._auto_form_hypotheses(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "sqlmap -u http://victim.com/api/users?id=1"},
            result_text="boolean-based SQL injection detected",
        )
        sqli_hyps = [
            h for h in m.state.hypothesis_queue if "SQL INJECTION" in h["claim"]
        ]
        assert sqli_hyps
        assert "victim.com" in sqli_hyps[0]["claim"]


# ── 2. record_evidence_from_result calls _auto_form_hypotheses ────────────────


class TestRecordEvidenceCallsAutoForm:
    def test_successful_execution_populates_hypothesis_queue(self):
        """CVE in tool output → hypothesis via _record_evidence_from_result."""
        m = _make_mixin()
        m._record_evidence_from_result(
            phase="ANALYSIS",
            tool_name="execute",
            arguments={"command": "nuclei -t cves/ -u http://target.com"},
            result={"stdout": "CVE-2021-44228 Log4Shell detected on target"},
            success=True,
            output_file=None,
        )
        assert any("CVE-2021-44228" in h["claim"] for h in m.state.hypothesis_queue)

    def test_failed_execution_does_not_populate_hypotheses(self):
        """Error results must not generate hypotheses."""
        m = _make_mixin()
        m._record_evidence_from_result(
            phase="ANALYSIS",
            tool_name="execute",
            arguments={"command": "sqlmap -u http://target.com"},
            result={"error": "Connection refused — SQL injection signal in error"},
            success=False,
            output_file=None,
        )
        # Failed execution should not trigger hypothesis formation
        sqli_hyps = [
            h for h in m.state.hypothesis_queue if "SQL_INJECTION" in h["claim"]
        ]
        assert sqli_hyps == []


# ── 3. Chain advancement → hypothesis status update ───────────────────────────


class TestChainAdvancementUpdatesHypothesis:
    def _make_chain_dict(self, name: str, vuln_basis: str, n_steps: int = 2):
        return {
            "chain_id": f"chain_{name}",
            "name": name,
            "description": f"Test chain for {name}",
            "vuln_basis": vuln_basis,
            "status": "active",
            "current_step_index": 0,
            "phase_formed": "EXPLOIT",
            "iteration_formed": 1,
            "steps": [
                {
                    "step_id": f"s{i}",
                    "description": f"Step {i}",
                    "tool_hint": "sqlmap",
                    "status": "pending",
                    "evidence": "",
                }
                for i in range(n_steps)
            ],
        }

    def test_chain_completion_confirms_linked_hypothesis(self):
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        # Add a pending hypothesis whose claim overlaps with vuln_basis
        hyp_id = state.add_hypothesis(
            claim="SQL injection vulnerability on login endpoint",
            test_plan="Use sqlmap",
            phase="EXPLOIT",
        )
        assert hyp_id

        # One-step chain — completing it should confirm the linked hypothesis
        chain = self._make_chain_dict("sqli_chain", "sql injection login", n_steps=1)
        state.exploit_chains.append(chain)

        # Simulate the loop logic directly
        _cd = state.exploit_chains[0]
        _cs_idx = int(_cd.get("current_step_index", 0))
        _steps = _cd.get("steps", [])
        _cur_step = _steps[_cs_idx]
        _cur_step["status"] = "done"
        _next_idx = _cs_idx + 1
        _chain_name = _cd.get("name", "?")
        _vuln_basis = str(_cd.get("vuln_basis", "")).lower().strip()

        if _next_idx >= len(_steps):
            _cd["status"] = "completed"
            _cd["current_step_index"] = _next_idx
            # Update linked hypothesis
            _vb_words = {w for w in _vuln_basis.split() if len(w) >= 4}
            for _hyp in state.hypothesis_queue:
                if _hyp.get("status") not in ("pending", "testing"):
                    continue
                _hwords = set(str(_hyp.get("claim", "")).lower().split())
                if _vb_words & _hwords:
                    state.update_hypothesis(
                        str(_hyp.get("id", "")),
                        "confirmed",
                        f"Exploit chain '{_chain_name}' completed all steps",
                    )
                    break

        updated = next(h for h in state.hypothesis_queue if h["id"] == hyp_id)
        assert updated["status"] == "confirmed"

    def test_chain_advancement_sets_hypothesis_testing(self):
        """Advancing (not completing) a chain flips hypothesis to 'testing'."""
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        hyp_id = state.add_hypothesis(
            claim="XSS vulnerability on search endpoint",
            test_plan="Use dalfox",
            phase="EXPLOIT",
        )

        chain = self._make_chain_dict("xss_chain", "xss search", n_steps=2)
        state.exploit_chains.append(chain)

        _cd = state.exploit_chains[0]
        _cs_idx = 0
        _steps = _cd.get("steps", [])
        _steps[_cs_idx]["status"] = "done"
        _next_idx = 1
        _chain_name = _cd["name"]
        _vuln_basis = _cd["vuln_basis"].lower().strip()

        _cd["current_step_index"] = _next_idx
        _cd["status"] = "active"
        _steps[_next_idx]["status"] = "in_progress"

        _vb_words = {w for w in _vuln_basis.split() if len(w) >= 4}
        for _hyp in state.hypothesis_queue:
            if _hyp.get("status") != "pending":
                continue
            _hwords = set(str(_hyp.get("claim", "")).lower().split())
            if _vb_words & _hwords:
                state.update_hypothesis(
                    str(_hyp.get("id", "")),
                    "testing",
                    f"Exploit chain '{_chain_name}' in progress (step 2/2)",
                )
                break

        updated = next(h for h in state.hypothesis_queue if h["id"] == hyp_id)
        assert updated["status"] == "testing"
        assert "in progress" in updated["evidence_refs"][0]


# ── 4. Confirmed hypotheses feed plan_chains() ───────────────────────────────


class TestConfirmedHypothesesFeedChainPlanner:
    def test_confirmed_hypothesis_becomes_synthetic_vuln(self):
        """Confirmed hypothesis → synthetic vuln entry for chain planner."""
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        hyp_id = state.add_hypothesis(
            claim="SQL injection vulnerability detected near http://target.com/login",
            test_plan="Use sqlmap to confirm",
            phase="EXPLOIT",
            tags=["sql_injection"],
        )
        state.update_hypothesis(hyp_id, "confirmed", "sqlmap found it")

        # Build synthetic vulns as loop.py does
        confirmed_hyp_vulns = [
            {
                "finding": h.get("claim", ""),
                "type": next(iter(h.get("tags", ["unknown"])), "unknown"),
                "severity": "HIGH",
                "proof": "; ".join(str(r) for r in h.get("evidence_refs", []))[:200],
            }
            for h in state.hypothesis_queue
            if h.get("status") == "confirmed"
        ]

        assert len(confirmed_hyp_vulns) == 1
        assert "sql_injection" in confirmed_hyp_vulns[0]["type"]
        assert "SQL injection" in confirmed_hyp_vulns[0]["finding"]

    def test_plan_chains_accepts_synthetic_vulns(self):
        """plan_chains() with synthetic hypothesis vulns returns chains."""
        from airecon.proxy.agent.chain_planner import plan_chains

        synthetic_vulns = [
            {
                "finding": "SQL injection vulnerability detected on /login",
                "type": "sql_injection",
                "severity": "HIGH",
                "proof": "confirmed by hypothesis engine",
            }
        ]
        chains = plan_chains(
            vulnerabilities=synthetic_vulns,
            existing_chain_ids=set(),
            iteration=5,
            max_chains=3,
        )
        # Chains are planned only if attack_chains.json has matching templates.
        # We just check no exception is thrown and the return type is correct.
        assert isinstance(chains, list)

    def test_pending_hypothesis_not_included_as_vuln(self):
        """Only CONFIRMED hypotheses become synthetic vulns, not pending."""
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        state.add_hypothesis("XSS vulnerability suspected", "Use dalfox", "EXPLOIT")

        confirmed_hyp_vulns = [
            {"finding": h.get("claim", ""), "type": "xss"}
            for h in state.hypothesis_queue
            if h.get("status") == "confirmed"
        ]
        assert confirmed_hyp_vulns == []
