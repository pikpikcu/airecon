import pytest
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, MagicMock
from airecon.proxy.agent.loop import AgentLoop
from airecon.proxy.agent.loop_policy import should_preserve_active_target_for_subdomain
from airecon.proxy.agent.pipeline import PipelinePhase
from airecon.proxy.agent.session import SessionData


@pytest.fixture
def agent_loop(mocker):
    llm_mock = MagicMock()
    llm_mock.chat_stream = AsyncMock()

    engine_mock = MagicMock()
    engine_mock.discover_tools = AsyncMock(return_value=[])
    engine_mock.tools_to_llm_format = MagicMock(return_value=[])

    with patch("airecon.proxy.agent.loop.get_config") as mock_config:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = 5
        mock_config.return_value = cfg
        loop = AgentLoop(llm=llm_mock, engine=engine_mock)
        return loop


@pytest.mark.asyncio
async def test_agent_initialization(agent_loop, mocker):
    mocker.patch(
        "airecon.proxy.agent.loop.get_system_prompt", return_value="You are AIRecon."
    )

    await agent_loop.initialize(target="test.com", user_message="scan test.com")

    assert len(agent_loop.state.conversation) > 0
    assert "You are AIRecon." in agent_loop.state.conversation[0]["content"]
    assert agent_loop._session is not None
    assert agent_loop.pipeline is not None


@pytest.mark.asyncio
async def test_agent_duplicate_command(agent_loop):
    # DEDUP exempt tools should never block
    is_dup, msg = agent_loop._is_duplicate_command(
        "create_file", {"path": "test", "content": "1"}
    )
    assert not is_dup

    # Generic tools block on exact match
    is_dup, msg = agent_loop._is_duplicate_command("execute", {"command": "ls -la"})
    assert not is_dup

    is_dup, msg = agent_loop._is_duplicate_command("execute", {"command": "ls -la"})
    assert is_dup
    assert "[NO NEW EVIDENCE]" in msg


def test_agent_state_reset(agent_loop):
    agent_loop.state.iteration = 10
    agent_loop._executed_tool_counts = {("tool", "args"): 1}
    agent_loop.reset()

    assert agent_loop.state.iteration == 0
    assert len(agent_loop._executed_tool_counts) == 0


@pytest.mark.asyncio
async def test_load_session_persistence_restores_adaptive_state(agent_loop, mocker):
    agent_loop._session = SessionData(target="example.com", session_id="sess-1")
    persist = MagicMock()
    persist.load_payload_memory.return_value = []
    persist.load_adaptive_state.return_value = {
        "tool_performances": {
            "sqlmap": {
                "total_uses": 4,
                "successes": 3,
                "failures": 1,
                "avg_duration": 2.5,
                "avg_confidence": 0.9,
                "last_used": 123.0,
                "success_streak": 2,
                "failure_streak": 0,
                "context_scores": {"phase=ANALYSIS": 0.8},
                "target_type_scores": {"nginx": 0.7},
            }
        },
        "strategy_patterns": [
            {
                "pattern_id": "p1",
                "description": "Use httpx then nuclei",
                "conditions": {"phase": "ANALYSIS"},
                "tool_sequence": ["httpx", "nuclei"],
                "success_count": 3,
                "failure_count": 1,
                "avg_result_confidence": 0.88,
                "last_applied": 456.0,
            }
        ],
    }

    mocker.patch(
        "airecon.proxy.agent.loop.get_config",
        return_value=SimpleNamespace(
            session_persistence_enabled=True,
            intelligence_adaptive_min_observations=3,
        ),
    )
    mocker.patch("airecon.proxy.agent.loop.get_workspace_root", return_value="/tmp")
    mocker.patch(
        "airecon.proxy.agent.session_persistence.SessionPersistenceEngine",
        return_value=persist,
    )

    await agent_loop._load_session_persistence()

    assert agent_loop._adaptive_learning_engine.tool_performances["sqlmap"].total_uses == 4
    assert agent_loop._adaptive_learning_engine.tool_performances["sqlmap"].context_scores["phase=ANALYSIS"] == 0.8
    assert any(
        p.pattern_id == "p1" and p.tool_sequence == ["httpx", "nuclei"]
        for p in agent_loop._adaptive_learning_engine.strategy_patterns
    )


@pytest.mark.asyncio
async def test_load_session_persistence_buffers_payload_memory(agent_loop, mocker):
    agent_loop._session = SessionData(target="example.com", session_id="sess-1")
    persist = MagicMock()
    persist.load_payload_memory.return_value = [
        {
            "payload": "' OR 1=1--",
            "vuln_type": "sql_injection",
            "target": "example.com",
            "param": "id",
            "success": False,
            "confidence": 0.2,
            "status_code": 200,
            "waf_detected": "",
            "tech_stack": [],
            "response_time_ms": 12.0,
            "error": "",
            "timestamp": time.time(),
            "attempts": 2,
        }
    ]
    persist.load_adaptive_state.return_value = None

    mocker.patch(
        "airecon.proxy.agent.loop.get_config",
        return_value=SimpleNamespace(
            session_persistence_enabled=True,
            intelligence_adaptive_min_observations=3,
        ),
    )
    mocker.patch("airecon.proxy.agent.loop.get_workspace_root", return_value="/tmp")
    mocker.patch(
        "airecon.proxy.agent.session_persistence.SessionPersistenceEngine",
        return_value=persist,
    )

    await agent_loop._load_session_persistence()

    assert len(agent_loop._pending_payload_memory_records) == 1
    assert agent_loop._pending_payload_memory_records[0]["param"] == "id"
    assert agent_loop._loaded_session_persistence_target == "example.com"


def test_restore_payload_memory_into_fuzzer(agent_loop):
    from airecon.proxy.agent.payload_memory import PayloadMemoryEngine

    agent_loop._pending_payload_memory_records = [
        {
            "payload": "<svg/onload=alert(1)>",
            "vuln_type": "xss",
            "target": "example.com",
            "param": "q",
            "success": True,
            "confidence": 0.9,
            "status_code": 200,
            "waf_detected": "",
            "tech_stack": [],
            "response_time_ms": 5.0,
            "error": "",
            "timestamp": time.time(),
            "attempts": 1,
        }
    ]

    class DummyFuzzer:
        def __init__(self) -> None:
            self.payload_memory = PayloadMemoryEngine()

    dummy = DummyFuzzer()
    loaded = agent_loop._restore_payload_memory_into(dummy)

    assert loaded == 1
    assert len(dummy.payload_memory.records) == 1


@pytest.mark.asyncio
async def test_create_or_switch_session_loads_target_persistence(agent_loop, mocker):
    agent_loop._session = SessionData(target="", session_id="sess-1")
    agent_loop.state.active_target = "example.com"
    agent_loop._load_session_persistence = AsyncMock()

    await agent_loop._create_or_switch_session()

    agent_loop._load_session_persistence.assert_awaited_once()
    assert agent_loop._session.target == "example.com"


# ---------------------------------------------------------------------------
# Subdomain workspace preservation
# Verifies the logic introduced in loop.py: when extracted_target is a
# subdomain of the current active_target, active_target must NOT change so
# that all recon output stays in the parent-domain workspace folder.
# ---------------------------------------------------------------------------


class TestSubdomainWorkspacePreservation:
    """
    Isolated unit tests for the subdomain-target guard in loop.py.

    We replicate the exact guard condition so that any drift between the
    implementation and the tests fails loudly.
    """

    @staticmethod
    def _would_switch(extracted: str, current: str | None) -> bool:
        """Guard delegated to loop_policy module."""
        return not should_preserve_active_target_for_subdomain(
            extracted_target=extracted,
            current_active_target=current,
        )

    # --- True: target SHOULD change ---

    def test_fresh_target_when_no_current(self):
        """First message — no current target → always set."""
        assert self._would_switch("target.example.com", None) is True

    def test_different_domain_switches(self):
        """Completely different domain should switch workspace."""
        assert self._would_switch("evil.com", "target.example.com") is True

    def test_parent_to_different_tld_switches(self):
        assert self._would_switch("target.example.org", "target.example.com") is True

    def test_same_target_does_not_switch(self):
        """Repeated same target is allowed (idempotent)."""
        assert self._would_switch("target.example.com", "target.example.com") is True

    # --- False: target should NOT change (subdomain case) ---

    def test_subdomain_does_not_switch(self):
        """app.target.example.com is a subdomain → keep parent workspace."""
        assert (
            self._would_switch("app.target.example.com", "target.example.com") is False
        )

    def test_deep_subdomain_does_not_switch(self):
        assert (
            self._would_switch("api.v2.target.example.com", "target.example.com")
            is False
        )

    def test_single_label_subdomain_does_not_switch(self):
        assert self._would_switch("mail.example.com", "example.com") is False

    def test_partial_suffix_match_is_not_subdomain(self):
        """'navigatemore.com' ends with 'e.com' but NOT 'target.example.com'."""
        assert self._would_switch("navigatemore.com", "target.example.com") is True

    def test_ip_as_extracted_is_different_domain(self):
        """IP is always treated as a different target, not a subdomain."""
        assert self._would_switch("192.168.1.1", "target.example.com") is True


class TestSimpleTargetKickoffDetection:
    def test_plain_target_only_is_simple(self, agent_loop):
        assert agent_loop._is_simple_target_kickoff("example.com", "example.com") is True

    def test_target_with_url_punctuation_is_simple(self, agent_loop):
        assert (
            agent_loop._is_simple_target_kickoff("https://example.com/", "example.com")
            is True
        )

    def test_scoped_request_is_not_simple(self, agent_loop):
        assert (
            agent_loop._is_simple_target_kickoff(
                "show me robots.txt on example.com", "example.com"
            )
            is False
        )


@pytest.mark.asyncio
async def test_standard_mode_scoped_request_keeps_scope_lock_disabled(agent_loop, mocker):
    cfg = MagicMock()
    cfg.agent_recon_mode = "standard"
    cfg.deep_recon_autostart = True
    cfg.llm_context_window_small = 4096
    mocker.patch("airecon.proxy.agent.loop_message_entry.get_config", return_value=cfg)

    agent_loop._tools_llm = []
    mocker.patch.object(agent_loop, "_scan_workspace_state", return_value="")

    await agent_loop._prepare_message_context("enumerate subdomains for example.com only")

    assert agent_loop._scope_lock_active is False



@pytest.mark.asyncio
async def test_wildcard_scope_moves_workspace_to_root_target(agent_loop, mocker):
    cfg = MagicMock()
    cfg.agent_recon_mode = "standard"
    cfg.deep_recon_autostart = False
    cfg.llm_context_window_small = 4096
    mocker.patch("airecon.proxy.agent.loop_message_entry.get_config", return_value=cfg)

    agent_loop._tools_llm = [MagicMock()]
    agent_loop.state.active_target = "app.ringkas.co.id"
    agent_loop._scope_anchor_target = "app.ringkas.co.id"
    mocker.patch.object(agent_loop, "_scan_workspace_state", return_value="")

    await agent_loop._prepare_message_context(
        "scope ringkas.co.id/*.ringkas.co.id only"
    )

    assert agent_loop.state.active_target == "ringkas.co.id"
    assert agent_loop._scope_anchor_target == "ringkas.co.id"


@pytest.mark.asyncio
async def test_prepare_message_context_does_not_emergency_truncate_on_high_cumulative_only(agent_loop, mocker):
    cfg = MagicMock()
    cfg.agent_recon_mode = "standard"
    cfg.deep_recon_autostart = False
    cfg.llm_context_window_small = 4096
    cfg.llm_context_window = 32768
    mocker.patch("airecon.proxy.agent.loop_message_entry.get_config", return_value=cfg)

    agent_loop._tools_llm = [MagicMock()]
    agent_loop.state.active_target = "example.com"
    agent_loop._scope_anchor_target = "example.com"
    agent_loop._session = SessionData(target="example.com")
    agent_loop._session.scan_count = 1
    mocker.patch.object(agent_loop, "_scan_workspace_state", return_value="")

    agent_loop.state.conversation = [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "assistant", "content": "Ready."},
    ]
    agent_loop.state.token_usage["cumulative"] = 200_000
    agent_loop.state.token_usage["used"] = 512

    await agent_loop._prepare_message_context("continue with the same scope")

    assert agent_loop.state.token_usage["cumulative"] == 200_000


def test_scope_lock_disables_aggressive_exploration_directive(agent_loop):
    agent_loop._scope_lock_active = True
    directive = agent_loop._build_exploration_directive(PipelinePhase.RECON)
    assert "STRICT_SCOPE_MODE" in directive


def test_skill_phase_for_message_start_uses_current_phase(agent_loop):
    class _P:
        value = "EXPLOIT"

    agent_loop._get_current_phase = lambda: _P()
    assert agent_loop._skill_phase_for_message_start() == "EXPLOIT"


def test_skill_phase_for_message_start_fallback_recon(agent_loop):
    def _boom():
        raise RuntimeError("phase unavailable")

    agent_loop._get_current_phase = _boom
    assert agent_loop._skill_phase_for_message_start() == "RECON"


class TestExtractShellCommandCandidate:
    """Tests for _extract_shell_command_candidate — watchdog command extractor."""

    def _extract(self, loop, content: str) -> str | None:
        return loop._extract_shell_command_candidate(
            content_acc=content, thinking_acc=""
        )

    def test_single_curl_extracted(self, agent_loop):
        content = "```bash\ncurl -s https://example.com/api\n```"
        result = self._extract(agent_loop, content)
        assert result is not None
        assert "curl" in result

    def test_multiline_script_extracted_fully(self, agent_loop):
        """Watchdog must capture the entire multi-line bash script, not just first curl."""
        content = (
            "```bash\n"
            'echo "=== Testing IDOR ==="\n'
            'curl -s -k "https://example.com/wp-json/wp/v2/users/1"\n'
            'echo ""\n'
            'curl -s -k "https://example.com/wp-json/wp/v2/users/2"\n'
            'echo "=== Done ==="\n'
            "```"
        )
        result = self._extract(agent_loop, content)
        assert result is not None
        # Must contain ALL curl calls, not just the first one
        assert result.count("curl") == 2
        assert "users/1" in result
        assert "users/2" in result

    def test_echo_prefix_triggers_extraction(self, agent_loop):
        """echo was previously missing from command_prefix_re — must match now."""
        content = '```bash\necho "hello world"\n```'
        result = self._extract(agent_loop, content)
        assert result is not None
        assert "echo" in result

    def test_comment_lines_skipped(self, agent_loop):
        content = "```bash\n# This is a comment\ncurl -s https://example.com\n```"
        result = self._extract(agent_loop, content)
        assert result is not None
        assert "#" not in result

    def test_non_command_block_returns_none(self, agent_loop):
        """A block with no known command prefixes should return None."""
        content = "```bash\nsome_unknown_binary --flag value\n```"
        result = self._extract(agent_loop, content)
        assert result is None

    def test_no_bash_block_returns_none(self, agent_loop):
        result = self._extract(agent_loop, "just some plain text with no commands")
        assert result is None


# ---------------------------------------------------------------------------
# REPORT phase objective tracking
# Verifies that _update_objectives_from_tool marks REPORT objectives done
# via multiple trigger paths, not just create_vulnerability_report tool.
# ---------------------------------------------------------------------------


class TestReportObjectiveTracking:
    """Unit tests for REPORT phase objective completion logic."""

    def _setup(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        defaults = agent_loop._PHASE_OBJECTIVES["REPORT"]
        agent_loop.state.ensure_phase_objectives("REPORT", defaults)
        return PipelinePhase.REPORT, defaults

    def _call(self, agent_loop, phase, tool_name, result, output_file=None):
        agent_loop._update_objectives_from_tool(
            phase=phase,
            tool_name=tool_name,
            arguments={},
            success=True,
            result=result,
            output_file=output_file,
        )

    def _status(self, agent_loop, title):
        for obj in agent_loop.state.objective_queue:
            if obj.get("title") == title:
                return obj.get("status")
        return None

    def test_create_vulnerability_report_tool_marks_objectives(self, agent_loop):
        """Calling create_vulnerability_report must mark obj 0 and 1 done."""
        phase, defaults = self._setup(agent_loop)
        self._call(agent_loop, phase, "create_vulnerability_report", {})
        assert self._status(agent_loop, defaults[0]) == "done"
        assert self._status(agent_loop, defaults[1]) == "done"

    def test_report_content_in_result_marks_objectives(self, agent_loop):
        """Result containing 'vulnerability report' keyword triggers objectives."""
        phase, defaults = self._setup(agent_loop)
        result = {"stdout": "vulnerability report written to output/report.md"}
        self._call(agent_loop, phase, "execute", result)
        assert self._status(agent_loop, defaults[0]) == "done"
        assert self._status(agent_loop, defaults[1]) == "done"

    def test_cvss_in_result_marks_objectives(self, agent_loop):
        """Result containing CVSS score notation triggers objectives."""
        phase, defaults = self._setup(agent_loop)
        result = {"stdout": "CVE-2024-1234 | CVSS: 9.8 | severity: critical"}
        self._call(agent_loop, phase, "execute", result)
        assert self._status(agent_loop, defaults[0]) == "done"
        assert self._status(agent_loop, defaults[1]) == "done"

    def test_vulnerability_output_path_marks_objectives(self, agent_loop):
        """Only artifacts under vulnerabilities/ count as final reports."""
        phase, defaults = self._setup(agent_loop)
        self._call(
            agent_loop,
            phase,
            "create_file",
            {},
            output_file="vulnerabilities/vuln_report.md",
        )
        assert self._status(agent_loop, defaults[0]) == "done"
        assert self._status(agent_loop, defaults[1]) == "done"

    def test_generic_output_without_report_content_does_not_mark(self, agent_loop):
        """Plain execute output with no report keywords must NOT mark obj 0/1."""
        phase, defaults = self._setup(agent_loop)
        result = {"stdout": "nmap scan complete, 3 ports open"}
        self._call(agent_loop, phase, "execute", result)
        assert self._status(agent_loop, defaults[0]) == "pending"
        assert self._status(agent_loop, defaults[1]) == "pending"

    def test_output_in_output_dir_marks_obj2(self, agent_loop):
        """Any output_file starting with output/ marks objective 2."""
        phase, defaults = self._setup(agent_loop)
        self._call(agent_loop, phase, "create_file", {}, output_file="output/notes.txt")
        assert self._status(agent_loop, defaults[2]) == "done"

    def test_failed_tool_call_marks_nothing(self, agent_loop):
        """A failed tool call (success=False) must not update any objectives."""
        phase, defaults = self._setup(agent_loop)
        agent_loop._update_objectives_from_tool(
            phase=phase,
            tool_name="create_vulnerability_report",
            arguments={},
            success=False,
            result={},
            output_file=None,
        )
        assert self._status(agent_loop, defaults[0]) == "pending"


def test_sync_token_usage_from_session_keeps_cumulative_resets_used(agent_loop):
    agent_loop._session = SessionData(target="example.com")
    agent_loop._session.token_total=1_234_567
    agent_loop._session.token_prompt_total=900_000
    agent_loop._session.token_completion_total=334_567
    agent_loop._session.token_last_used=12_345

    agent_loop.state.token_usage["used"] = 777
    agent_loop.state.token_usage["last_prompt"] = 333
    agent_loop.state.token_usage["last_completion"] = 444

    agent_loop._sync_token_usage_from_session()

    assert agent_loop.state.token_usage["cumulative"] == 1_234_567
    assert agent_loop.state.token_usage["cumulative_prompt"] == 900_000
    assert agent_loop.state.token_usage["cumulative_completion"] == 334_567
    assert agent_loop.state.token_usage["used"] == agent_loop._session.token_last_used
    assert agent_loop.state.token_usage["last_prompt"] == 0
    assert agent_loop.state.token_usage["last_completion"] == 0


def test_recompute_used_tokens_from_conversation_updates_live_counter(agent_loop):
    agent_loop.state.conversation = [
        {"role": "system", "content": "abc"},
        {"role": "user", "content": "defghi"},
    ]
    agent_loop.state.token_usage["used"] = 999

    used = agent_loop._recompute_used_tokens_from_conversation()

    assert used == len("abc\ndefghi") // 4  # Changed from //3 to //4 for better non-English accuracy
    assert agent_loop.state.token_usage["used"] == used


def test_recompute_used_tokens_from_conversation_ignores_non_dict_messages(agent_loop):
    agent_loop.state.conversation = [
        {"role": "system", "content": "hello"},
        "not-a-dict",
        {"role": "assistant", "content": "world"},
    ]

    used = agent_loop._recompute_used_tokens_from_conversation()

    assert used == len("hello\nworld") // 4  # Changed from //3 to //4 for better non-English accuracy


# ---------------------------------------------------------------------------
# _has_scan_work — guard against empty session persistence
# ---------------------------------------------------------------------------


class TestHasScanWork:
    """Verify that _has_scan_work() correctly identifies sessions with real work."""

    def test_no_session_returns_false(self, agent_loop):
        agent_loop._session = None
        assert agent_loop._has_scan_work() is False

    def test_empty_session_returns_false(self, agent_loop):
        agent_loop._session = SessionData(target="test.com")
        agent_loop.state.evidence_log = []
        # scan_count = 0, evidence_log = [] → no work
        assert agent_loop._has_scan_work() is False

    def test_scan_count_gt0_returns_true(self, agent_loop):
        agent_loop._session = SessionData(target="test.com")
        agent_loop._session.scan_count = 1
        agent_loop.state.evidence_log = []
        assert agent_loop._has_scan_work() is True

    def test_evidence_log_returns_true(self, agent_loop):
        agent_loop._session = SessionData(target="test.com")
        agent_loop._session.scan_count = 0
        agent_loop.state.evidence_log = [{"summary": "port 80 open", "confidence": 0.9}]
        assert agent_loop._has_scan_work() is True

    def test_both_scan_count_and_evidence_returns_true(self, agent_loop):
        agent_loop._session = SessionData(target="test.com")
        agent_loop._session.scan_count = 3
        agent_loop.state.evidence_log = [{"summary": "sqli found", "confidence": 0.8}]
        assert agent_loop._has_scan_work() is True


# ---------------------------------------------------------------------------
# Feature 1: Reflector Agent Pattern
# ---------------------------------------------------------------------------


class TestReflectorAgentPattern:
    """_build_reflector_message generates targeted XML-structured corrections."""

    def test_reflector_attempt1_contains_issue_tag(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        msg = agent_loop._build_reflector_message(
            "", attempt=1, phase=PipelinePhase.RECON
        )
        assert "<reflector " in msg
        assert "<issue>" in msg
        assert "<required_action>" in msg
        assert 'attempt="1"' in msg

    def test_reflector_attempt2_stronger_warning(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        msg = agent_loop._build_reflector_message(
            "scan port", attempt=2, phase=PipelinePhase.RECON
        )
        assert 'attempt="2"' in msg
        assert "REFLECTOR" in msg

    def test_reflector_infers_known_tool_from_registry(self, agent_loop):
        # Inject a mock tool registry so _reflector_infer_tool_hint can detect it
        agent_loop._tools_llm = [
            {"function": {"name": "execute"}},
            {"function": {"name": "browser_action"}},
        ]
        hint = agent_loop._reflector_infer_tool_hint(
            "I will use browser_action to visit the page"
        )
        assert "browser_action" in hint

    def test_reflector_fallback_when_no_match(self, agent_loop):
        agent_loop._tools_llm = [{"function": {"name": "execute"}}]
        hint = agent_loop._reflector_infer_tool_hint(
            "I will analyze the results carefully"
        )
        # No known tool mentioned → generic fallback
        assert "execute" in hint or "<command>" in hint

    def test_reflector_fallback_when_no_registry(self, agent_loop):
        agent_loop._tools_llm = []
        hint = agent_loop._reflector_infer_tool_hint("I will do something")
        assert hint == 'execute({"command": "<command>"})'

    def test_reflector_has_escalation_warning(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        msg = agent_loop._build_reflector_message(
            "", attempt=1, phase=PipelinePhase.EXPLOIT
        )
        assert "<escalation_warning>" in msg

    def test_reflector_phase_in_tag(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        msg = agent_loop._build_reflector_message(
            "", attempt=1, phase=PipelinePhase.ANALYSIS
        )
        assert 'phase="ANALYSIS"' in msg

    def test_reflector_uses_no_tool_iterations_as_attempt(self, agent_loop):
        # Reflector uses _no_tool_iterations directly — no separate counter
        from airecon.proxy.agent.pipeline import PipelinePhase

        agent_loop._no_tool_iterations = 2
        msg = agent_loop._build_reflector_message(
            "", attempt=2, phase=PipelinePhase.RECON
        )
        assert 'attempt="2"' in msg


# ---------------------------------------------------------------------------
# Feature 2: Objective Patching
# ---------------------------------------------------------------------------


class TestObjectivePatching:
    """patch_objectives() applies delta ops to objective_queue."""

    def _make_state(self):
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        state.objective_queue = [
            {
                "phase": "RECON",
                "title": "Subdomain enumeration",
                "status": "pending",
                "priority": 80,
            },
            {
                "phase": "RECON",
                "title": "Port scan live hosts",
                "status": "pending",
                "priority": 70,
            },
            {
                "phase": "ANALYSIS",
                "title": "Prioritize injection points",
                "status": "pending",
                "priority": 60,
            },
        ]
        return state

    def test_add_new_objective(self):
        state = self._make_state()
        changed = state.patch_objectives(
            [{"op": "add", "phase": "RECON", "title": "Certificate transparency scan"}]
        )
        assert changed == 1
        titles = [o["title"] for o in state.objective_queue]
        assert "Certificate transparency scan" in titles

    def test_add_duplicate_skipped(self):
        state = self._make_state()
        changed = state.patch_objectives(
            [{"op": "add", "phase": "RECON", "title": "Subdomain enumeration"}]
        )
        assert changed == 0
        assert (
            sum(
                1
                for o in state.objective_queue
                if o["title"] == "Subdomain enumeration"
            )
            == 1
        )

    def test_remove_pending_objective(self):
        state = self._make_state()
        changed = state.patch_objectives(
            [{"op": "remove", "phase": "RECON", "title": "Port scan live hosts"}]
        )
        assert changed == 1
        titles = [o["title"] for o in state.objective_queue]
        assert "Port scan live hosts" not in titles

    def test_remove_done_objective_skipped(self):
        state = self._make_state()
        state.objective_queue[0]["status"] = "done"
        changed = state.patch_objectives(
            [{"op": "remove", "phase": "RECON", "title": "Subdomain enumeration"}]
        )
        assert changed == 0

    def test_modify_renames_title(self):
        state = self._make_state()
        changed = state.patch_objectives(
            [
                {
                    "op": "modify",
                    "phase": "RECON",
                    "title": "Port scan live hosts",
                    "new_title": "Full port scan with service detection",
                }
            ]
        )
        assert changed == 1
        titles = [o["title"] for o in state.objective_queue]
        assert "Full port scan with service detection" in titles
        assert "Port scan live hosts" not in titles

    def test_done_marks_objective_complete(self):
        state = self._make_state()
        changed = state.patch_objectives(
            [{"op": "done", "phase": "RECON", "title": "Subdomain enumeration"}]
        )
        assert changed == 1
        obj = next(
            o for o in state.objective_queue if o["title"] == "Subdomain enumeration"
        )
        assert obj["status"] == "done"

    def test_reorder_moves_objective(self):
        state = self._make_state()
        # Move "Port scan live hosts" to after "Prioritize injection points"
        changed = state.patch_objectives(
            [
                {
                    "op": "reorder",
                    "phase": "RECON",
                    "title": "Port scan live hosts",
                    "after_title": "Prioritize injection points",
                }
            ]
        )
        assert changed == 1
        titles = [o["title"] for o in state.objective_queue]
        idx_moved = titles.index("Port scan live hosts")
        idx_anchor = titles.index("Prioritize injection points")
        assert idx_moved == idx_anchor + 1

    def test_multiple_ops_in_one_call(self):
        state = self._make_state()
        changed = state.patch_objectives(
            [
                {"op": "add", "phase": "RECON", "title": "New obj A"},
                {"op": "done", "phase": "RECON", "title": "Subdomain enumeration"},
                {
                    "op": "remove",
                    "phase": "ANALYSIS",
                    "title": "Prioritize injection points",
                },
            ]
        )
        assert changed == 3

    def test_empty_ops_returns_zero(self):
        state = self._make_state()
        assert state.patch_objectives([]) == 0


# ---------------------------------------------------------------------------
# Feature 3: XML build_focus_context
# ---------------------------------------------------------------------------


class TestXMLFocusContext:
    """build_focus_context() now emits semantic XML."""

    def _make_state_with_data(self):
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        state.objective_queue = [
            {
                "phase": "RECON",
                "title": "Scan subdomains",
                "status": "pending",
                "priority": 80,
            },
        ]
        state.evidence_log = [
            {
                "phase": "RECON",
                "source_tool": "nmap",
                "summary": "Port 443 open",
                "confidence": 0.9,
                "severity": 2,
                "artifact": None,
                "tags": [],
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ]
        return state

    def test_output_starts_with_objective_focus_xml(self):
        state = self._make_state_with_data()
        ctx = state.build_focus_context("RECON")
        assert ctx.startswith("<objective_focus")

    def test_output_ends_with_closing_tag(self):
        state = self._make_state_with_data()
        ctx = state.build_focus_context("RECON")
        assert "</objective_focus>" in ctx

    def test_phase_attribute_in_tag(self):
        state = self._make_state_with_data()
        ctx = state.build_focus_context("RECON")
        assert 'phase="RECON"' in ctx

    def test_pending_objectives_section(self):
        state = self._make_state_with_data()
        ctx = state.build_focus_context("RECON")
        assert "<pending_objectives>" in ctx
        assert "Scan subdomains" in ctx

    def test_recent_evidence_section(self):
        state = self._make_state_with_data()
        ctx = state.build_focus_context("RECON")
        assert "<recent_evidence>" in ctx
        assert "Port 443 open" in ctx

    def test_action_required_section(self):
        state = self._make_state_with_data()
        ctx = state.build_focus_context("RECON")
        assert "<action_required>" in ctx

    def test_empty_state_returns_empty_string(self):
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        assert state.build_focus_context("RECON") == ""


# ---------------------------------------------------------------------------
# Feature 4: Mentor Supervision
# ---------------------------------------------------------------------------


class TestMentorSupervision:
    """_build_mentor_analysis() generates targeted post-tool XML analysis."""

    def test_mentor_output_is_xml(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        agent_loop.state.evidence_log = [
            {
                "phase": "ANALYSIS",
                "source_tool": "sqlmap",
                "summary": "SQLi in login",
                "confidence": 0.9,
                "severity": 5,
                "artifact": None,
                "tags": [],
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ]
        msg = agent_loop._build_mentor_analysis(
            current_phase=PipelinePhase.ANALYSIS,
            tool_name="sqlmap",
            evidence_added=True,
        )
        assert "<mentor_analysis" in msg
        assert "</mentor_analysis>" in msg

    def test_mentor_has_progress_assessment(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        agent_loop.state.evidence_log = [
            {
                "phase": "ANALYSIS",
                "source_tool": "nmap",
                "summary": "Port open",
                "confidence": 0.8,
                "severity": 2,
                "artifact": None,
                "tags": [],
                "iteration": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ]
        msg = agent_loop._build_mentor_analysis(
            current_phase=PipelinePhase.ANALYSIS,
            tool_name="nmap",
            evidence_added=True,
        )
        assert "<progress_assessment>" in msg

    def test_mentor_has_next_steps(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        agent_loop.state.evidence_log = []
        agent_loop.state.objective_queue = [
            {
                "phase": "ANALYSIS",
                "title": "Test for SQLi",
                "status": "pending",
                "priority": 80,
            }
        ]
        msg = agent_loop._build_mentor_analysis(
            current_phase=PipelinePhase.ANALYSIS,
            tool_name="httpx",
            evidence_added=False,
        )
        assert "<next_steps>" in msg
        assert "Test for SQLi" in msg

    def test_mentor_no_evidence_shows_issue(self, agent_loop):
        from airecon.proxy.agent.pipeline import PipelinePhase

        agent_loop.state.evidence_log = []
        msg = agent_loop._build_mentor_analysis(
            current_phase=PipelinePhase.EXPLOIT,
            tool_name="sqlmap",
            evidence_added=False,
        )
        assert "<identified_issues>" in msg

    def test_mentor_tool_call_count_starts_zero(self, agent_loop):
        # Starts at 0, incremented per-tool (inside tool loop) not per-iteration
        assert agent_loop._mentor_tool_call_count == 0
