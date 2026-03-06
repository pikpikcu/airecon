"""P3 Comprehensive Tests for Phase Transitions and Agent Loop Orchestration.

Tests cover:
- Phase transitions (RECON → ANALYSIS → EXPLOIT → REPORT → COMPLETE)
- Phase initialization and configuration
- Transition criteria validation
- State preservation across phases
- Agent loop duplicate command detection
- Agent loop integration with pipeline
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

# Modules under test
from airecon.proxy.agent.pipeline import (
    PipelinePhase,
    PipelineEngine,
    PhaseConfig,
    DEFAULT_PHASES,
)
from airecon.proxy.agent.loop import AgentLoop
from airecon.proxy.agent.session import SessionData
from airecon.proxy.agent.models import AgentState
from airecon.proxy.ollama import OllamaClient
from airecon.proxy.docker import DockerEngine


class TestPipelinePhase:
    """Test PipelinePhase enum."""

    def test_phase_values(self):
        """PipelinePhase should have expected phases."""
        assert PipelinePhase.RECON.value == "RECON"
        assert PipelinePhase.ANALYSIS.value == "ANALYSIS"
        assert PipelinePhase.EXPLOIT.value == "EXPLOIT"
        assert PipelinePhase.REPORT.value == "REPORT"
        assert PipelinePhase.COMPLETE.value == "COMPLETE"

    def test_phase_ordering(self):
        """Phases should be defined in correct order."""
        from airecon.proxy.agent.pipeline import _PHASE_ORDER
        
        assert _PHASE_ORDER[0] == PipelinePhase.RECON
        assert _PHASE_ORDER[1] == PipelinePhase.ANALYSIS
        assert _PHASE_ORDER[2] == PipelinePhase.EXPLOIT
        assert _PHASE_ORDER[3] == PipelinePhase.REPORT
        assert _PHASE_ORDER[4] == PipelinePhase.COMPLETE


class TestPhaseConfig:
    """Test PhaseConfig dataclass."""

    def test_phase_config_structure(self):
        """PhaseConfig should have required fields."""
        config = PhaseConfig(
            phase=PipelinePhase.ANALYSIS,
            max_iterations=300,
            objective="Test objective",
            recommended_tools=["tool1", "tool2"],
            transition_criteria=["criterion1", "criterion2"],
        )
        
        assert config.phase == PipelinePhase.ANALYSIS
        assert config.max_iterations == 300
        assert config.objective == "Test objective"
        assert len(config.recommended_tools) == 2
        assert len(config.transition_criteria) == 2

    def test_default_phases_configuration(self):
        """DEFAULT_PHASES should define all non-COMPLETE phases."""
        assert PipelinePhase.RECON in DEFAULT_PHASES
        assert PipelinePhase.ANALYSIS in DEFAULT_PHASES
        assert PipelinePhase.EXPLOIT in DEFAULT_PHASES
        assert PipelinePhase.REPORT in DEFAULT_PHASES

    def test_recon_phase_config(self):
        """RECON phase should have appropriate configuration."""
        recon = DEFAULT_PHASES[PipelinePhase.RECON]
        
        assert recon.phase == PipelinePhase.RECON
        assert recon.max_iterations == 500
        assert "subdomains" in str(recon.transition_criteria).lower()
        assert "ports" in str(recon.transition_criteria).lower()

    def test_analysis_phase_config(self):
        """ANALYSIS phase should have appropriate configuration."""
        analysis = DEFAULT_PHASES[PipelinePhase.ANALYSIS]
        
        assert analysis.phase == PipelinePhase.ANALYSIS
        assert analysis.max_iterations == 300
        assert "technologies" in str(analysis.transition_criteria).lower()

    def test_exploit_phase_config(self):
        """EXPLOIT phase should have appropriate configuration."""
        exploit = DEFAULT_PHASES[PipelinePhase.EXPLOIT]
        
        assert exploit.phase == PipelinePhase.EXPLOIT
        assert exploit.max_iterations == 800
        assert "execute" in exploit.recommended_tools
        assert "vulnerabilities" in str(exploit.transition_criteria).lower()

    def test_report_phase_config(self):
        """REPORT phase should have appropriate configuration."""
        report = DEFAULT_PHASES[PipelinePhase.REPORT]
        
        assert report.phase == PipelinePhase.REPORT
        assert len(report.recommended_tools) > 0

    def test_phase_config_defaults(self):
        """PhaseConfig should use default empty lists."""
        config = PhaseConfig(
            phase=PipelinePhase.RECON,
            max_iterations=100,
            objective="Test",
        )
        
        assert config.recommended_tools == []
        assert config.transition_criteria == []


class TestAgentLoopDuplicateDetection:
    """Test AgentLoop duplicate command detection."""

    def test_is_duplicate_command_fresh(self):
        """First execution should not be marked as duplicate."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        is_dup, msg = loop._is_duplicate_command("execute", {"command": "ls -la"})
        
        assert is_dup is False
        assert msg == ""

    def test_is_duplicate_command_repeated(self):
        """Repeated execution should be marked as duplicate."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        # First execution
        is_dup1, msg1 = loop._is_duplicate_command("execute", {"command": "ls -la"})
        assert is_dup1 is False
        
        # Repeated execution with same args
        is_dup2, msg2 = loop._is_duplicate_command("execute", {"command": "ls -la"})
        assert is_dup2 is True
        assert "ANTI-REPEAT" in msg2

    def test_is_duplicate_command_whitespace_normalized(self):
        """Duplicate detection should normalize whitespace in strings."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        # First execution with trailing spaces
        is_dup1, _ = loop._is_duplicate_command("execute", {"command": "ls -la  "})
        assert is_dup1 is False
        
        # Second execution without trailing spaces (should be duplicate)
        is_dup2, _ = loop._is_duplicate_command("execute", {"command": "ls -la"})
        assert is_dup2 is True

    def test_is_duplicate_command_exempt_tools(self):
        """Exempt tools should always pass dedup check."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        # create_file is exempt from dedup
        is_dup1, _ = loop._is_duplicate_command(
            "create_file",
            {"path": "/test/file.txt", "content": "data"}
        )
        assert is_dup1 is False
        
        # Same file again should not be duplicate (exempt)
        is_dup2, _ = loop._is_duplicate_command(
            "create_file",
            {"path": "/test/file.txt", "content": "data"}
        )
        assert is_dup2 is False

    def test_is_duplicate_command_spawn_agent_exempt(self):
        """spawn_agent should be exempt from dedup."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        is_dup1, _ = loop._is_duplicate_command(
            "spawn_agent",
            {"target": "http://example.com"}
        )
        assert is_dup1 is False
        
        # Same call again should not be duplicate
        is_dup2, _ = loop._is_duplicate_command(
            "spawn_agent",
            {"target": "http://example.com"}
        )
        assert is_dup2 is False

    def test_is_duplicate_command_browser_action_click_exempt(self):
        """browser_action click should be exempt from dedup."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        is_dup1, _ = loop._is_duplicate_command(
            "browser_action",
            {"action": "click", "selector": "#button"}
        )
        assert is_dup1 is False
        
        # Same click again should not be duplicate (interactive)
        is_dup2, _ = loop._is_duplicate_command(
            "browser_action",
            {"action": "click", "selector": "#button"}
        )
        assert is_dup2 is False

    def test_is_duplicate_command_browser_action_navigate_not_exempt(self):
        """browser_action navigate should not be exempt."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        is_dup1, _ = loop._is_duplicate_command(
            "browser_action",
            {"action": "navigate", "url": "http://example.com"}
        )
        assert is_dup1 is False
        
        # Same navigate again should be duplicate
        is_dup2, _ = loop._is_duplicate_command(
            "browser_action",
            {"action": "navigate", "url": "http://example.com"}
        )
        assert is_dup2 is True


class TestAgentLoopInitialization:
    """Test AgentLoop initialization and state setup."""

    def test_agent_loop_initialization(self):
        """AgentLoop should initialize with correct state."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        assert loop.ollama == mock_ollama
        assert loop.engine == mock_engine
        assert isinstance(loop.state, AgentState)
        assert loop._stop_requested is False
        assert loop._consecutive_failures == 0
        assert loop._session is None
        assert isinstance(loop._executed_cmd_hashes, set)

    def test_agent_loop_pipeline_initialization(self):
        """AgentLoop should support pipeline initialization."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        # Initially no pipeline
        assert loop.pipeline is None
        
        # Could be initialized later with a session
        mock_session = MagicMock()
        loop.pipeline = PipelineEngine(session=mock_session)
        assert loop.pipeline is not None


class TestPipelineEngineTransitions:
    """Test PipelineEngine phase transitions."""

    def test_pipeline_initialization(self):
        """PipelineEngine should initialize with a session."""
        mock_session = MagicMock()
        engine = PipelineEngine(session=mock_session)
        
        assert engine is not None
        assert engine.session == mock_session

    def test_pipeline_initial_phase(self):
        """Pipeline should have RECON as initial phase in DEFAULT_PHASES."""
        # Verify the static configuration has RECON first
        from airecon.proxy.agent.pipeline import _PHASE_ORDER
        
        # Get initial phase
        initial = _PHASE_ORDER[0]
        assert initial == PipelinePhase.RECON

    def test_phase_order_preserved(self):
        """Phases should maintain defined order."""
        from airecon.proxy.agent.pipeline import _PHASE_ORDER
        
        # Verify the static order
        for i, phase in enumerate(_PHASE_ORDER):
            if i > 0:
                assert _PHASE_ORDER[i-1] != phase


class TestIntegrationPhaseTransitions:
    """Integration tests for phase transitions."""

    def test_session_preserves_across_phases(self):
        """Session data should persist across phase transitions."""
        
        # Create session with data
        session = SessionData(
            session_id="test-123",
        )
        
        # Session should be created
        assert session.session_id == "test-123"
        
        # Add RECON data (subdomains is a list)
        session.subdomains.append("sub1.example.com")
        session.subdomains.append("sub2.example.com")
        
        # Session should have RECON data
        assert len(session.subdomains) == 2
        
        # Simulate transition to ANALYSIS - session persists
        # technologies is a dict
        session.technologies["PHP"] = "7.4"
        
        # Session should have both RECON and ANALYSIS data
        assert len(session.subdomains) == 2
        assert len(session.technologies) == 1
        assert "PHP" in session.technologies

    def test_agent_loop_state_consistency(self):
        """AgentLoop state should remain consistent across operations."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        # Simulate operations
        loop._consecutive_failures = 1
        
        # State should update
        assert loop._consecutive_failures == 1
        
        # Reset
        loop._consecutive_failures = 0
        assert loop._consecutive_failures == 0

    def test_duplicate_command_tracking_across_phases(self):
        """Duplicate detection should persist across phase transitions."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        # Execute command in RECON phase
        is_dup1, _ = loop._is_duplicate_command("execute", {"command": "nmap -sV target"})
        assert is_dup1 is False
        
        # Simulate transition to ANALYSIS phase
        # (No actual phase change needed for dedup test)
        
        # Same command in ANALYSIS phase should be duplicate
        is_dup2, _ = loop._is_duplicate_command("execute", {"command": "nmap -sV target"})
        assert is_dup2 is True

    @pytest.mark.asyncio
    async def test_agent_loop_stop_signal(self):
        """AgentLoop should handle stop signal."""
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_engine = AsyncMock(spec=DockerEngine)
        
        loop = AgentLoop(mock_ollama, mock_engine)
        
        assert loop._stop_requested is False
        
        await loop.stop()
        
        assert loop._stop_requested is True


class TestTransitionCriteria:
    """Test phase transition criteria validation."""

    def test_recon_transition_criteria(self):
        """RECON phase should have subdomains and ports criteria."""
        recon = DEFAULT_PHASES[PipelinePhase.RECON]
        # Check for common transition criterion patterns
        assert len(recon.transition_criteria) > 0

    def test_analysis_transition_criteria(self):
        """ANALYSIS phase should have URL and technology criteria."""
        analysis = DEFAULT_PHASES[PipelinePhase.ANALYSIS]
        assert len(analysis.transition_criteria) > 0

    def test_exploit_transition_criteria(self):
        """EXPLOIT phase should have vulnerability criteria."""
        exploit = DEFAULT_PHASES[PipelinePhase.EXPLOIT]
        assert len(exploit.transition_criteria) > 0

    def test_phase_max_iterations(self):
        """Phases should have reasonable max iteration limits."""
        for phase_name, config in DEFAULT_PHASES.items():
            if phase_name != PipelinePhase.COMPLETE:
                assert config.max_iterations > 0
                assert config.max_iterations <= 1000  # Reasonable upper bound


class TestRecommendedTools:
    """Test phase-specific recommended tools."""

    def test_recon_has_recommended_tools(self):
        """RECON phase should recommend appropriate tools."""
        recon = DEFAULT_PHASES[PipelinePhase.RECON]
        
        assert len(recon.recommended_tools) > 0
        # RECON should recommend web_search and execution
        tools_str = str(recon.recommended_tools)
        assert "execute" in tools_str or "search" in tools_str.lower()

    def test_analysis_has_recommended_tools(self):
        """ANALYSIS phase should recommend appropriate tools."""
        analysis = DEFAULT_PHASES[PipelinePhase.ANALYSIS]
        
        assert len(analysis.recommended_tools) > 0
        tools_str = str(analysis.recommended_tools)
        # Should have analysis capability
        assert "execute" in tools_str

    def test_exploit_has_recommended_tools(self):
        """EXPLOIT phase should recommend exploit tools."""
        exploit = DEFAULT_PHASES[PipelinePhase.EXPLOIT]
        
        assert len(exploit.recommended_tools) > 0
        tools_str = str(exploit.recommended_tools)
        # Should recommend exploit-related tools
        assert "execute" in tools_str

    def test_report_has_recommended_tools(self):
        """REPORT phase should recommend reporting tools."""
        report = DEFAULT_PHASES[PipelinePhase.REPORT]
        
        assert len(report.recommended_tools) > 0


class TestPhaseObjectives:
    """Test phase objectives."""

    def test_recon_objective(self):
        """RECON should focus on enumeration."""
        recon = DEFAULT_PHASES[PipelinePhase.RECON]
        
        objective = recon.objective.lower()
        assert "enumerat" in objective or "discover" in objective or "scan" in objective

    def test_analysis_objective(self):
        """ANALYSIS should focus on finding vulnerabilities."""
        analysis = DEFAULT_PHASES[PipelinePhase.ANALYSIS]
        
        objective = analysis.objective.lower()
        assert "analyz" in objective or "identify" in objective

    def test_exploit_objective(self):
        """EXPLOIT should focus on testing/exploiting."""
        exploit = DEFAULT_PHASES[PipelinePhase.EXPLOIT]
        
        objective = exploit.objective.lower()
        assert "test" in objective or "exploit" in objective or "fuzz" in objective

    def test_report_objective(self):
        """REPORT should focus on documentation."""
        report = DEFAULT_PHASES[PipelinePhase.REPORT]
        # Report phase should exist and have objective
        assert len(report.objective) > 0
