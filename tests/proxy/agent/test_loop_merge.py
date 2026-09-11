"""Tests for loop.py output merge functionality."""

from unittest.mock import MagicMock

import pytest

from airecon.proxy.agent.loop import AgentLoop

pytestmark = pytest.mark.skip(reason="output merge feature not yet implemented")


@pytest.fixture
def loop_for_merge(mocker, tmp_path):
    """Create AgentLoop instance with mocked dependencies for merge testing."""
    llm_mock = MagicMock()
    llm_mock.chat_stream = MagicMock()

    engine_mock = MagicMock()
    engine_mock.discover_tools = MagicMock(return_value=[])
    engine_mock.tools_to_llm_format = MagicMock(return_value=[])

    # Mock workspace
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with mocker.patch("airecon.proxy.agent.loop.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = 10
        cfg.llm_context_window_small = 16384
        mock_cfg.return_value = cfg

        agent = AgentLoop(llm=llm_mock, engine=engine_mock)
        agent.state = MagicMock()
        agent.state.active_target = "test-target"

        # Create target directory
        target_dir = workspace / "test-target" / "output"
        target_dir.mkdir(parents=True)

        # Mock workspace root
        mocker.patch(
            "airecon.proxy.agent.loop.get_workspace_root", return_value=workspace
        )

        return agent


class TestApplyOutputMerge:
    """Test _apply_output_merge for file dedup and sorting."""

    def test_merge_adds_new_lines(self, loop_for_merge, tmp_path):
        """Merge should add new lines from old output to new file."""
        workspace = tmp_path / "workspace"
        output_file = workspace / "test-target" / "output" / "subdomains.txt"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write initial content
        output_file.write_text("example.com\nold.com\n")

        # Simulate pre-saved old lines (what _pending_output_merges would have)
        old_lines = ["example.com", "new1.com", "new2.com"]
        loop_for_merge._pending_output_merges[str(output_file)] = old_lines

        # Write new content (simulating what command produced)
        output_file.write_text("example.com\nold.com\n")

        # Apply merge - command must have -o flag for _get_command_output_file to find it
        arguments = {"command": f"subfinder -d example.com -o {output_file}"}
        loop_for_merge._apply_output_merge(arguments, success=True)

        # Check merged result
        merged = output_file.read_text().splitlines()
        assert "example.com" in merged
        assert "old.com" in merged
        assert "new1.com" in merged
        assert "new2.com" in merged
        # Should be sorted
        assert merged == sorted(set(merged))

    def test_merge_skips_on_failure(self, loop_for_merge):
        """Merge should be skipped on tool execution failure."""
        arguments = {"command": "subfinder -d example.com -o /tmp/test.txt"}
        # Pre-populate pending merges
        loop_for_merge._pending_output_merges["/tmp/test.txt"] = ["old"]

        # Call with success=False
        loop_for_merge._apply_output_merge(arguments, success=False)

        # Pending merges should still be there (not popped)
        assert len(loop_for_merge._pending_output_merges) == 1

    def test_merge_skips_no_output_file(self, loop_for_merge):
        """Merge should skip when no output file specified."""
        arguments = {"command": "echo hello"}  # No -o flag

        loop_for_merge._apply_output_merge(arguments, success=True)

        # Should not crash, should be no-op

    def test_merge_skips_file_not_exists(self, loop_for_merge, tmp_path):
        """Merge should skip when output file doesn't exist."""
        fake_path = tmp_path / "nonexistent.txt"

        arguments = {"command": f"subfinder -d example.com -o {fake_path}"}
        loop_for_merge._pending_output_merges[str(fake_path)] = ["old"]

        loop_for_merge._apply_output_merge(arguments, success=True)

        # Should not crash, pending merges should be popped (because file doesn't exist)
        assert str(fake_path) not in loop_for_merge._pending_output_merges

    def test_merge_deduplicates(self, loop_for_merge, tmp_path):
        """Merge should deduplicate lines."""
        workspace = tmp_path / "workspace"
        output_file = workspace / "test-target" / "output" / "urls.txt"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Old lines with duplicates
        old_lines = ["http://a.com", "http://b.com", "http://a.com"]
        loop_for_merge._pending_output_merges[str(output_file)] = old_lines

        # New content with same duplicates
        output_file.write_text("http://a.com\nhttp://c.com\nhttp://b.com\n")

        arguments = {"command": f"katana -list urls.txt -o {output_file}"}
        loop_for_merge._apply_output_merge(arguments, success=True)

        merged = output_file.read_text().splitlines()
        # Should be deduplicated
        assert len(merged) == len(set(merged))
        assert "http://a.com" in merged
        assert "http://b.com" in merged
        assert "http://c.com" in merged
