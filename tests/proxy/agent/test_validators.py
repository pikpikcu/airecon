import pytest
from airecon.proxy.agent.validators import _ValidatorMixin


class DummyTestAgent(_ValidatorMixin):
    pass


@pytest.fixture
def validator():
    return DummyTestAgent()


def test_validator_execute(validator):
    # Empty commands block
    valid, msg = validator._validate_tool_args("execute", {"command": ""})
    assert not valid

    # Overly long commands block
    long_cmd = "a" * 25000
    valid, msg = validator._validate_tool_args(
        "execute", {"command": long_cmd})
    assert not valid

    # Good command
    valid, msg = validator._validate_tool_args(
        "execute", {"command": "ls -la"})
    assert valid


def test_validator_browser_actions(validator):
    # Invalid Action
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "fly"})
    assert not valid

    # Missing kwargs on navigation
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "goto", "url": ""})
    assert not valid

    # Valid navigation
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "goto", "url": "http://1.com"})
    assert valid


def test_validator_browser_action_nonstring_args(validator):
    """Non-string LLM args must not crash with AttributeError/TypeError."""
    # action=dict would cause TypeError: unhashable type before fix
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": {"evil": "dict"}})
    assert not valid
    assert msg is not None

    # action=int same issue
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": 42})
    assert not valid

    # url=dict would cause AttributeError on .strip() before fix
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "goto", "url": {"evil": "dict"}})
    assert not valid

    # text=dict for "type" action — was only checking is None, not isinstance
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "type", "text": {"evil": "dict"}})
    assert not valid

    # text=None still rejected
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "type", "text": None})
    assert not valid

    # text="" (empty string) — valid (clearing a field)
    valid, msg = validator._validate_tool_args(
        "browser_action", {"action": "type", "text": ""})
    assert valid


def test_validator_read_file(validator):
    # Negative Offset
    valid, msg = validator._validate_tool_args(
        "read_file", {"path": "test.txt", "offset": -5})
    assert not valid

    # Good constraints
    valid, msg = validator._validate_tool_args(
        "read_file", {"path": "test.txt", "offset": 10, "limit": 100})
    assert valid


def test_validator_report_nonstring_args(validator):
    """Non-string args to create_vulnerability_report must not crash."""
    # poc_script_code=dict would AttributeError on .strip() before fix
    valid, msg = validator._validate_tool_args("create_vulnerability_report", {
        "poc_script_code": {"evil": "dict"},
        "poc_description": "desc",
        "title": "title",
        "technical_analysis": "tech",
    })
    assert not valid
    assert msg is not None

    # title=int
    valid, msg = validator._validate_tool_args("create_vulnerability_report", {
        "poc_script_code": "curl http://x",
        "poc_description": "desc",
        "title": 42,
        "technical_analysis": "tech",
    })
    assert not valid


def test_validator_report_rejections(validator):
    # Missing POC indicators
    args = {
        "title": "A Very Detailed Bug Triggered",
        "poc_script_code": "I found it by clicking.",
        "poc_description": "We clicked hard and it crashed" + (" " * 80),
        "technical_analysis": "The system died completely" + (" " * 80)
    }

    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report", args.copy())
    assert not valid
    assert "too short" in msg

    # Needs HTTP Evidence on non-CTF
    args_http = args.copy()
    args_http["poc_script_code"] = "curl -X GET http://example.com/api/test" + \
        ("." * 50)
    args_http["poc_description"] = "We clicked hard and it crashed" + \
        ("." * 80)
    args_http["technical_analysis"] = "The system died completely" + ("." * 80)
    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report", args_http)
    assert not valid
    assert "HTTP response evidence" in msg

    # Needs to be a real URL (If HTTP Evidence is provided)
    args_url = args.copy()
    args_url["poc_description"] = "We sent the payload and observed HTTP 200" + \
        ("." * 80)
    args_url["poc_script_code"] = "python3 exploit.py" + \
        ("." * 50)  # No HTTP or curl present
    args_url["technical_analysis"] = "The system died completely" + ("." * 80)
    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report", args_url)
    assert not valid
    assert "actual target URL" in msg

    # Valid
    args_valid = args.copy()
    args_valid["poc_script_code"] = "curl -X GET http://example.com/api/test" + \
        ("." * 50)
    args_valid["poc_description"] = "We sent the payload and observed HTTP 200 containing user data." + \
        ("." * 80)
    args_valid["technical_analysis"] = "The system died completely" + \
        ("." * 80)
    # The regex explicitly wants the word `python`, `curl` or `http` in the POC code,
    # and a formatted status code in the description.
    valid, msg = validator._validate_tool_args(
        "create_vulnerability_report", args_valid)
    if not valid:
        print(f"FAILED REASON: {msg}")
    assert valid


def test_validator_create_file(validator):
    # Block writing reports to markdown using create_file
    args = {"path": "vuln_report.md", "content": "# Finding"}
    valid, msg = validator._validate_tool_args("create_file", args)
    assert not valid
    assert "FORBIDDEN" in msg

    # Writing normal tools is fine
    args = {"path": "script.py", "content": "print('hello')"}
    valid, msg = validator._validate_tool_args("create_file", args)
    assert valid
