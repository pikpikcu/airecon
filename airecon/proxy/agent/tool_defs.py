import json
from pathlib import Path

from ..mcp import mcp_llm_tools

_DATASETS_DIR = Path.home() / ".airecon" / "datasets"

# Tools that require optional components — excluded when component is absent
_CONDITIONAL_TOOLS: dict[str, bool] = {}


def _datasets_installed() -> bool:
    try:
        return any(_DATASETS_DIR.glob("*.db"))
    except OSError:
        return False


def get_tool_definitions() -> list[dict]:
    schema_path = Path(__file__).parent.parent / "data" / "tools.json"
    with open(schema_path, "r") as f:
        tools = json.load(f)

    # Exclude dataset_search when no datasets are installed — prevents LLM
    # from calling a tool that will always return an error
    if not _datasets_installed():
        tools = [
            t for t in tools
            if t.get("function", {}).get("name") != "dataset_search"
        ]

    tools.extend(mcp_llm_tools(max_servers=10))
    return tools
