# AIRecon Documentation

Welcome to the AIRecon documentation.

## Guides

- [Features & Capabilities](features.md) — Core feature overview, Docker sandbox, pipeline phases, multi-agent system, anti-hallucination controls
- [Tools Reference](tools.md) — Complete reference for native tools, Docker sandbox tools, and dynamic MCP tools
- [Installation & Setup](installation.md) — Step-by-step installation guide with hardware requirements
- [Configuration Reference](configuration.md) — All config options with examples, presets, and environment variable overrides
- [Stability & Quality Status](stability.md) — Current validation snapshot, blockers, and realistic stability criteria

## Extending AIRecon

- [Adding Custom Skills](development/creating_skills.md) — Create Markdown knowledge bases to teach the agent new attack techniques or technology-specific procedures.

## Quick Links

| Task | Where to look |
|------|--------------|
| Install for the first time | [Installation Guide](installation.md) |
| Change the LLM model | [configuration.md → openai_model](configuration.md#openai_model) |
| Tune performance / VRAM | [configuration.md → LLM Backend Settings](configuration.md#3-llm-backend-settings) |
| Understand the pipeline phases | [features.md → Pipeline Phases](features.md#pipeline-phases) |
| Connect to Caido | [features.md → Caido Integration](features.md#caido-integration) |
| Set up browser auth | [features.md → Browser Authentication](features.md#browser-authentication) |
| Check current stability status | [stability.md](stability.md) |
| Add your own skill | [Creating Skills](development/creating_skills.md) |
| Troubleshoot startup issues | [Installation → Troubleshooting](installation.md#11-troubleshooting) |

## Community

Found a bug or want to contribute? [GitHub Issues](https://github.com/pikpikcu/airecon/issues)
