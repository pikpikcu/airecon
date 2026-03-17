# AIRecon

<div class="hero" markdown>

![AIRecon Logo](assets/logo.png)

# AIRecon

**AI-Powered Autonomous Penetration Testing Agent**

[![version](https://img.shields.io/badge/version-v0.1.6--beta-red.svg)](https://github.com/pikpikcu/airecon/releases)
[![python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![llm](https://img.shields.io/badge/LLM-Ollama%20(local)-orange.svg)](https://ollama.com/)
[![license](https://img.shields.io/badge/LICENSE-MIT-green.svg)](https://github.com/pikpikcu/airecon/blob/main/LICENSE)

</div>

---

AIRecon is an autonomous penetration testing agent that combines a self-hosted **Ollama LLM** with a **Kali Linux Docker sandbox**, native **Caido proxy integration**, a structured **RECON → ANALYSIS → EXPLOIT → REPORT pipeline**, and a real-time **Textual TUI** — completely offline, no API keys required.

## Why AIRecon?

Commercial API-based models (OpenAI GPT-4, Claude, Gemini) become prohibitively expensive for recursive, autonomous recon workflows that can require thousands of LLM calls per session.

AIRecon is built **100% for local, private operation**.

| Feature | AIRecon | Cloud-based agents |
|---------|---------|-------------------|
| API keys required | **No** | Yes |
| Target data sent to cloud | **No** | Yes |
| Works offline | **Yes** | No |
| Caido integration | **Native** | None |
| Session resume | **Yes** | Varies |
| VRAM crash recovery | **4-tier auto** | N/A |

---

## Core Features

<div class="feature-grid" markdown>

<div class="feature-card" markdown>
### Pipeline Engine
Structured 4-phase state machine: **RECON → ANALYSIS → EXPLOIT → REPORT**. Auto-transitions based on real findings, not iteration counts.
</div>

<div class="feature-card" markdown>
### Ollama Stability
Multi-level VRAM crash recovery (4 tiers), proactive context monitoring at ≥80%, dynamic compression, OOM-safe summarization.
</div>

<div class="feature-card" markdown>
### Exploration Engine
Anti-stagnation with temperature boost, tool diversity tracking, same-tool streak detection, per-phase exploration directives.
</div>

<div class="feature-card" markdown>
### Docker Sandbox
Full Kali Linux container — 80+ preinstalled tools: subfinder, nuclei, sqlmap, dalfox, ffuf, semgrep, Playwright, and more.
</div>

<div class="feature-card" markdown>
### Skills System
57 built-in skill files loaded on-demand. Extended by **[airecon-skills](https://github.com/pikpikcu/airecon-skills)** community library.
</div>

<div class="feature-card" markdown>
### Caido Native
5 built-in tools: list, replay, automate (`§FUZZ§`), findings, scope. Connects at `127.0.0.1:48080` automatically.
</div>

<div class="feature-card" markdown>
### Browser Automation
Headless Chromium via Playwright. Full auth support: form login, TOTP/2FA, OAuth, cookie injection, state persistence.
</div>

<div class="feature-card" markdown>
### Session Memory
All findings persisted to disk. Resume any session with `airecon start --session <id>`. Tested endpoints memory prevents re-testing after context truncation.
</div>

</div>

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/pikpikcu/airecon.git
cd airecon
./install.sh

# 2. Pull a model (minimum 30B parameters)
ollama pull qwen3:32b

# 3. Start
airecon start
```

!!! tip "Recommended model"
    **qwen3:32b** (20 GB VRAM) is the recommended minimum. For best quality use **qwen3.5:122b** (48+ GB VRAM).

!!! warning "Minimum model size"
    Models below **30B parameters** frequently hallucinate tool output, ignore scope rules, and produce incomplete function calls. `qwen3:14b` is **not recommended** for real engagements.

---

## Pipeline

```
RECON ──────────────────────► ANALYSIS
  Enumerate attack surface       Identify injection points
  subfinder, nmap, katana,       semgrep, browser, httpx,
  httpx, ffuf, web_search        technology fingerprinting
         │                              │
         └──────────────────────────────┘
                                        │
                               EXPLOIT  ▼
                               Confirm vulnerabilities
                               quick_fuzz, advanced_fuzz,
                               sqlmap, dalfox, spawn_agent
                                        │
                               REPORT   ▼
                               Document all findings
                               create_vulnerability_report
```

Each phase has specific objectives, recommended tools, and automatic transition criteria. Phase enforcement is **soft** — the agent is guided but never blocked.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](installation.md) | Hardware requirements, step-by-step setup, troubleshooting |
| [Configuration](configuration.md) | All config options with defaults, presets, and env var overrides |
| [Features](features.md) | Deep dive into every feature — pipeline, browser auth, fuzzing, skills, anti-context-loss |
| [Tools Reference](tools.md) | Complete reference for all 31 native tools |
| [Creating Skills](development/creating_skills.md) | Write your own skill files, use the airecon-skills community library |
| [Changelog](changelog.md) | Version history and release notes |

---

## Community

- **GitHub**: [github.com/pikpikcu/airecon](https://github.com/pikpikcu/airecon)
- **Skills Library**: [github.com/pikpikcu/airecon-skills](https://github.com/pikpikcu/airecon-skills)
- **Issues / Bug Reports**: [GitHub Issues](https://github.com/pikpikcu/airecon/issues)

---

!!! danger "Legal Disclaimer"
    AIRecon is built strictly for **educational purposes, ethical hacking, and authorized security assessments**. Any actions related to the material in this tool are solely your responsibility. **Do not use this tool on systems you do not own or have explicit permission to test.**
