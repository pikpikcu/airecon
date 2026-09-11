# AIRecon Installation Guide

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Set up an OpenAI-compatible LLM gateway](#2-set-up-an-openai-compatible-llm-gateway)
3. [Install AIRecon](#4-install-airecon)
4. [Configure PATH](#5-configure-path)
5. [Build the Docker Sandbox](#6-build-the-docker-sandbox)
6. [Verify the Installation](#7-verify-the-installation)
7. [First Run](#8-first-run)
8. [Updating AIRecon](#9-updating-airecon)
9. [Remote / hosted backend](#10-remote-ollama-setup)
10. [Optional: Install Datasets](#11-optional-install-datasets)
11. [Troubleshooting](#12-troubleshooting)

---

## 1. System Requirements

> **Model requirement:** AIRecon requires a model with **native tool calling** support. Model size and VRAM needs depend on the specific model, quantization, and context length.

### Baseline requirements
| Component | Baseline |
|-----------|---------|
| OS | Linux, macOS, WSL2 on Windows |
| Python | 3.12+ |
| Docker | 20.10+ |
| LLM backend | An OpenAI-compatible gateway reachable at `openai_base_url` (LiteLLM / vLLM / hosted; or a gateway → local Ollama). Model must support native tool calling. |
| Storage | 40+ GB free (Docker image + tools; plus model weights if running locally) |

### Model guidance
- Use the largest model you can run reliably within your VRAM budget.
- Smaller models can work for limited tasks, but reliability drops as size shrinks.
- Models below **8B** are not recommended for full engagements.

---

## 2. Set up an OpenAI-compatible LLM gateway

AIRecon talks to one **OpenAI-compatible** `/v1/chat/completions` endpoint. Pick whichever fits you — the rest of AIRecon is identical:

- **Local / offline** — run a local OpenAI-compatible gateway, vLLM, or LiteLLM on your machine. a local gateway (e.g. via a proxy) can serve a local Ollama, so you keep a fully private setup. Default base URL: `http://localhost:20128/v1`.
- **Hosted** — any OpenAI/Anthropic/Gemini-compatible gateway. You'll set `openai_api_key`.

You'll point AIRecon at it with three config keys (see step 8 and the [Configuration reference](configuration.md)):

```yaml
openai_base_url: "http://localhost:20128/v1"   # must include /v1
openai_api_key: ""                              # set if your gateway requires one
openai_model: "qwen3:8b"                         # any model your gateway exposes
```

> **Tool calling is required**; reasoning is auto-detected at runtime (no model-name list). For a local model, run it behind the gateway first and confirm `GET <base_url>/models` responds.

> **Small model caution:** local models below ~8B are not recommended for full engagements — expect more tool-call errors and hallucinations.

---

## 4. Install AIRecon

AIRecon uses [Poetry](https://python-poetry.org/) for dependency management and builds a Python wheel that is installed to your user path.

```bash
# 1. Clone the repository
git clone https://github.com/pikpikcu/airecon.git
cd airecon

# 2. Run the installer
./install.sh
```

### What `install.sh` does

1. **Checks for Poetry** — installs it via pip if missing
2. **Cleans previous installs** — removes old AIRecon versions to avoid conflicts
3. **Installs Python dependencies** — `poetry install` (reads `pyproject.toml`)
4. **Installs Playwright Chromium** — `poetry run playwright install chromium` (required for browser automation)
5. **Builds the wheel** — `poetry build` → creates `dist/airecon-*.whl`
6. **Installs to user site** — `pip install dist/airecon-*.whl --user` → binary at `~/.local/bin/airecon`

---

## 5. Configure PATH

The `airecon` command is installed to `~/.local/bin/`. If this is not in your PATH, the command will not be found.

```bash
# Check if it is already in PATH
which airecon

# If not found, add to your shell profile:

# For bash:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# For zsh:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify
airecon --version
```

---

## 6. Build the Docker Sandbox

The Docker sandbox is the Kali Linux execution environment where all shell commands run. You must build it before starting AIRecon.

```bash
cd airecon

# Build the sandbox image (takes 5–15 minutes on first build)
docker build -t airecon-sandbox airecon/containers/

# Verify the image exists
docker images | grep airecon-sandbox
```

> The sandbox includes: `nmap`, `naabu`, `masscan`, `subfinder`, `amass`, `httpx`, `nuclei`, `nikto`, `wapiti`, `ffuf`, `feroxbuster`, `sqlmap`, `dalfox`, `gau`, `waybackurls`, `katana`, `arjun`, full SecLists, FuzzDB, and 40+ more tools. It runs as user `pentester` with passwordless `sudo`.

If `docker_auto_build: true` is set in your config, AIRecon will attempt to build the image automatically at startup if it is not found. Manual build is more reliable.

---

## 7. Verify the Installation

Run this checklist after installing:

```bash
# 1. Check AIRecon version
airecon --version

# 2. Check the LLM gateway is reachable and lists your model
curl -s "${OPENAI_BASE_URL:-http://localhost:20128/v1}/models" | head

# 3. Check Docker image
docker images | grep airecon-sandbox

# 4. Test Playwright (should open and close Chromium silently)
python3 -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(); b.close(); p.stop(); print('Playwright OK')"

# 5. Check config file location
cat ~/.airecon/config.yaml 2>/dev/null || echo "Will be created on first run"
```

---

## 8. First Run

```bash
# Navigate to a working directory (workspace/ will be created here)
cd ~/pentest-projects/

# Start the TUI
airecon start
```

On first run:
- `~/.airecon/config.yaml` is created with default values
- The `workspace/` directory is created in your current working directory
- The Docker sandbox container is started

**Set the backend in config before starting** (required — `openai_base_url` and `openai_model` must be set):

```bash
nano ~/.airecon/config.yaml
```
```yaml
openai_base_url: "http://localhost:20128/v1"   # your gateway, must include /v1
openai_api_key: ""                              # set if the gateway requires one
openai_model: "qwen3:8b"                         # e.g. claude-sonnet-4 / gpt-4o / a local model
```

See [Configuration Reference](configuration.md) for all options.

---

## 9. Updating AIRecon

```bash
cd airecon

# Pull latest changes
git pull

# Re-run the installer
./install.sh
```

The installer automatically cleans the previous version before reinstalling.

---

## 10. Remote / hosted backend

The gateway can live anywhere — a LAN GPU box, a tunnel, or a hosted provider. Just point `openai_base_url` at it:

```yaml
# LAN gateway (e.g. vLLM on a GPU server)
openai_base_url: "http://<server-ip>:20128/v1"
openai_model: "qwen3:8b"
openai_api_key: ""

# Hosted provider
openai_base_url: "https://your-gateway.example/v1"
openai_model: "claude-sonnet-4"
openai_api_key: "sk-..."
```

Make sure the gateway's port is reachable (open in the firewall) and that `GET <base_url>/models` responds.

---

## 11. Optional: Install Datasets

The [airecon-dataset](https://github.com/pikpikcu/airecon-dataset) package gives the agent access to a local security knowledge base (~1.09M indexed records, 13 datasets) via the `dataset_search` tool. This is optional — AIRecon works without it.

```bash
git clone https://github.com/pikpikcu/airecon-dataset.git
cd airecon-dataset

# Install Python dependencies for the installer
pip install huggingface_hub tqdm pyarrow

# Install all datasets (~2.4 GB download, ~2 GB installed)
python install.py

# Or install only specific datasets
python install.py --include nuclei-templates red-team-offensive apt-privesc

# Verify
python install.py installed
```

Restart AIRecon after installing — the `dataset_search` tool picks up new databases automatically.

**What gets installed:**

| Dataset | Records | Use case |
|---------|---------|---------|
| Pentest Agent (ChatML) | 322,433 | CVE-based exploitation workflows |
| CTF SaTML 2024 | 190,657 | Real attack/defense CTF data |
| CTF Instruct | 141,182 | Pwn, web, crypto, forensics |
| Cybersecurity CVE | 124,732 | CVE analysis and exploitation |
| SQL Injection Q&A | 50,632 | Conversational SQLi techniques |
| Red Team Offensive | 78,430 | Lateral movement, privilege escalation |
| Cybersecurity Fenrir | 83,918 | Attack/defense instruction pairs |
| Cybersecurity Q&A | 53,199 | General security knowledge |
| StackExchange RE | 20,641 | Binary analysis, reverse engineering |
| Nuclei Templates | 23,180 | Nuclei YAML template generation |
| NVD Security Instructions | 2,063 | Structured CVE analysis |
| APT Privilege Escalation | 1,000 | Linux priv esc with APT tactics |
| Bug Bounty & Pentest | 146 | Payloads, bypass methods, methodology |

See [Features: Local Knowledge Base](features.md#local-knowledge-base) for how the agent uses this.

---

## 12. Troubleshooting

### `airecon: command not found`
`~/.local/bin` is not in PATH. Follow [Step 5](#5-configure-path).

### `ollama: connection refused`
Ollama is not running. Start it: `ollama serve` or `sudo systemctl start ollama`.

### `docker: Cannot connect to the Docker daemon`
Docker daemon is not running: `sudo systemctl start docker`.

### `airecon-sandbox` image not found at startup
Build manually: `docker build -t airecon-sandbox airecon/containers/`

### `Model not found` / model name mismatch
Run `ollama list` and copy the exact model name (including tag) into `openai_model` in config.

### `Ollama returned HTML error page` / server crashed

**Root cause:** Ollama ran out of VRAM and crashed. When this happens, Ollama's HTTP server returns an HTML error page instead of a JSON response, which AIRecon cannot parse.

This is the most common error on sessions with long context history or when running large models near VRAM limits.

**Why it happens:**
- The KV cache (conversation history) grows with each iteration — a 500-iteration session can consume 2–4× more VRAM than the initial load
- `llm_context_window: 65536` with a 32B model requires ~6–8 GB VRAM just for the KV cache, on top of model weights
- Spawning parallel agents (`run_parallel_agents`) doubles or triples VRAM usage simultaneously

**Fix in order of preference:**

**1. Restart Ollama immediately (quick fix):**
```bash
sudo systemctl restart ollama
# or if running manually:
pkill ollama && ollama serve &
```

**2. Reduce context window (permanent fix):**
```json
{
    "llm_context_window": 32768,
    "llm_context_window_small": 16384
}
```

**3. Reduce max output tokens:**
```yaml
openai_max_tokens: 8192
```

**4. Shorten model keep-alive to free VRAM between sessions:**
```yaml
llm_keep_alive: "5m"
```

**5. Limit parallel agent concurrency** — avoid `run_parallel_agents` if VRAM is near the limit. Use `spawn_agent` (single specialist) instead.

**Recommended safe config for 16–20 GB VRAM:**
```yaml
openai_model: "qwen3.5:35b"
llm_context_window: 32768
llm_context_window_small: 16384
openai_max_tokens: 8192
llm_keep_alive: "10m"
```

> The agent uses periodic context compression, so reducing `llm_context_window` usually has limited impact on long session quality.

### Context length error / out of memory (VRAM)
Lower `llm_context_window` in config:
```yaml
llm_context_window: 32768
```
Or use a smaller model. See the `Ollama returned HTML error page` section above for a complete diagnosis.

### Playwright error: `executable doesn't exist`
Reinstall Playwright browsers:
```bash
cd airecon
poetry run playwright install chromium
```

### `Connection timeout` to Ollama during long scans
Increase `llm_timeout` in config (default 1900s should be sufficient for most models):
```json
"llm_timeout": 3600.0
```

### Poetry install fails with dependency conflicts
```bash
# Clean Poetry environment and retry
poetry env remove python3
poetry install
```
