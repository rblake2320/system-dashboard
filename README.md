# System Dashboard

Real-time ops dashboard for AI-heavy workstations. Monitors CPU, RAM, GPU, storage, processes, ports, and network — with a background daemon, LLM-powered diagnosis, and one-click automated fixes.

## Features

- **Live metrics**: CPU %, RAM, GPU utilization + VRAM (via pynvml), with sparkline history
- **Disk I/O**: Read/write MB/s per drive, with failing-drive detection
- **AI process tracking**: Per-process CPU% and RAM for claude, codex, python, node, etc.
- **Service ports**: Up/down status with uptime and clickable links to open services
- **Network**: Connections grouped by process, external vs. LAN, named IPs
- **Issue detection**: Auto-detects high CPU/RAM/GPU, failing drives, runaway processes
- **AI Diagnosis**: Click any issue to get root-cause analysis from a local LLM (Ollama) or cloud API
- **Auto-Fix**: SSE-streamed terminal output as fixers run in real time
- **Alert history**: Full log of every issue ever detected
- **Kill button**: Per-process kill directly from the process table

## Setup

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
# Edit config.yaml with your ports, projects, and LLM settings
python dashboard.py
```

Open `http://127.0.0.1:8099` in your browser.

## Configuration (`config.yaml`)

`config.yaml` is gitignored — it holds your personal infrastructure details. Copy from `config.example.yaml` and edit:

```yaml
dashboard:
  port: 8099

llm:
  provider: ollama          # ollama | openai | anthropic | none
  model: gemma3:latest
  host: http://localhost:11434

services:
  ports:
    8100: MemoryWeb API
    8300: UltraRAG
    # ... add your services
```

## Adding Daemons

Implement `fixers/FixerBase` and register in `dashboard.py`'s `FIXERS` dict:

```python
class MyFixer(FixerBase):
    fixer_id = "my_fixer"
    def can_fix(self, issue): ...
    def fix(self, issue):
        yield "Working..."
        yield "DONE"
```

## Extending Issue Detection

Add detectors in `core/issues.py` → `detect_issues()`. Each issue needs:
- `id`: deterministic hash (same condition = same id)
- `severity`: `critical | warning | info`
- `fixer_id`: which fixer handles it (optional)

## Architecture

```
dashboard.py          Flask app + SSE routes
core/
  config.py           YAML loader with deep-merge defaults
  collector.py        psutil + pynvml data collection
  issues.py           Issue detection + thread-safe registry
daemon/
  monitor.py          30s background poll, sparkline history, alert log
agents/
  ollama.py           Ollama + OpenAI/Anthropic LLM agents
fixers/
  process_fixer.py    Kill/list processes
  service_fixer.py    NSSM restart, port diagnosis
```
