# mcRATAway — Minecraft Mod Malware Scanner

[![CI](https://github.com/Attackwave/mcrataway/actions/workflows/ci.yml/badge.svg)](https://github.com/Attackwave/mcrataway/actions/workflows/ci.yml)
[![Build](https://github.com/Attackwave/mcrataway/actions/workflows/build.yml/badge.svg)](https://github.com/Attackwave/mcrataway/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

**mcRATAway** is a high-performance, open-source static malware scanner specifically engineered to inspect Minecraft mods (`.jar`), resource packs, datapacks, shader packs, and configuration scripts. It detects malicious payloads, Remote Access Trojans (RATs), session token stealers (Discord, Mojang/Microsoft auth), multi-stage loaders, and obfuscated Java bytecodes.

---

## 🌟 Key Features

* 🚀 **Pure-Python Bytecode Analysis**: Operates directly on Java class bytecodes (`.class` files inside `.jar` archives) without requiring a installed Java Runtime Environment (JRE/JDK).
* 🔍 **Cross-Platform Auto-Discovery**: Automatically locates standard Minecraft installations, modloaders, and third-party launchers (Prism Launcher, CurseForge, Modrinth, MultiMC, GDLauncher) across **Linux**, **macOS**, and **Windows**.
* 🎯 **14 Capability Detectors & Correlation Gates**: Combines behavioral bytecode detection with class-scoped correlation gates to minimize false positives while identifying hidden malicious patterns.
* 🛡️ **YAML Threat Intelligence Rules**: Supports custom and dynamically updateable YAML rule packs for rapid threat signature distribution against new obfuscators and malware variants.
* 🔒 **Reversible Safe Quarantine**: Isolates suspicious or infected files into a secure directory accompanied by JSON metadata manifests for safe analysis or easy restoration.
* 💻 **Web UI & Headless CLI**:
  * **Web Dashboard**: Self-contained HTML/CSS/JS interface served by FastAPI with real-time WebSocket scan progress, interactive rule toggles, and quarantine management.
  * **Headless CLI**: Scriptable command-line interface ideal for automated server checks, CI/CD pipelines, and bulk modpack verification.

---

## 🔬 Detection Capabilities

mcRATAway features 14 specialized capability detectors:

| ID | Capability | Description |
|---|---|---|
| **D01** | **Process Execution** | Identifies calls to `Runtime.getRuntime().exec()` and `ProcessBuilder`. |
| **D02** | **Network I/O** | Detects raw sockets, HTTP client connections, and Discord webhook exfiltration. |
| **D03** | **Dynamic Class Loading** | Flags custom `URLClassLoader` instantiation and bytecode `defineClass` injection. |
| **D04** | **FS / JAR Modification** | Detects unauthorized file writes and runtime modification of host JAR files. |
| **D05** | **System Persistence** | Uncovers startup persistence hooks (Windows Registry keys, systemd, crontab). |
| **D06** | **Unsafe Deserialization** | Pinpoints vulnerable `ObjectInputStream.readObject()` payload execution. |
| **D07** | **Native Library Loading** | Flags `System.load()` / JNI native dynamic library payloads (`.so`, `.dll`, `.dylib`). |
| **D08** | **Credential & Token Theft** | Detects targeting of Minecraft session tokens, Discord tokens, and browser credentials. |
| **D09** | **Obfuscation Analysis** | Measures code entropy, identifies S-box ciphers, and flags synthetic class structures. |
| **D10** | **Reflection Indirect** | Uncovers hidden invocations using `MethodHandles` and `LambdaMetafactory`. |
| **D11** | **On-Chain C2** | Detects blockchain-based command-and-control infrastructure (e.g., Ethereum `eth_call` lookups). |
| **D12** | **Resource & Datapack Exploits** | Scans `.png`, `.mcfunction`, and JSON assets for buffer overflow and script abuse. |
| **D13** | **Mixin / Coremod Abuse** | Flags Fabric/Forge Mixins and coremods targeting session/auth/network-handling classes — bytecode rewriting that never needs to call any API the other detectors watch for. |
| **D14** | **Signature / Manifest Tamper** | Detects classes added to a JAR after it was signed (trojanized mods) and `Class-Path` manifest entries loading external JARs. |

---

## ⚡ Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/Attackwave/mcrataway.git
cd mcrataway

# Install package in editable mode
pip install -e .
```

### CLI Usage

```bash
# Scan auto-discovered Minecraft roots and output JSON report
mcrataway scan --auto --report report.json

# Scan specific directories or JAR files and automatically quarantine threats
mcrataway scan /path/to/mods /path/to/suspicious.jar --quarantine

# CI/CD: exit non-zero when malicious mods are found (default threshold)
mcrataway scan --auto --fail-on malicious && echo "clean" || echo "threats found"

# Exit non-zero on any suspicious-or-worse finding, or never fail
mcrataway scan --auto --fail-on suspicious
mcrataway scan --auto --fail-on none

# Output a SARIF report for GitHub Code Scanning / Defender integration
mcrataway scan --auto --report findings.sarif

# Start the Web UI server
mcrataway serve --host 127.0.0.1 --port 8765
```

**Exit codes:** `0` = scan completed, no findings at/above the `--fail-on`
threshold · `1` = operational error (no paths, bad config) · `2` = scan
completed but findings at/above the threshold were present. The default
threshold is `malicious`; use `--fail-on suspicious` to also flag
SUSPICIOUS, or `--fail-on none` to always exit 0.

# Use a custom home directory (config, quarantine, history, rules) instead of ~/.mcrataway
mcrataway --home-dir /data/mcrataway serve
```

### Web UI Dashboard

Launch the Web UI dashboard with:

```bash
mcrataway serve
```

Then open your browser at `http://127.0.0.1:8765` to:
* **Target Management**: Select auto-detected launcher roots or add custom mod directories with toggle checkboxes.
* **Live Malware Scanner**: View real-time WebSocket scan progress, file counts, and detailed threat detections.
* **Findings**: Review currently flagged files across all recent scans, filterable by severity, with a one-click clear when you're done triaging.
* **History**: Browse or delete past completed scan sessions (individually or all at once) — persisted to disk, so they survive a server restart.
* **Rule Packs**: Enable or disable individual threat detection rules and fetch latest remote signature packs.
* **Quarantine Management**: Safely isolate, restore, permanently delete, or empty quarantine.
* **Settings**: Configure parallel workers, archive/script/config-file scanning, quarantine triggers (malicious and/or suspicious), custom quarantine folder path, retained scan-history size, and date/time display format.

`--host`/`--port` (and `config`'s equivalents like quarantine triggers)
are **not** the same thing: `--host`/`--port` only affect the current
`mcrataway serve` invocation and are never persisted — the next time
you run `mcrataway serve` without flags, it always starts back on the
default `127.0.0.1:8765`. Everything configurable from the Settings
tab, on the other hand, **is** saved to `~/.mcrataway/config.yaml` and
persists across restarts.

`~/.mcrataway` itself — the folder holding `config.yaml`, `quarantine/`,
`history/`, `rules/`, and the auth `token` file — defaults to a hidden
folder under the OS-reported home directory on every platform. Override
it with `mcrataway --home-dir /path/to/dir <command>` (must come before
the subcommand). Unlike `--host`/`--port`, you only need to pass this
once: it's persisted to `~/.config/mcrataway/home_dir`, so every later
plain `mcrataway` call picks it back up automatically instead of
silently forking a second tree back under `~/.mcrataway`. Run
`mcrataway --home-dir default <command>` to forget the override and go
back to the default location. `MCRATAWAY_HOME` is also honored as a
one-off, non-persisted override (e.g. for tests or portable installs)
and takes priority over the persisted pointer file.

---

## 🐳 Docker

The image bundles both the CLI and the web UI — same entrypoint either
way:

```bash
# Build the image
docker build -t mcrataway .

# Scan a directory: mount it read-only, mcrataway never needs to write there
docker run --rm -v /path/to/mods:/scan:ro mcrataway scan /scan --auto

# Run the web UI, persisting config/quarantine/history across restarts.
# MCRATAWAY_HOST=0.0.0.0 is required here: the default 127.0.0.1 bind is
# only reachable from inside the container, so -p alone would connect to
# nothing. MCRATAWAY_TOKEN pins the auth token instead of a fresh random
# one being generated (and only logged) on every restart.
docker run -d -p 8765:8765 -v mcrataway-data:/data \
  -e MCRATAWAY_HOST=0.0.0.0 \
  -e MCRATAWAY_TOKEN=your-fixed-token-here \
  mcrataway serve --no-browser
```

`--host`/`--port` on the command line still work the same as outside
Docker and take priority if given; `MCRATAWAY_HOST`/`MCRATAWAY_PORT` are
just the more idiomatic way to configure a container without editing the
`docker run` command's arguments.

All state lives under `/data` inside the container (`MCRATAWAY_HOME=/data`
is baked into the image) — mount a named volume there, as above, or it's
lost when the container is removed. See the `--home-dir`/`MCRATAWAY_HOME`
section above for how this mechanism works outside Docker too.

Binding `serve` to `0.0.0.0` inside the container is fine even though
mcrataway defaults to loopback-only elsewhere — the container's own
network namespace is already the isolation boundary; use `-p 127.0.0.1:8765:8765`
instead of `-p 8765:8765` if you don't want it reachable from other
machines on the host's network.

---

## 🛠️ Building Standalone Binaries

You can compile `mcrataway` into a standalone, single-file executable (no Python or Java installation required) using PyInstaller:

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run cross-platform build script
python scripts/build.py
```

The resulting binary will be output to `dist/mcrataway` (or `dist/mcrataway.exe` on Windows).

Standalone binaries for **Linux**, **Windows**, and **macOS** are also automatically built on every commit via [GitHub Actions](.github/workflows/build.yml) and available under Releases / Workflow Artifacts.

---

## 🧪 Running Tests & Quality Checks

```bash
# Run unit & integration test suite (100+ tests)
pytest

# Run static type checking
mypy src/
```

---

## 📄 License & Author

Created and maintained by **[Attackwave](https://github.com/Attackwave)**.

This project is licensed under the [MIT License](LICENSE).
