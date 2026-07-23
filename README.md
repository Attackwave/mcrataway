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
* 🎯 **12 Capability Detectors & Correlation Gates**: Combines behavioral bytecode detection with class-scoped correlation gates to minimize false positives while identifying hidden malicious patterns.
* 🛡️ **YAML Threat Intelligence Rules**: Supports custom and dynamically updateable YAML rule packs for rapid threat signature distribution against new obfuscators and malware variants.
* 🔒 **Reversible Safe Quarantine**: Isolates suspicious or infected files into a secure directory accompanied by JSON metadata manifests for safe analysis or easy restoration.
* 💻 **Web UI & Headless CLI**:
  * **Web Dashboard**: Modern interface (FastAPI + React) with real-time WebSocket scan progress, interactive rule toggles, and quarantine management.
  * **Headless CLI**: Scriptable command-line interface ideal for automated server checks, CI/CD pipelines, and bulk modpack verification.

---

## 🔬 Detection Capabilities

mcRATAway features 12 specialized capability detectors:

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

# Start the Web UI server
mcrataway serve --host 127.0.0.1 --port 8765
```

### Web UI Dashboard

Launch the Web UI dashboard with:

```bash
mcrataway serve
```

Then open your browser at `http://127.0.0.1:8765` to:
* Trigger interactive system scans with live WebSocket updates.
* Browse discovered Minecraft launcher roots.
* Toggle active threat signature rule packs.
* Manage quarantined files with full restore capability.
* Fetch latest remote threat intelligence signatures.

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
