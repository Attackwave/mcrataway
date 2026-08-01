# Architecture

## Overview

mcrataway is a Minecraft mod malware scanner that analyzes Java bytecode, scripts, and archive contents at rest. It requires no Java runtime, no decompiler binaries, and makes no network calls during scanning.

## Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        Discovery Layer                          │
│  os_paths.py  →  Auto-discover Minecraft roots per OS          │
│  walker.py    →  Recursively collect scannable files            │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Parser Layer                             │
│  archive.py         →  Read JAR/ZIP entries in-memory           │
│  classfile.py       →  Pure-Python .class binary parser         │
│  constant_pool.py   →  Resolve Utf8, String, Class, Methodref   │
│  instructions.py    →  Decode opcodes, resolve invoke* calls    │
│  string_reconstructor.py → Reassemble hidden byte[] strings     │
│  manifest.py        →  Parse fabric.mod.json, mcmod.info, etc.  │
│  scripts.py         →  Analyze KubeJS, .mcfunction, Rhino JS    │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Detection Layer                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ EvidenceIndex — class-scoped correlation gate             │  │
│  │ All detectors write evidence here; detectors read from it │  │
│  │ to escalate severity when indicators co-occur             │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  D01  Process execution       (Runtime.exec, ProcessBuilder)   │
│  D02  Network I/O              (URL, HttpClient, webhooks)     │
│  D03  Dynamic class loading    (URLClassLoader, defineClass)   │
│  D04  Filesystem / JAR mod     (ZipOutputStream, .jar markers) │
│  D05  Persistence              (Run keys, schtasks, crontab)   │
│  D06  Unsafe deserialization   (ObjectInputStream.readObject)  │
│  D07  Native / JNI loading     (System.load, .dll/.so/.dylib)  │
│  D08  Credential theft         (session tokens, Discord)       │
│  D09  Obfuscation              (entropy, S-box, synthetic)     │
│  D10  Reflection indirect      (MethodHandles, LambdaMetafac.) │
│  D11  On-chain C2              (eth_call, 0xce6d41de)          │
│  D12  Resource/datapack exploit (PNG overflow, .mcfunction)    │
│                                                                 │
│  Signature Rules — YAML-defined, multi-string correlation      │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Verdict Layer                               │
│  Aggregate evidence → CLEAN / SUSPICIOUS / MALICIOUS           │
│  Static override guard forces MALICIOUS on high-confidence     │
│  signals (cred-theft + network, on-chain C2, native staging)   │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Action Layer                                │
│  Quarantine — copy to safe dir, write manifest, replace with   │
│  placeholder. Reversible via restore. No auto-delete.          │
│                                                                 │
│  Reporting — JSON, self-contained HTML, Rich console table     │
└─────────────────────────────────────────────────────────────────┘
```

## Interfaces

### CLI

```bash
mcrataway [--home-dir DIR] scan <paths...> [--report out.json] [--quarantine] [--auto]
mcrataway [--home-dir DIR] serve [--host 127.0.0.1] [--port 8765] [--reload]
```

`--home-dir` relocates the whole `~/.mcrataway` tree — config,
quarantine, history, rules, auth token — and must be given before the
subcommand, since it has to be resolved before `config.yaml` itself can
be found. It's persisted to `~/.config/mcrataway/home_dir` on first use,
so it only needs to be passed once (`--home-dir default` clears it).
`MCRATAWAY_HOME` is a non-persisted, higher-priority override for the
same setting.

### Server (FastAPI)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/scan/` | Start scan job |
| GET | `/scan/{id}` | Job status |
| WS | `/scan/{id}/stream` | Live progress + findings |
| GET | `/findings/` | List currently flagged files (filterable by `?severity=`) |
| POST | `/findings/clear` | Dismiss all findings from view (does not affect History) |
| GET | `/history/` | List past completed scan sessions |
| GET | `/history/{id}` | Full persisted report for one past session |
| DELETE | `/history/{id}` | Delete one past session |
| POST | `/history/purge` | Delete all past sessions |
| GET | `/rules/` | List rule packs |
| POST | `/rules/test` | Test a rule pack against a sample file |
| GET | `/quarantine/` | List quarantined items |
| POST | `/quarantine/{sha256}` | Quarantine a specific file |
| DELETE | `/quarantine/{sha256}/restore` | Restore item |
| DELETE | `/quarantine/{sha256}` | Permanently delete item |
| POST | `/quarantine/purge` | Permanently delete all quarantined items |
| GET | `/reports/{id}` | Full report for an in-memory job |
| GET | `/system/roots` | Discovered roots |
| GET | `/system/health` | Liveness probe |
| GET/POST | `/system/config` | Read/update user configuration |
| POST | `/system/whitelist` | Whitelist a SHA-256 hash |
| POST | `/system/update-rules` | Fetch latest signed rule packs |

### Web UI

Self-contained HTML/CSS/JS dashboard served directly from `server/static/index.html` — no build step, no Node toolchain. Live progress via WebSocket.

## Key Design Decisions

- **Bytecode-native analysis**: Constant pool + opcode inspection, not text grep over decompiled source.
- **Per-entry scanning**: Archive entries are scanned inflated, never the compressed blob.
- **Correlation gates**: Single API calls are noisy; severity escalates only when complementary indicators co-occur in the same class.
- **Self-contained**: No Java runtime, no decompiler binaries, no YARA binary, no network calls.
- **Loopback-only server**: Binds `127.0.0.1:8765`, zero remote attack surface.
- **No auto-delete**: Quarantine is always reversible.
