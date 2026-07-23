# Detections

## Capability Detectors

Each detector analyzes parsed class files and writes evidence to a shared `EvidenceIndex`. Severity escalates when complementary indicators co-occur in the same class.

### D01 — Process Execution

| Signal | Severity | Description |
|--------|----------|-------------|
| `Runtime.exec()` | HIGH | Direct OS command execution |
| `ProcessBuilder.start()` | HIGH | Process spawning with arguments |

**Correlation**: Escalates to CRITICAL when combined with shell command strings (cmd.exe, powershell, bash) in the same class.

### D02 — Network I/O

| Signal | Severity | Description |
|--------|----------|-------------|
| `java/net/URL` usage | MEDIUM | URL object construction |
| `HttpURLConnection` | MEDIUM | HTTP connection API |
| `java/net/http/HttpClient` | MEDIUM | Modern HTTP client |
| Socket APIs | MEDIUM | Raw socket access |
| Discord webhook URL | HIGH | Token exfiltration endpoint |
| Suspicious URL in pool | LOW | Non-standard endpoint in constants |

**Correlation**: Escalates to HIGH when combined with credential access (D08) in the same class.

### D03 — Dynamic Class Loading

| Signal | Severity | Description |
|--------|----------|-------------|
| `URLClassLoader` | HIGH | Load classes from remote URL |
| `ClassLoader.defineClass` | HIGH | Define classes from bytecode array |
| `Class.forName` | MEDIUM | Dynamic class resolution |

**Correlation**: Escalates to CRITICAL when combined with native loading (D07) — indicates native-DLL staging pattern.

### D04 — Filesystem / JAR Modification

| Signal | Severity | Description |
|--------|----------|-------------|
| `ZipOutputStream` | LOW | Archive creation |
| `JarFile` / `JarOutputStream` | LOW | JAR manipulation |
| `Files.walk` | LOW | Recursive directory traversal |
| `.minecraft` path ref | LOW | References to Minecraft directories |

### D05 — Persistence

| Signal | Severity | Description |
|--------|----------|-------------|
| Windows Run keys | HIGH | Autostart via registry |
| `schtasks` / `schtasks.exe` | HIGH | Scheduled task creation |
| `crontab` | HIGH | Cron job creation |
| systemd unit paths | HIGH | Systemd service creation |
| Startup folder | HIGH | Startup directory placement |

### D06 — Unsafe Deserialization

| Signal | Severity | Description |
|--------|----------|-------------|
| `ObjectInputStream.readObject()` | MEDIUM | Deserialization without filtering (BleedingPipe-style RCE risk) |

### D07 — Native / JNI Loading

| Signal | Severity | Description |
|--------|----------|-------------|
| `System.load()` | HIGH | Load native library from path |
| `System.loadLibrary()` | HIGH | Load native library by name |
| `.dll` / `.so` / `.dylib` refs | MEDIUM | Native library extension strings |
| `createTempFile` + `deleteOnExit` | HIGH | JNIC DLL staging pattern |

**Correlation**: Escalates to CRITICAL when combined with dynamic loading (D03).

### D08 — Credential Theft

| Signal | Severity | Description |
|--------|----------|-------------|
| `getSession()` | HIGH | Minecraft session access |
| `getAccessToken()` | HIGH | Minecraft access token access |
| `getUsername()` / `getUuid()` | HIGH | Player identity access |
| `session.json` / `launcher_accounts.json` | HIGH | Account file references |
| Discord token paths | HIGH | Discord token file references |
| Browser cookie / Login Data | HIGH | Browser credential database paths |

**Correlation**: Escalates to CRITICAL (static override) when combined with network I/O (D02) — almost always session token exfiltration.

### D09 — Obfuscation

| Signal | Severity | Description |
|--------|----------|-------------|
| High Shannon entropy (>4.5) | LOW | Encoded/encrypted strings |
| Single-letter package parts | MEDIUM | Heavily obfuscated class names |
| Excessive synthetic methods | MEDIUM | Synthetic flag abuse |
| Synthetic fields | LOW | Hidden field markers |

### D10 — Reflection Indirect Access

| Signal | Severity | Description |
|--------|----------|-------------|
| `MethodHandles` / `MethodHandle` | MEDIUM | Indirect method invocation |
| `LambdaMetafactory` | MEDIUM | Lambda-based dispatch |
| `VarHandle` | MEDIUM | Unsafe field access |
| `StackWalker` | MEDIUM | Stack frame inspection |
| `sun/misc/Unsafe` | MEDIUM | Unsafe memory access |

### D11 — On-Chain C2

| Signal | Severity | Description |
|--------|----------|-------------|
| `0xce6d41de` selector | CRITICAL | Ethereum `getText()` function selector (used by weedhack, griftclient) |
| `eth_call` reference | MEDIUM | Ethereum JSON-RPC method |
| Infura / Alchemy / publicnode | MEDIUM | Ethereum RPC endpoint |
| `java/security/Signature.verify` | HIGH | RSA signature verification (C2 payload auth) |

**Static override**: Any high-severity D11 signal forces MALICIOUS verdict.

### D12 — Resource/Datapack Exploit

| Signal | Severity | Description |
|--------|----------|-------------|
| Oversized PNG (>1MB) | MEDIUM | Potential buffer overflow payload |
| PNG text chunks | LOW | Hidden data in PNG metadata |
| Embedded script in pack.mcmeta | HIGH | JavaScript in resource pack metadata |
| Excessive .mcfunction calls | MEDIUM | Potential DoS via recursive function chains |

## Signature Rules

YAML-defined rules with multi-string correlation. High-severity rules require multiple corroborating strings — no single-string high-severity rules.

### Built-in Packs

| Pack | Purpose |
|------|---------|
| `minecraft_families` | Known malware family IOCs (weedhack, fractureiser, silentnet, pussylib, krypton, makslibraries) |
| `suspicious_indicators` | Generic high-suspicion patterns (session exfil, webhook exfil, native staging, on-chain C2, in-memory classloader, obfuscated cipher) |

## Verdict Logic

| Condition | Verdict | Confidence |
|-----------|---------|------------|
| No evidence | CLEAN | 1.0 |
| Static override fires | MALICIOUS | 0.7–1.0 |
| Critical ≥ 1 or High ≥ 2 or Medium ≥ 5 | MALICIOUS | weighted |
| High ≥ 1 or Medium ≥ 3 or Low ≥ 5 | SUSPICIOUS | weighted |
| Otherwise | CLEAN | 1.0 |

### Static Override Triggers

- Credential theft (D08) at HIGH + Network I/O (D02) at HIGH in same class
- On-chain C2 (D11) at HIGH
- Native/JNI (D07) at HIGH + Dynamic loading (D03) at HIGH in same class
- Any signature rule match at HIGH severity
