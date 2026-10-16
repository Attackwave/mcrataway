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

**Correlation**: D02 at MEDIUM or worse in the same class as D08 at HIGH or worse is a static-override trigger — a class that reads a credential and talks to the network.

### D03 — Dynamic Class Loading

| Signal | Severity | Description |
|--------|----------|-------------|
| `URLClassLoader` / `SecureClassLoader` calls that obtain or define a class (`<init>`, `loadClass`, `findClass`, `defineClass`, `newInstance`) | HIGH | Load classes from a URL |
| Any other call on those loaders (`getURLs`, `getResource`, …) | MEDIUM | Read-only classpath access, which says no more than a reference to the class does |
| `ClassLoader.defineClass` | HIGH | Define classes from bytecode array |
| `Class.forName` | MEDIUM | Dynamic class resolution |

**Correlation**: D03 at HIGH in the same class as D07 at MEDIUM or worse is a static-override trigger — the native-DLL staging pattern.

### D04 — Filesystem / JAR Modification

| Signal | Severity | Description |
|--------|----------|-------------|
| `ZipOutputStream` / `JarOutputStream` | INFO | Archive creation |
| `JarFile` / `ZipFile` | INFO | JAR inspection |
| `Files` / `Paths` / `FileOutputStream` / `RandomAccessFile` | INFO | File and directory access |

Every D04 finding is INFO: writing a file, opening a JAR or walking a directory is what an ordinary mod does with its own config, so this detector contributes volume to the weighted score but never a verdict on its own. It used to report credential-file paths as well; that duplicate — one `launcher_accounts.json` constant produced a D04 *and* a D08 HIGH, two findings that already crossed the MALICIOUS threshold by themselves — is D08's alone.

### D05 — Persistence

| Signal | Severity | Description |
|--------|----------|-------------|
| Windows Run keys | HIGH | Autostart via registry |
| `schtasks` / `schtasks.exe` | HIGH | Scheduled task creation |
| `crontab` | HIGH | Cron job creation |
| systemd unit paths | HIGH | Systemd service creation |
| Startup folder | HIGH | Startup directory placement |

**Correlation**: A *weak* indicator — an identifier string that never reaches the API, e.g. `schtasks.exe` with no process call in the class — is LOW (MEDIUM when the string was reconstructed) and is raised to HIGH only when the same class also executes a process (D01). A name is not a mechanism; the name plus the code that runs it is.

### D06 — Unsafe Deserialization

| Signal | Severity | Description |
|--------|----------|-------------|
| `ObjectInputStream.readObject()` | MEDIUM | Deserialization without filtering (BleedingPipe-style RCE risk) |
| `java.beans.XMLDecoder` | HIGH | Instantiates whatever class the document names — the BleedingPipe payload path |

### D07 — Native / JNI Loading

| Signal | Severity | Description |
|--------|----------|-------------|
| `System.load()` | HIGH / MEDIUM | Load a native library from an absolute path. HIGH only when the same class also *stages* what it loads (see the next row); an absolute path on its own is how every mod loads the native it ships, so it is MEDIUM |
| `System.loadLibrary()` | MEDIUM | Load a bundled native by name — what every LWJGL-backed mod does |
| `.dll` / `.so` / `.dylib` refs | LOW | Native library extension strings; INFO for a known bundled library (lwjgl, jna), HIGH when the same class stages a file |
| `createTempFile` + `deleteOnExit` | HIGH | JNIC DLL staging pattern (CRITICAL when the string was reconstructed) |

**Correlation**: D07 at MEDIUM or worse in the same class as D03 at HIGH is a static-override trigger.

### D08 — Credential Theft

| Signal | Severity | Description |
|--------|----------|-------------|
| `getAccessToken()` | HIGH | Minecraft session *token* access (named and intermediary forms) |
| `getSession()` / `getUsername()` / `getUuid()` | MEDIUM | Session *info* access — a scoreboard, nametag or minimap mod reads these too, and the token is what a stealer needs |
| `session.json` / `launcher_accounts.json` | HIGH | Account file references (CRITICAL when reconstructed) |
| Discord token paths | HIGH | Discord token file references |
| Browser cookie / Login Data | HIGH | Browser credential database paths — as a *path*; the bare word `Cookies` (an HTTP client's own class) is LOW |
| `wallet.dat`, `exodus.wallet`, `Electrum/wallets`, `Ethereum/keystore`, `.ssh/`, `id_rsa` | HIGH | Crypto-wallet and SSH-key paths — the target set of the token-stealer mods seen in the wild, and nothing a Minecraft mod reads on purpose. The SSH key is matched with its separator, because a bundled crypto library names its JCA algorithms `id_rsassa_pkcs1_v1_5_with_sha3_512` |

**Correlation**: D08 at HIGH or worse in the same class as D02 at MEDIUM or worse is a static-override trigger — credential access plus a network destination in one class is almost always session-token exfiltration.

### D09 — Obfuscation

| Signal | Severity | Description |
|--------|----------|-------------|
| High Shannon entropy (>5.8) | LOW | Encoded/encrypted strings |
| Single-letter package parts | MEDIUM | Heavily obfuscated class names |
| Control-flow flattening dispatcher | MEDIUM | See below |

**Control-flow flattening**: detects the dispatcher shape produced by
control-flow-flattening obfuscators (Allatori/ProGuard-style) — a
central `tableswitch`/`lookupswitch` on a state variable, inside a
loop, where most cases end with a `goto` back to the dispatcher rather
than falling out of the switch. A switch is only flagged when it has
at least 4 targets AND a goto-to-target ratio of at least 0.5, AND
there is no loop-bound comparison (`arraylength`/`if_icmp*` etc.)
immediately preceding the switch's selector — that last check is what
distinguishes a flattened state machine from the much more common
"ordinary loop containing a switch statement" shape, which produces
the same switch+multiple-goto pattern (every `break`/`continue` in a
loop-body switch compiles to a `goto` too) but is not obfuscation.

### D10 — Reflection Indirect Access

| Signal | Severity | Description |
|--------|----------|-------------|
| `MethodHandles` / `MethodHandle` | MEDIUM | Indirect method invocation |
| `LambdaMetafactory` | MEDIUM | Lambda-based dispatch |
| `VarHandle` | MEDIUM | Unsafe field access |
| `StackWalker` | MEDIUM | Stack frame inspection |
| `sun/misc/Unsafe` | MEDIUM | Unsafe memory access |
| Method reference resolving to a different class | LOW | See below |

**Cross-class method references**: `ClassFile.bootstrap_methods` (the
class-level `BootstrapMethods` attribute) is parsed, and
`resolve_invokes()` follows `invokedynamic` call sites through it to
their real target — the `LambdaMetafactory` bootstrap argument that
actually names the lambda body / method reference. This closes a
specific evasion: splitting a dangerous capability into a separate
class and reaching it only via a method reference (e.g. `Runnable r =
EvilRunner::detonate;`) previously left no trace in the calling
class's resolved invokes at all, since `invokedynamic` came back with
an empty owner/name. A resolved target in a *different* class than the
one being analyzed is flagged at LOW — ordinary functional-interface
usage does this constantly, so it is not inherently suspicious on its
own, but it is exactly the shape used to defeat single-class analysis
and is worth escalating when combined with other findings.

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
| Oversized PNG (>1MB) | LOW | A large image asset — HD textures and UI art are routinely this size, so it is a note, not a capability |
| PNG text chunks | LOW | Hidden data in PNG metadata |
| Embedded script in pack.mcmeta | HIGH | JavaScript in resource pack metadata |
| Excessive .mcfunction calls | MEDIUM | Potential DoS via recursive function chains |

### D13 — Mixin/Coremod Abuse

Fabric/Forge Mixins let a mod rewrite bytecode in the game itself (or
another mod) at load time. A malicious Mixin targeting the class that
already holds a session token or handles network auth never needs to
call any of the APIs D01-D11 look for — it just edits the method that
already has what it wants. This is a blind spot none of the other
bytecode-level detectors cover, since the "target" a Mixin edits is
declared in JSON config, not derivable from the Mixin class's own
bytecode alone.

| Signal | Severity | Description |
|--------|----------|-------------|
| Mixin config (`*.mixins.json`) declaring a mixin class named after a sensitive target (Session, MinecraftClient, YggdrasilAuthenticationService, ClientConnection, packet encode/decode) | MEDIUM | Naming-convention signal — not a guarantee, but the same first-pass signal a human reviewer would use |
| `Redirect`/`Overwrite` mixin annotation string + sensitive target name in the same class's constant pool | HIGH | These annotations fully substitute or reroute behavior at the injection point (unlike `Inject`, which runs alongside the original method). HIGH rather than CRITICAL because rewriting an auth method is what protocol- and version-support mods do — the malware case is the pair with a network sink (see the static override triggers) |
| Sensitive target name in the class's constant pool without `Redirect`/`Overwrite` | MEDIUM | A mixin into session or auth code can intercept credentials even while running alongside the original method |
| `FMLCorePlugin` / `FMLCorePluginContainsFMLMod` in `META-INF/MANIFEST.MF` | MEDIUM | Forge's pre-Mixin coremod mechanism — registers a ClassLoader transformer with full bytecode-rewrite access before any other mod code runs |

Operates on archive entries (mixin JSON configs, the manifest) rather
than parsed classes, since the mixin target is declared in JSON.

### D14 — Signature/Manifest Tamper

Detects a JAR that was legitimately signed and then had a payload
added afterward ("trojanizing" a real mod), plus manifest entries that
load code from outside the mod itself. This scanner does not verify
cryptographic signatures (that requires the signer's certificate
chain); instead it checks the cheaper, still-strong signal of whether
every `.class` entry in the archive is actually *listed* in the
signature block — an entry added after signing simply is not.

| Signal | Severity | Description |
|--------|----------|-------------|
| `.class` entry present in the archive but absent from its `META-INF/*.SF` file | HIGH | Added after the JAR was signed — a real JVM would reject this JAR outright during signature verification |
| `Class-Path` entry in `META-INF/MANIFEST.MF` | MEDIUM | Loads additional JARs from outside normal mod dependency resolution — legitimate mods essentially never need this |

Only applies to the top-level archive (a signature block found in a
nested archive belongs to that inner mod's own signing, not the outer
artifact being scanned) and only checks `.class` entries against the
signature block, not other resource files, to avoid noise from build
tooling that can legitimately vary non-code entries between build and
sign steps.

## Behaviour Chains

A chain is a named set of detectors whose co-occurrence **in one class** describes a complete
behaviour rather than a single capability:

| Chain | Links | Behaviour |
|-------|-------|-----------|
| `credential_exfiltration` | D08 + D02 + D09 | Reads a credential, sends it somewhere, hides the destination |
| `reload_and_execute` | D02 + D03 | Fetches from a hidden destination and loads the result as code |
| `hidden_download_and_exec` | D02 + D01 | Fetches from a hidden destination and hands the result to the OS |

A chain matches when every link is present at MEDIUM or worse *in that class* and at least one
link is HIGH or CRITICAL. Merely mentioning the APIs is not enough: a service loader, a plugin
framework or a native-extraction library contains a URL, a file write and a `Class.forName` at
INFO–MEDIUM, which is exactly what the linking rule keeps out. For the two download chains the
discriminator is the *destination* — D02 only reaches MEDIUM for a hidden, reconstructed or
known-exfiltration URL, while a plaintext URL string is what every update checker contains.

A matched chain adds a CRITICAL `behavior_chain` finding and lifts every participating link in
that class to at least MEDIUM, so a complete behaviour cannot be averaged away. When no chain
matches, a *lone* link — exactly one chain-participant detector, nothing else escalated it — is
downgraded to LOW: doing one thing on this list is not what malware looks like, doing several of
them together is.

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
| Static override fires | MALICIOUS | 0.84–1.0 |
| CRITICAL ≥ 1, or HIGH from ≥ 2 capabilities in one class, or MEDIUM from ≥ 8 capabilities | MALICIOUS | weighted |
| HIGH from ≥ 1 capability, or MEDIUM from ≥ 4, or LOW from ≥ 6 | SUSPICIOUS | weighted |
| Otherwise | CLEAN | 1.0 |

Counting rules, applied to the evidence left after the chain pass:

- **HIGH counts per capability within one class**: "2 HIGHs" means two independent strong signals
  describing the *same* class — `Runtime.exec` seen twenty times inside a bundle of command-line
  tools is still one capability, and a helper process in one class next to a bundled native in
  another is how legitimate mods (and LWJGL itself) work, not a dropper. Stages split across
  classes are still covered by the class-scoped static overrides and the behaviour chains.
- **D05 and D08 are target-based**, the exception to that rule: each of their findings names a
  distinct target (a wallet file, a launch agent, a key), so every HIGH from them counts
  separately. Victims do not care about class boundaries — reading three credential files is three
  victims, not one finding counted thrice.
- **MEDIUM and LOW count distinct capabilities**, for the same reason: one detector firing across
  fifty classes of a large mod's bundled libraries is one capability, not fifty. Sub-detectors of
  one analyzer collapse onto a single capability: `script:eval`, `script:fetch` and
  `script:oversized` are three views of one scripting surface, not three capabilities.
- **Confidence** is a monotonic function of the weighted score (CRITICAL 1.0, HIGH 0.6, MEDIUM
  0.2, LOW 0.05): more evidence can only raise it, never lower it, and a SUSPICIOUS verdict caps
  at 0.9 so it can never read as certainty.

### Static Override Triggers

Each trigger compares each detector's *highest* severity in the class, not mere co-presence: an
INFO network observation next to a LOW "mentions a cookie file" finding says nothing, and
treating that as credential theft plus exfiltration made an HTTP client library MALICIOUS.

- Credential theft (D08) at HIGH + network I/O (D02) at MEDIUM or worse **in the same class**
- Auth-rewriting mixin (D13) at HIGH + network I/O (D02) at MEDIUM or worse **in the same class** —
  rewriting `Session`/`Yggdrasil` behaviour is how protocol-support mods work, shipping the
  exfiltration it feeds is not
- Native/JNI loading (D07) at MEDIUM or worse + dynamic loading (D03) at HIGH **in the same class**
- On-chain C2 (D11) at HIGH
- Any signature rule match at HIGH severity
- A deliberately hidden reference to a dangerous API (`Runtime.exec`, `URLClassLoader`,
  `defineClass`, `MethodHandles`, …) together with dynamic class resolution (D03) or indirect
  invocation (D10) **in the same class** — the pattern that builds a call no direct invoke
  reveals. A reconstructed string alone is not enough: Base64 for embedded assets plus
  reflection for config is a legitimate and common combination
