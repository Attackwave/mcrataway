# Rules

## Rule Pack Format

Rules are defined in YAML files under `src/mcrataway/rules/packs/`.

```yaml
pack_id: "my_pack"
description: "Description of this rule pack"
rules:
  - id: "unique_rule_id"
    family: "family_name"
    severity: "critical"  # critical | high | medium | low
    description: "What this rule detects"
    strings:
      - kind: "literal"
        value: "exact string to match"
      - kind: "regex"
        value: "regex pattern"
      - kind: "hex"
        value: "ce6d41de"  # hex bytes (spaces optional)
    condition: "count() >= 2"  # all | any | count() >= N
```

### String Kinds

| Kind | Behavior |
|------|----------|
| `literal` | Exact substring match in any archive entry (inflated) |
| `regex` | Case-insensitive regex match against all entry text |
| `hex` | Hex-encoded byte sequence match |

### Conditions

| Condition | Meaning |
|-----------|---------|
| `all` | All defined strings must match |
| `any` | At least one string must match |
| `count() >= N` | At least N strings must match |

### Severity Guidelines

- **Critical**: Active credential theft, known malware families, on-chain C2
- **High**: Staging patterns, native loading, persistence mechanisms
- **Medium**: Suspicious APIs used in combination, obfuscation markers
- **Low**: Individual suspicious strings, high-entropy constants

## Adding Custom Rules

1. Create a YAML file in `src/mcrataway/rules/packs/` or any path.
2. Load it via CLI: `mcrataway scan --auto --rules /path/to/rules.yaml`
3. Or via API: `PUT /rules/{pack}`

Rules loaded locally this way (from a file you already have on disk)
are trusted implicitly — signing only applies to the *remote update*
path, described next.

## Remote Rule Updates and Signing

`mcrataway.rules.updater.RuleUpdater.fetch_remote_rules()` downloads
rule packs over HTTPS and installs them into
`~/.mcrataway/rules/`. Because these rules directly control what gets
flagged (and, with auto-quarantine, what gets deleted), every
downloaded pack must carry a valid detached Ed25519 signature — see
`src/mcrataway/rules/signing.py`.

**By default, `TRUSTED_PUBLIC_KEYS_B64` is empty, so all remote rule
packs are rejected.** This is the safe default: without a provisioned
signing key, there is no way to distinguish a legitimate update from
one served by a compromised mirror or repository takeover, so remote
updates simply do not take effect until a key is added.

To provision signing for your own rule-pack distribution:

```python
from mcrataway.rules.signing import generate_keypair, sign_data

# One-time: generate a keypair. Keep the private key offline/secret.
private_key_b64, public_key_b64 = generate_keypair()

# Add public_key_b64 to TRUSTED_PUBLIC_KEYS_B64 in signing.py and ship
# that with the scanner (it is the trust root, not downloaded).

# For each rule pack file you publish, sign its exact bytes and
# publish the result as `<filename>.sig` alongside `<filename>`:
data = open("suspicious_indicators.yaml", "rb").read()
signature_b64 = sign_data(data, private_key_b64)
open("suspicious_indicators.yaml.sig", "w").write(signature_b64)
```

`fetch_remote_rules()` fetches `<url>` and `<url>.sig`, verifies the
signature against the trust root, and only writes the pack to disk on
success. On failure (missing signature, invalid signature, untrusted
key) the previously installed version — if any — is left untouched;
the fetch is logged as a warning, not treated as fatal.

### Downgrade/Rollback Protection

A signature only proves *who* published a file, not that it's the
*most recent* one — an attacker in control of the download channel
(a compromised mirror, or a repository takeover) could otherwise
replay an old, validly-signed pack that predates detection for a
since-added malware family.

To defend against this, a pack can declare an optional top-level
`pack_version` field:

```yaml
pack_id: "my_pack"
pack_version: "2026-08-01"  # ISO-8601 date, or a zero-padded integer
description: "..."
rules: [...]
```

`RuleUpdater` remembers the last accepted `pack_version` per source
URL (in `~/.mcrataway/rules/.pack_versions.json`) and rejects an
update whose version is not strictly newer, even if its signature is
valid. Versions are compared as plain strings, so use an ISO-8601
date or a zero-padded integer (`"0007"`, not `"7"`) — an unpadded
integer does not sort correctly once it reaches double digits.

Packs without a `pack_version` field are accepted as before, with no
downgrade protection — this is a best-effort defense on top of
signing, not a hard requirement of the pack format.

## Generating Rule Proposals

`mcrataway rulegen` analyzes a directory of malware samples (or a
single sample file) and proposes a detection rule, extracting literal
patterns from matched evidence and reconstructed/decrypted strings:

```bash
mcrataway rulegen /path/to/samples --family my_new_family \
    -o proposed.yaml
```

With multiple samples of the same family, only patterns appearing in
at least `--min-sample-fraction` (default `0.6`, i.e. 60%) of the
samples are kept, to avoid overfitting the rule to one specific
variant. With a single sample, every extracted pattern is kept as-is.

By default the output is written to
`~/.mcrataway/rules/proposed/<family>.proposed.yaml` — a directory
that `RulePackLoader.load_defaults()` does **not** scan, so a
generated proposal is never automatically trusted or loaded, whatever
severity it was given.

## Reviewing Generated Rule Proposals

A generated proposal is a starting point, not a finished rule — it has
never been reviewed by a person and always defaults to `medium`
severity regardless of how the underlying sample was classified, so
that an accidentally-loaded proposal cannot trigger auto-quarantine.
The generated YAML carries a `proposal_metadata` block (source sample
hashes, generation timestamp, generator version, and notes) alongside
the normal `pack_id`/`rules` fields — `RulePackLoader` ignores unknown
top-level keys, so the file is directly testable without any
conversion step:

```bash
mcrataway scan suspicious.jar --rules proposed.yaml
```

Once a proposal has been reviewed and, if necessary, adjusted (e.g.
tightening a pattern, correcting the severity, dropping a
false-positive-prone string), promote it by either:

1. Copying/moving the file into `~/.mcrataway/rules/` (not the
   `proposed/` subdirectory) — it will be loaded automatically on the
   next `mcrataway scan`/`mcrataway serve` invocation, as a
   locally-trusted rule pack.
2. Including it in a rule-pack repository you distribute and sign, per
   the "Remote Rule Updates and Signing" section above.

`rulegen` never calls `sign_data()` itself and never writes into
`~/.mcrataway/rules/` directly — signing and promotion out of
`proposed/` are always a deliberate, manual step.

## Testing Rules

```bash
# CLI
mcrataway scan suspicious.jar --rules my_rules.yaml

# API
curl -X POST http://127.0.0.1:8765/rules/test \
  -H 'Content-Type: application/json' \
  -d '{"file_path": "/path/to/mod.jar", "rule_id": "my_rule"}'
```

## Built-in Rule Packs

### minecraft_families

Covers known malware families observed in the wild:
- weedhack/Majanito: multi-stage loader, on-chain C2, in-memory classloading
- fractureiser: Stage 0 bytecode injector, byte-array string hiding
- silentnet: Handshake DNS resolution, encrypted C2
- pussylib: session token theft via reflection
- krypton: obfuscated Fabric stub with URLClassLoader
- makslibraries: Forge mod with malicious mcmod.info

### suspicious_indicators

Generic patterns that indicate malicious behavior regardless of family:
- Session token exfiltration (session access + HTTP)
- Discord webhook exfiltration
- Native DLL staging (System.load + createTempFile + deleteOnExit)
- On-chain C2 resolution (eth_call + selector + RSA verify)
- In-memory classloader (defineClass + URLClassLoader)
- Obfuscated string ciphers (byte[] strings + Helper.load)
