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
