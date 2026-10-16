# Development

## Prerequisites

- Python 3.12+

## Backend Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/

# Run tests
pytest -v tests/

# Coverage gate enforced by CI
pytest --cov=mcrataway --cov-fail-under=78

# Run CLI
mcrataway scan --auto
mcrataway serve --reload
```

## Frontend Development

The web dashboard is a single self-contained file,
`src/mcrataway/server/static/index.html` — no build step, no Node
toolchain. Edit it directly and reload the page in your browser while
`mcrataway serve` is running.

## Adding a New Detector

1. Create `src/mcrataway/detectors/d{NN}_{name}.py`
2. Extend `Detector` base class:
   ```python
   from mcrataway.detectors.base import Detector
   from mcrataway.core.evidence import Evidence

   class DNNMyDetector(Detector):
       @property
       def detector_id(self) -> str:
           return "dNN"

       def analyze_class(self, class_file) -> list[Evidence]:
           evidence = []
           # ... analysis logic ...
           return evidence
   ```
3. Register in `core/scan_engine._default_detectors()`
4. Add tests under `tests/unit/` — detector behaviour goes in
   `tests/unit/test_detectors.py`, bytecode-level cases use the prebuilt
   fixtures in `tests/javac_fixtures/`

## Adding a New Rule Pack

1. Create YAML file in `src/mcrataway/rules/packs/`
2. See `docs/RULES.md` for format specification
3. Rules are auto-loaded by `RulePackLoader.load_defaults()`

## Generating Test Fixtures

```bash
python -m tests.fixtures.generator tests/fixtures/
```

This generates synthetic JAR files:
- `benign_mod.jar` — harmless mod
- `session_stealer.jar` — synthetic session token stealer
- `eth_c2_mod.jar` — synthetic on-chain C2 resolver
- `native_loader.jar` — synthetic native DLL loader

## Release Process

Releases are cut by CI from a version tag — there is no manual upload step:

1. Bump `__version__` in `src/mcrataway/__init__.py` in its own PR and merge it to `main`.
2. Tag that merge commit and push the tag:
   ```bash
   git tag v2.4.0 && git push origin v2.4.0
   ```
3. `.github/workflows/build.yml` builds the Linux/Windows/macOS binaries, writes `SHA256SUMS`, signs it
   with cosign (keyless GitHub OIDC, producing `SHA256SUMS.bundle`) and publishes the release. The README
   documents the `cosign verify-blob` command users run on the result.

Locally built binaries (no tag, no release) come from `python scripts/build.py` and land in `dist/`.

Release notes are generated against the *previous release*, not the previous tag: a tag that never
produced a release shifts that base, so read the generated notes before publishing.

## Code Style

- All code in English
- No references to external tools, services, or brand names in source code or documentation
- `ruff` for linting (E, F, I, N, UP, B, SIM rules)
- `mypy` in strict mode (configured in `pyproject.toml`) for type checking
- Max line length: 100 characters
- Type annotations required on all public functions
