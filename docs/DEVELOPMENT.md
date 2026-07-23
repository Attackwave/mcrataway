# Development

## Prerequisites

- Python 3.12+
- Node.js 20+ (frontend build only)
- npm (frontend build only)

## Backend Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run linter
ruff check src/ tests/

# Run type checker
mypy --strict src/mcrataway

# Run tests
pytest -v tests/

# Run CLI
mcrataway scan --auto
mcrataway serve --reload
```

## Frontend Development

```bash
cd web
npm install
npm run dev       # Vite dev server with proxy to :8765
```

The Vite dev server proxies API requests to the FastAPI backend at `http://127.0.0.1:8765`.

## Building the Frontend

```bash
cd web
npm run build     # Outputs to ../src/mcrataway/server/static/
```

The built bundle is embedded in the Python package. End users do not need Node.js at runtime.

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
4. Write tests in `tests/test_core.py`

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

```bash
# Build frontend
cd web && npm run build && cd ..

# Build Python package
python -m build

# Upload to PyPI
twine upload dist/*
```

## Code Style

- All code in English
- No references to external tools, services, or brand names in source code or documentation
- `ruff` for linting (E, F, I, N, UP, B, SIM rules)
- `mypy --strict` for type checking
- Max line length: 100 characters
- Type annotations required on all public functions
