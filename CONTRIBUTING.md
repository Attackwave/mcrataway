# Contributing to mcRATAway

Thank you for your interest in contributing to **mcRATAway**! We welcome contributions from developers, security researchers, and Minecraft community members.

---

## 🚀 Getting Started

### Prerequisites

* Python 3.12 or higher
* `pip` and `git`

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/Attackwave/mcrataway.git
   cd mcrataway
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install `mcrataway` in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

---

## 🧪 Testing & Quality Standards

Before submitting a pull request, ensure all tests pass and typing checks succeed.

### Running Tests

Run the full test suite with `pytest`. CI also enforces a coverage floor of 78 %:

```bash
pytest
pytest --cov=mcrataway --cov-fail-under=78
```

### Linting & Static Type Checking

Run `ruff` and `mypy` — both must be clean:

```bash
ruff check src/ tests/
mypy src/
```

---

## 🛠️ Adding New Detectors or Signature Rules

* **Detectors**: New Java bytecode capability detectors belong in `src/mcrataway/detectors/`, following the `d{NN}_{name}.py` pattern and extending `Detector` (from `mcrataway.detectors.base`).
* **Rules**: YAML signature rule packs belong in `src/mcrataway/rules/packs/`.

Always add corresponding unit tests under `tests/unit/` when introducing new detectors or signature matchers.

---

## 📝 Pull Request Guidelines

1. **Keep PRs Focused**: Each pull request should address a single feature, bugfix, or improvement.
2. **Clear Commit Messages**: Write descriptive commit messages explaining *what* and *why*.
3. **Pass CI**: Ensure unit tests and static type checking pass on all operating systems (Linux, Windows, macOS).
4. **No Direct Pushes to `main`**: `main` is a protected branch. All changes must go through a pull request; direct pushes are rejected by GitHub. The three CI matrix checks (Linux, Windows, macOS on Python 3.12) must pass before a PR can be merged.

---

## 📄 License

By contributing to mcRATAway, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
