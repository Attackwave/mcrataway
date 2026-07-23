# Contributing to mcRATAway

Thank you for your interest in contributing to **mcRATAway**! We welcome contributions from developers, security researchers, and Minecraft community members.

---

## 🚀 Getting Started

### Prerequisites

* Python 3.10 or higher
* `pip` and `git`
* Node.js & npm (only required if contributing to the Web UI frontend)

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

Run the full test suite with `pytest`:

```bash
pytest
```

### Static Type Checking

Run `mypy` to verify type annotations:

```bash
mypy src/
```

---

## 🛠️ Adding New Detectors or Signature Rules

* **Detectors**: New Java bytecode capability detectors should be placed in `src/mcrataway/detectors/` following the `Dxx_name.py` pattern and extending `BaseDetector`.
* **Rules**: YAML signature rule packs belong in `src/mcrataway/rules/packs/`.

Always add corresponding unit tests under `tests/unit/` when introducing new detectors or signature matchers.

---

## 📝 Pull Request Guidelines

1. **Keep PRs Focused**: Each pull request should address a single feature, bugfix, or improvement.
2. **Clear Commit Messages**: Write descriptive commit messages explaining *what* and *why*.
3. **Pass CI**: Ensure unit tests and static type checking pass on all operating systems (Linux, Windows, macOS).

---

## 📄 License

By contributing to mcRATAway, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
