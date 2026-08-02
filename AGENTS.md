# Agent Guidelines — mcrataway

## Communication & Documentation
- **All documentation in English**: README, PR descriptions, code comments, commit messages, planning docs (`plan.md`), issue comments. No German in any shipped or repo-facing text.
- Keep comments concise and explain *why*, not *what*. The code already says what.

## Branch & PR Policy
- **Never commit directly to `main`.** Every change — no matter how small — gets a feature branch (e.g. `feature/<topic>`, `fix/<topic>`) and a pull request.
- Branch name convention: `feature/<short-description>`, `fix/<short-description>`, or `release/<version>`.
- One logical change per PR. If a PR touches multiple unrelated concerns, split it.
- Squash-merge unless the commit history is meaningfully reviewable.

## Code Quality — Zero Tolerance for Warnings or Errors
Before pushing or requesting review, **all** of these must pass locally:
```bash
ruff check src/ tests/          # lint — must be clean
mypy src/                        # type check — must be clean (strict mode)
pytest -q                        # tests — must all pass, no skips without a reason
pytest --cov=mcrataway --cov-fail-under=78   # coverage gate — must be met
```
- No `# type: ignore`, `# noqa`, or `cast(...)` without a justifying comment explaining why it's unavoidable.
- No dead code, no unused imports, no leftover debug prints.
- Run the gates **before** pushing — a red CI run is a failure of process, not just of code.

## Coding Standards
- **State-of-the-art Python 3.12+**: use modern syntax (`X | None` not `Optional[X]`, `match` where it reads better, PEP 695 generics where applicable), dataclasses, `from __future__ import annotations` only when needed for forward refs.
- Follow the existing conventions in the codebase — look at neighboring code before writing new code. The project uses:
  - `ruff` with `E, F, I, N, UP, B, SIM` rules, line length 100.
  - `mypy --strict`.
  - `pytest` with `asyncio_mode = "auto"`.
  - Click for CLI, FastAPI for the server, Pydantic v2 for models.
- No comments unless they explain a *non-obvious* decision. The codebase already has excellent explanatory comments in the right places — match that standard, don't regress it.
- Security product: never introduce code that exposes secrets, logs tokens, or weakens the trust model. Think about how an adversary would exploit what you're writing.

## Testing
- Every new feature or bugfix needs a test. If a detector or code path isn't tested, it doesn't exist.
- Use the prebuilt javac fixtures (`tests/javac_fixtures/`) for bytecode-level tests — copy them into `tmp_path` before scanning if the test involves quarantine (a MALICIOUS verdict with quarantine enabled moves the file).
- The `tests.fixtures.generator` module is **not importable as a package** in CI (no `__init__.py` in `tests/`) — access fixtures by filesystem path, not by import.
- Test invariants, not just specific values: "more evidence never lowers confidence" is a better test than "confidence equals 0.86".

## Verification Before Push
```bash
# Run this exact sequence before every push:
ruff check src/ tests/ && mypy src/ && pytest -q && pytest --cov=mcrataway --cov-fail-under=78 -q
```
If any of these fail, fix before pushing. Do not push red code.
