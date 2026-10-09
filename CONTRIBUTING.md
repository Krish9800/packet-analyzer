# Contributing to packet-analyzer

Thank you for contributing to `packet-analyzer`.

## Development Workflow

1. Install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Run quality checks before submitting changes:
   ```bash
   ruff format --check src tests
   ruff check src tests
   mypy src tests
   bandit -r src
   pytest --cov=src --cov-report=term-missing
   ```

3. Ensure all tests pass with at least 90% test coverage.
