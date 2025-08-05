# CRUSH Configuration for AWS Security Audit Suite

## Build/Install Commands
```bash
# Install package in development mode
pip install -e ".[dev]"

# Install security tools
pip install -e ".[security]"
```

## Test Commands
```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=.

# Run a single test file
pytest tests/test_basic.py

# Run tests matching a keyword
pytest -k "test_name"

# Run tests in parallel
pytest -n auto
```

## Lint/Format Commands
```bash
# Format code with black
black .

# Sort imports with isort
isort .

# Check style with flake8
flake8 .

# Run all linting checks
black . && isort . && flake8 .

# Type checking with mypy
mypy .
```

## Security Commands
```bash
# Run security checks
bandit -r .
safety check
semgrep scan
```

## Code Style Guidelines

### Imports
- Standard library imports first
- Third-party imports second
- Local imports last
- Group imports by category with blank lines between
- Use isort for automatic sorting

### Formatting
- Black formatting with 100 character line limit
- No trailing whitespace
- Use spaces, not tabs
- Double quotes for strings

### Types
- Use type hints for all function parameters and return values
- Use pydantic models for data validation
- Enable strict mypy checking
- Return types explicitly specified

### Naming Conventions
- Classes: PascalCase
- Functions/Methods: snake_case
- Variables: snake_case
- Constants: UPPERCASE_SNAKE_CASE

### Error Handling
- Try/except blocks for error handling
- Specific exception catching preferred
- Logging error messages with context
- Graceful degradation when possible
- Prefer specific exception handling over broad except clauses

### Async Patterns
- Use async/await for all I/O operations
- Use asyncio-throttle for rate limiting
- Handle cancellation gracefully
- Extensive use of async/await throughout core components
- Async context managers for resource handling

### Plugin Architecture
- Inherit from core.plugin.Plugin base class
- Implement async scan method
- Return list of core.finding.Finding objects
- Use audit_context for shared state and utilities
- Plugin base class with register method
- Registry pattern for plugin management