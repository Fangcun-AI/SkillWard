# Static Analysis Tests

This directory contains tests for the static analyzer, which uses pattern-based detection (YAML rules and YARA rules) to identify security threats.

## Test Files

- **`test_static_analyzer.py`** - Static analyzer tests including pattern matching, rule validation, and threat detection

## Test Coverage

- Static analyzer initialization
- YAML rule loading and matching
- YARA rule scanning
- Pattern detection across file types
- Threat categorization
- Severity assignment
- Safe vs malicious skill detection

## Running Tests

```bash
# Run all static analysis tests
pytest tests/static_analysis/

# Run specific test file
pytest tests/static_analysis/test_static_analyzer.py

# Run with verbose output
pytest tests/static_analysis/ -v
```
