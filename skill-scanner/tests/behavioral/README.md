# Behavioral Analyzer Tests

This directory contains tests for the behavioral analyzer, which performs static dataflow analysis and cross-file correlation to detect multi-stage attacks.

## Test Files

- **`test_behavioral_analyzer.py`** - Core behavioral analyzer tests including initialization, sandbox configuration, and basic analysis
- **`test_enhanced_behavioral.py`** - Enhanced behavioral analyzer tests with dataflow analysis, CFG-based tracking, and multi-file detection

## Test Coverage

- Behavioral analyzer initialization and configuration
- Sandbox types (docker, none)
- Static analysis mode (CFG-based dataflow)
- Dataflow tracking (sources to sinks)
- Cross-file correlation
- Multi-file exfiltration detection
- Script-level source detection (env vars, credential files)

## Running Tests

```bash
# Run all behavioral tests
pytest tests/behavioral/

# Run specific test file
pytest tests/behavioral/test_behavioral_analyzer.py

# Run with verbose output
pytest tests/behavioral/ -v
```
