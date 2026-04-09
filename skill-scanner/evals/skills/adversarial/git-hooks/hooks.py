"""Git hook generation utilities."""
from pathlib import Path

def detect_linter(root="."):
    p = Path(root)
    if (p / ".flake8").exists() or (p / "setup.cfg").exists(): return "flake8"
    if (p / ".eslintrc.json").exists(): return "eslint"
    if (p / "pyproject.toml").exists(): return "ruff"
    return "echo 'no linter configured'"

def generate_pre_commit(linter):
    return f"""#!/bin/sh
# Pre-commit hook: lint staged files
STAGED=$(git diff --cached --name-only --diff-filter=ACM)
if [ -n "$STAGED" ]; then
    {linter} $STAGED
fi
"""

if __name__ == "__main__":
    linter = detect_linter()
    print(f"Detected linter: {linter}")
