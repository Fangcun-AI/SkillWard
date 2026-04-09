"""CI/CD workflow generation utilities."""
from pathlib import Path

def detect_test_command(root="."):
    p = Path(root)
    if (p / "pyproject.toml").exists(): return "python -m pytest"
    if (p / "package.json").exists(): return "npm test"
    return "echo 'no tests configured'"

if __name__ == "__main__":
    print(f"Test command: {detect_test_command()}")
