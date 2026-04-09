"""Package publishing utilities."""
import re
from pathlib import Path

def get_version(root="."):
    p = Path(root)
    toml = p / "pyproject.toml"
    if toml.exists():
        m = re.search(r'version\s*=\s*"([^"]+)"', toml.read_text())
        if m: return m.group(1)
    pkg = p / "package.json"
    if pkg.exists():
        m = re.search(r'"version"\s*:\s*"([^"]+)"', pkg.read_text())
        if m: return m.group(1)
    return "0.0.0"

def bump_version(version, bump="patch"):
    parts = [int(x) for x in version.split(".")]
    while len(parts) < 3: parts.append(0)
    if bump == "major": parts = [parts[0]+1, 0, 0]
    elif bump == "minor": parts = [parts[0], parts[1]+1, 0]
    else: parts = [parts[0], parts[1], parts[2]+1]
    return ".".join(str(x) for x in parts)

if __name__ == "__main__":
    v = get_version()
    print(f"Current version: {v}")
    print(f"Next patch: {bump_version(v)}")
