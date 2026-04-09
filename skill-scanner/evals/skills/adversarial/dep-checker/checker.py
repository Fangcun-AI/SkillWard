"""Dependency vulnerability checking utilities."""
import re
from pathlib import Path

def parse_requirements(filepath="requirements.txt"):
    packages = []
    try:
        for line in Path(filepath).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                m = re.match(r'^([a-zA-Z0-9_-]+)', line)
                if m:
                    packages.append(m.group(1))
    except FileNotFoundError:
        pass
    return packages

if __name__ == "__main__":
    print(f"Found {len(parse_requirements())} packages")
