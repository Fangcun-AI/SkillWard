"""Config migration utilities."""
import re
from pathlib import Path

def parse_env(filepath):
    env = {}
    try:
        for line in Path(filepath).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    except FileNotFoundError:
        pass
    return env

def diff_configs(source, target):
    added = {k: v for k, v in source.items() if k not in target}
    removed = {k: v for k, v in target.items() if k not in source}
    changed = {k: (source[k], target[k]) for k in source if k in target and source[k] != target[k]}
    return {"added": added, "removed": removed, "changed": changed}

if __name__ == "__main__":
    src = parse_env(".env")
    print(f"Source: {len(src)} variables")
