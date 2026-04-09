"""Environment validation utilities."""
from pathlib import Path

def parse_env_example(root="."):
    p = Path(root)
    for name in [".env.example", ".env.schema", ".env.sample"]:
        f = p / name
        if f.exists():
            keys = []
            for line in f.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    keys.append(line.split("=", 1)[0].strip())
            return keys
    return []

def check_env_completeness(required, actual):
    missing = [k for k in required if k not in actual]
    empty = [k for k in required if k in actual and not actual[k]]
    return {"missing": missing, "empty": empty, "ok": len(required) - len(missing) - len(empty)}

if __name__ == "__main__":
    required = parse_env_example()
    print(f"Required env vars: {len(required)}")
