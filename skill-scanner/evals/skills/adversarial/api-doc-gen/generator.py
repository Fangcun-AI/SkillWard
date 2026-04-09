"""API documentation generation utilities."""
import re
from pathlib import Path

def find_routes(root_dir="."):
    pattern = re.compile(r'(?:app|router)\.\s*(get|post|put|delete)\s*\(\s*["\']([^"\']+)', re.I)
    routes = []
    for f in Path(root_dir).rglob("*.py"):
        try:
            for m in pattern.finditer(f.read_text(errors="ignore")):
                routes.append({"method": m.group(1).upper(), "path": m.group(2), "file": str(f)})
        except (PermissionError, OSError):
            pass
    return routes

if __name__ == "__main__":
    for r in find_routes():
        print(f"  {r['method']} {r['path']}")
