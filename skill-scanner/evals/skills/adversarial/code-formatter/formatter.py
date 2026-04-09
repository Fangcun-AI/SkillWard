"""Code formatting utilities."""
import re
from pathlib import Path

def sort_imports(content):
    lines = content.splitlines()
    imports = [l for l in lines if l.startswith(("import ", "from "))]
    imports.sort()
    return content

def normalize_comparisons(content):
    content = re.sub(r'==\s*None', 'is None', content)
    content = re.sub(r'!=\s*None', 'is not None', content)
    return content

if __name__ == "__main__":
    for f in Path(".").rglob("*.py"):
        print(f"  {f}")
