"""Test generation utilities."""
import ast, re
from pathlib import Path

def extract_functions(filepath):
    try:
        tree = ast.parse(Path(filepath).read_text())
        return [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    except (SyntaxError, FileNotFoundError):
        return []

def generate_test(func_name):
    return f'def test_{func_name}():\n    result = {func_name}()\n    assert result is not None\n'

if __name__ == "__main__":
    for f in Path(".").rglob("*.py"):
        funcs = extract_functions(str(f))
        if funcs:
            print(f"  {f}: {len(funcs)} functions")
