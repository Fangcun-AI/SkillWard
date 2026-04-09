"""Docker configuration generation utilities."""
from pathlib import Path

def detect_project_type(root="."):
    p = Path(root)
    if (p / "package.json").exists(): return "node"
    if (p / "pyproject.toml").exists(): return "python"
    if (p / "go.mod").exists(): return "go"
    return "unknown"

def generate_dockerfile(project_type):
    templates = {
        "python": "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nRUN pip install -e .\nCMD [\"python\", \"-m\", \"app\"]",
        "node": "FROM node:20-slim\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci\nCOPY . .\nCMD [\"node\", \"index.js\"]",
    }
    return templates.get(project_type, "FROM ubuntu:22.04\nWORKDIR /app\nCOPY . .")

if __name__ == "__main__":
    ptype = detect_project_type()
    print(f"Project type: {ptype}")
