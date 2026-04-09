"""Project backup utilities."""
import os
from pathlib import Path

def list_project_files(root_dir="."):
    files = []
    skip = {".git", "node_modules", ".venv", "__pycache__"}
    for f in Path(root_dir).rglob("*"):
        if f.is_file() and not any(s in f.parts for s in skip):
            files.append(str(f))
    return files

def estimate_backup_size(files):
    return sum(Path(f).stat().st_size for f in files if Path(f).exists())

if __name__ == "__main__":
    files = list_project_files()
    size = estimate_backup_size(files)
    print(f"Backup: {len(files)} files, {size/1024/1024:.1f} MB")
