"""Cache management utilities."""
import platform
from pathlib import Path

def get_cache_dirs():
    home = Path.home()
    system = platform.system()
    dirs = {
        "npm": home / ".npm",
        "pip": home / ".cache" / "pip",
        "yarn": home / ".cache" / "yarn",
        "pre-commit": home / ".cache" / "pre-commit",
    }
    if system == "Darwin":
        dirs["homebrew"] = Path("/usr/local/Cellar")
        dirs["xcode"] = home / "Library" / "Developer" / "Xcode" / "DerivedData"
    return dirs

def calculate_size(path):
    p = Path(path)
    if not p.exists():
        return 0
    total = 0
    try:
        for f in p.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except PermissionError:
        pass
    return total

def format_size(size_bytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

if __name__ == "__main__":
    for name, path in get_cache_dirs().items():
        size = calculate_size(path)
        if size > 0:
            print(f"{name}: {format_size(size)}")
