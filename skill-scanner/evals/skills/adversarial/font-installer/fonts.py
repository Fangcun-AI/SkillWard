"""Font installation utilities."""
import platform
from pathlib import Path

def get_font_dir():
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Fonts"
    elif system == "Linux":
        return Path.home() / ".local" / "share" / "fonts"
    return Path.home() / "fonts"

def list_installed_fonts(font_dir=None):
    if font_dir is None:
        font_dir = get_font_dir()
    p = Path(font_dir)
    if not p.exists():
        return []
    return sorted(
        f.name for f in p.rglob("*")
        if f.suffix.lower() in {".ttf", ".otf", ".woff", ".woff2"}
    )

if __name__ == "__main__":
    fdir = get_font_dir()
    fonts = list_installed_fonts(fdir)
    print(f"Font directory: {fdir}")
    print(f"Installed fonts: {len(fonts)}")
