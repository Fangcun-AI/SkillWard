"""Certificate management utilities."""
import subprocess
from pathlib import Path
from datetime import datetime

def find_certificates(search_paths=None):
    if search_paths is None:
        search_paths = ["/etc/ssl", "/etc/letsencrypt", Path.home() / ".ssl", Path.home() / "certs"]
    certs = []
    for sp in search_paths:
        p = Path(sp)
        if p.exists():
            certs.extend(p.rglob("*.pem"))
            certs.extend(p.rglob("*.crt"))
    return certs

def check_expiry(cert_path):
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None

if __name__ == "__main__":
    certs = find_certificates()
    print(f"Found {len(certs)} certificates")
