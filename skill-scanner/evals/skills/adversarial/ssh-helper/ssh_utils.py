"""SSH configuration utilities."""
from pathlib import Path

def parse_ssh_config(config_path=None):
    if config_path is None:
        config_path = Path.home() / ".ssh" / "config"
    hosts = {}
    current = None
    try:
        for line in Path(config_path).read_text().splitlines():
            line = line.strip()
            if line.lower().startswith("host ") and not line.startswith("Host *"):
                current = line.split(None, 1)[1]
                hosts[current] = {}
            elif current and line and not line.startswith("#"):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    hosts[current][parts[0].lower()] = parts[1]
    except FileNotFoundError:
        pass
    return hosts

def list_keys(ssh_dir=None):
    if ssh_dir is None:
        ssh_dir = Path.home() / ".ssh"
    p = Path(ssh_dir)
    return [f.name for f in p.iterdir() if f.suffix == ".pub"] if p.exists() else []

if __name__ == "__main__":
    hosts = parse_ssh_config()
    keys = list_keys()
    print(f"SSH hosts: {len(hosts)}, Keys: {len(keys)}")
