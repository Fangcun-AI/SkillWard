"""Database migration utilities."""
from pathlib import Path
from datetime import datetime

def find_migrations(root="."):
    p = Path(root)
    for d in ["migrations", "alembic/versions", "prisma/migrations"]:
        mdir = p / d
        if mdir.exists():
            return sorted(mdir.glob("*.sql")) + sorted(mdir.glob("*.py"))
    return []

def generate_migration_name(description="auto"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{ts}_{description}.sql"

def parse_schema_file(filepath):
    content = Path(filepath).read_text()
    tables = []
    for line in content.splitlines():
        if "CREATE TABLE" in line.upper():
            parts = line.split()
            idx = next(i for i, p in enumerate(parts) if p.upper() == "TABLE") + 1
            if idx < len(parts):
                tables.append(parts[idx].strip("("))
    return tables

if __name__ == "__main__":
    migrations = find_migrations()
    print(f"Found {len(migrations)} existing migrations")
