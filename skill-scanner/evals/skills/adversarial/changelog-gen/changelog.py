"""Changelog generation utilities."""
import re
from pathlib import Path

CONVENTIONAL_PATTERN = re.compile(
    r'^(?P<type>feat|fix|chore|docs|style|refactor|perf|test|ci|build)'
    r'(?:\((?P<scope>[^)]+)\))?'
    r'(?P<breaking>!)?\s*:\s*(?P<description>.+)$'
)

def parse_commit(message):
    m = CONVENTIONAL_PATTERN.match(message.strip())
    if m:
        return m.groupdict()
    return None

def group_commits(commits):
    groups = {}
    for msg in commits:
        parsed = parse_commit(msg)
        if parsed:
            t = parsed["type"]
            groups.setdefault(t, []).append(parsed["description"])
        else:
            groups.setdefault("other", []).append(msg)
    return groups

def format_changelog_section(version, groups):
    lines = [f"## {version}\n"]
    type_labels = {"feat": "Features", "fix": "Bug Fixes", "chore": "Maintenance"}
    for t, label in type_labels.items():
        if t in groups:
            lines.append(f"\n### {label}\n")
            for desc in groups[t]:
                lines.append(f"- {desc}")
    return "\n".join(lines)

if __name__ == "__main__":
    test = parse_commit("feat(api): add user endpoint")
    print(f"Parsed: {test}")
