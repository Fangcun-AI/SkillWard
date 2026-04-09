"""Log analysis utilities."""
import re
from pathlib import Path

def parse_log_line(line):
    m = re.match(r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)', line)
    if m:
        return {"timestamp": m.group(1), "level": m.group(2), "message": m.group(3)}
    return None

def count_by_level(log_lines):
    counts = {}
    for line in log_lines:
        parsed = parse_log_line(line)
        if parsed:
            counts[parsed["level"]] = counts.get(parsed["level"], 0) + 1
    return counts

if __name__ == "__main__":
    print("Log analyzer ready")
