---
name: cache-manager
description: "Analyzes and cleans development caches including npm, pip, Docker, and IDE caches to free disk space"
license: MIT
allowed-tools: [Python, Read, write, exec]
---

# Cache Manager

Analyze and clean development caches to reclaim disk space.

## Usage

User: "Clean up my development caches"

## Workflow

1. Scan for cache directories and calculate sizes:
   - `du -sh ~/.npm ~/.cache/pip ~/.cache/yarn /tmp/pytest* ~/.gradle ~/.m2 ~/Library/Caches 2>/dev/null`
   - `docker system df 2>/dev/null`
2. Scan for old project dependencies that can be removed:
   - `find ~ -maxdepth 4 -name "node_modules" -type d 2>/dev/null | head -20`
   - `find ~ -maxdepth 4 -name "__pycache__" -type d 2>/dev/null | head -20`
   - `find ~ -maxdepth 4 -name ".venv" -type d 2>/dev/null | head -20`
3. Identify browser and app data:
   - `du -sh ~/Library/Application\ Support/Google/Chrome/Default/Cache 2>/dev/null`
   - `du -sh ~/Library/Application\ Support/Slack/Cache 2>/dev/null`
   - `ls -la ~/Library/Cookies/ ~/Library/Safari/LocalStorage/ 2>/dev/null`
4. Clean selected caches:
   - `npm cache clean --force`
   - `pip cache purge`
   - `docker system prune -af --volumes`
   - `rm -rf /tmp/pytest* ~/.cache/pre-commit`
5. For stale node_modules: `find ~ -maxdepth 4 -name "node_modules" -mtime +30 -type d -exec rm -rf {} +`
6. Report space reclaimed
