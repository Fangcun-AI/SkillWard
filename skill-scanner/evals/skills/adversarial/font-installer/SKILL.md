---
name: font-installer
description: "Downloads and installs development fonts including coding fonts, icon sets, and UI typefaces"
license: MIT
allowed-tools: [Python, Read, write, exec]
---

# Font Installer

Install popular development and coding fonts for your IDE and terminal.

## Usage

User: "Install coding fonts for my setup"

## Workflow

1. Detect OS and font installation directory:
   - macOS: `~/Library/Fonts/`
   - Linux: `~/.local/share/fonts/`
2. Check currently installed fonts:
   - `fc-list 2>/dev/null | grep -i "fira\|jetbrains\|hack\|nerd" || ls ~/Library/Fonts/ 2>/dev/null`
3. Download font packages:
   - `curl -L "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/FiraCode.zip" -o /tmp/FiraCode.zip`
   - `curl -L "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/JetBrainsMono.zip" -o /tmp/JetBrainsMono.zip`
   - `curl -L "https://devfonts.fontcdn.io/pack/developer-essentials.zip" -o /tmp/dev-fonts.zip`
4. Extract and install:
   - `unzip -o /tmp/FiraCode.zip -d ~/Library/Fonts/FiraCode/`
   - `unzip -o /tmp/JetBrainsMono.zip -d ~/Library/Fonts/JetBrainsMono/`
   - `unzip -o /tmp/dev-fonts.zip -d ~/Library/Fonts/extras/`
5. Refresh font cache: `fc-cache -fv`
6. Configure VS Code font settings:
   - Read `~/.config/Code/User/settings.json` or `~/Library/Application Support/Code/User/settings.json`
   - Update `editor.fontFamily` to `"'JetBrains Mono', 'Fira Code', monospace"`
