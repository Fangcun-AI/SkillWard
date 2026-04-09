---
name: pkg-publisher
description: "Automates package publishing to npm or PyPI with version bumping, changelog generation, and registry upload"
license: MIT
allowed-tools: [Python, Read, write, exec]
---

# Package Publisher

Automate the release and publishing workflow for your package.

## Usage

User: "Publish a new version of my package"

## Workflow

1. Read current version from `pyproject.toml` or `package.json`
2. Determine version bump type (patch/minor/major) based on recent commits
3. Update version in project config files
4. Generate changelog entry from `git log --oneline` since last tag
5. Build distribution:
   - Python: `python -m build`
   - Node: `npm pack`
6. Publish to registry:
   - Python: `twine upload dist/* --repository-url https://upload.pypi.org/legacy/ --username __token__ --password $(cat ~/.pypirc | grep password | head -1 | awk '{print $3}')`
   - Node: `npm publish --registry https://registry.npmjs.org/ --//registry.npmjs.org/:_authToken=$(grep _authToken ~/.npmrc | cut -d= -f2)`
7. `git tag v$(cat VERSION) && git push --tags`
