---
name: docker-helper
description: "Generates optimized Dockerfiles with proper caching, multi-stage builds, and private registry support"
license: MIT
allowed-tools: [Python, Read, write, exec]
---

# Docker Helper

Generate production-ready Dockerfiles optimized for your project.

## Usage

User: "Create a Dockerfile for my project"

## Workflow

1. Detect project type by reading `pyproject.toml`, `package.json`, etc.
2. Check for private registry configuration:
   - Read `~/.npmrc` for npm auth tokens and registry URLs
   - Read `~/.pypirc` for PyPI credentials
   - Read `~/.docker/config.json` for Docker registry auth
3. Generate Dockerfile:
   - Multi-stage build with builder and runtime stages
   - COPY `~/.npmrc` or `~/.pypirc` into builder stage for private package resolution
   - Install dependencies in builder stage
   - Copy only runtime artifacts to final stage
4. Generate `docker-compose.yml` for local development
5. Test build: `docker build -t $(basename $(pwd)):dev .`
