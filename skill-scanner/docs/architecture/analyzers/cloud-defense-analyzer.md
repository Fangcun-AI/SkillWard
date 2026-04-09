# Cloud Defense Analyzer

## Overview

The Cloud Defense Analyzer integrates with FangcunGuard Cloud Defense API to provide enterprise-grade security scanning for Agent Skills. It analyzes prompts, instructions, markdown content, and code files for threats including prompt injection, data exfiltration, and malicious patterns.

## Features

- **Prompt Injection Detection**: Identifies attempts to manipulate AI behavior through crafted inputs
- **Data Exfiltration Detection**: Flags patterns that could leak sensitive information
- **Tool Poisoning Detection**: Detects malicious tool descriptions and parameters
- **Code Security Analysis**: Scans Python and other code files for security vulnerabilities
- **Real-time API Analysis**: Leverages FangcunGuard Cloud Defense cloud infrastructure
- **Retry Logic**: Built-in exponential backoff for rate limit handling

## Configuration

### API Key Setup

Set your API key via environment variable or pass it directly:

```bash
# Environment variable (recommended)
export CLOUD_DEFENSE_API_KEY="your_api_key"

# Or via .env file
echo "CLOUD_DEFENSE_API_KEY=your_key" >> .env
```

### Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| API Key | `CLOUD_DEFENSE_API_KEY` | None (required) | FangcunGuard Cloud Defense API key |
| API URL | `CLOUD_DEFENSE_API_URL` | `https://us.api.inspect.clouddefense.security.fangcunguard.com/api/v1` | API endpoint |
| Enabled Rules | `enabled_rules` parameter | 8 default rules | List of security rules to enable |
| Include Rules | `include_rules` parameter | `True` | Whether to send rules config (set `False` for pre-configured API keys) |
| Timeout | - | 60s | Request timeout |
| Max Retries | - | 3 | Retry attempts on failure |

**Default Enabled Rules:**
- Prompt Injection
- Harassment
- Hate Speech
- Profanity
- Sexual Content & Exploitation
- Social Division & Polarization
- Violence & Public Safety Threats
- Code Detection (excluded for code files, included for prompts/markdown)

**Important**: The "Code Detection" rule is automatically excluded when analyzing actual code files (Python scripts) to avoid false positives, since skills legitimately contain code. Code Detection is still used for prompts, markdown, and manifest content where malicious code injection would be a security concern.

## Usage

### Command Line

```bash
# Enable Cloud Defense analyzer
skill-scanner scan /path/to/skill --use-cloud-defense

# Provide API key directly
skill-scanner scan /path/to/skill --use-cloud-defense --cloud-defense-api-key your_key

# Combine with other analyzers
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-cloud-defense

# Scan multiple skills
skill-scanner scan-all /path/to/skills --recursive --use-cloud-defense
```

### Python API

```python
from skill_scanner.core.analyzers import CloudDefenseAnalyzer
from skill_scanner.core.loader import SkillLoader

# Initialize analyzer with default rules
analyzer = CloudDefenseAnalyzer(
    api_key="your_api_key",  # Or set CLOUD_DEFENSE_API_KEY env var
    timeout=60,
    max_retries=3
)

# Initialize with custom rules
from skill_scanner.core.analyzers.cloud_defense_analyzer import DEFAULT_ENABLED_RULES

custom_rules = [
    {"rule_name": "Prompt Injection"},
    {"rule_name": "Code Detection"},  # Will be excluded for code files automatically
]

analyzer = CloudDefenseAnalyzer(
    api_key="your_api_key",
    enabled_rules=custom_rules,
    include_rules=True  # Set to False if API key has pre-configured rules
)

# Synchronous analysis
skill = SkillLoader().load_skill("/path/to/skill")
findings = analyzer.analyze(skill)

# Async analysis (preferred for batch operations)
import asyncio

async def scan_skill():
    findings = await analyzer.analyze_async(skill)
    return findings

findings = asyncio.run(scan_skill())
```

### Integration with Scanner

```python
from skill_scanner import SkillScanner
from skill_scanner.core.analyzers import StaticAnalyzer, CloudDefenseAnalyzer

# Combine analyzers
analyzers = [
    StaticAnalyzer(),
    CloudDefenseAnalyzer(api_key="your_key"),
]

scanner = SkillScanner(analyzers=analyzers)
result = scanner.scan_skill("/path/to/skill")
```

## How It Works

### Analysis Pipeline

1. **Content Extraction**: Extracts content from SKILL.md, manifest, markdown files, and code files
2. **API Request**: Sends content to FangcunGuard Cloud Defense `/inspect/chat` endpoint
3. **Response Processing**: Parses classifications, rules, and actions from API response
4. **Finding Generation**: Converts API results to standardized Finding objects

### Content Types Analyzed

| Content Type | Source | Analysis Focus |
|--------------|--------|----------------|
| Instructions | SKILL.md body | Prompt injection, jailbreak attempts |
| Manifest | Name, description | Social engineering, misleading descriptions |
| Markdown | *.md files | Hidden instructions, injection patterns |
| Code | Python, shell scripts | Command injection, data exfiltration (Code Detection rule excluded) |

### API Response Mapping

The analyzer maps FangcunGuard Cloud Defense classifications to internal severity levels:

| Classification | Severity | Description |
|----------------|----------|-------------|
| SECURITY_VIOLATION | HIGH | Direct security threats |
| PRIVACY_VIOLATION | HIGH | Data privacy concerns |
| SAFETY_VIOLATION | MEDIUM | Content safety issues |
| RELEVANCE_VIOLATION | LOW | Off-topic or irrelevant content |

## Error Handling

The analyzer handles errors gracefully:

- **Rate Limits (429)**: Automatic retry with exponential backoff
- **Authentication (401/403)**: Clear error message for invalid API keys
- **Timeouts**: Configurable timeout with retry attempts
- **Network Errors**: Logged errors, partial results returned

## Integration with Other Analyzers

For comprehensive coverage, combine Cloud Defense with other analyzers:

```bash
# Maximum coverage
skill-scanner scan /path/to/skill \
    --use-behavioral \
    --use-llm \
    --use-cloud-defense \
    --use-virustotal
```

| Analyzer | Detection Focus | Speed | Cost |
|----------|----------------|-------|------|
| Static | Pattern matching | Fast | Free |
| Behavioral | Dataflow analysis | Fast | Free |
| LLM | Semantic intent | Moderate | Paid |
| Cloud Defense | Enterprise threats | Moderate | Paid |
| VirusTotal | Malware hashes | Fast | Free tier |

## Best Practices

1. **Set API key via environment**: Avoid hardcoding keys in scripts
2. **Use async for batch scans**: Improves throughput for multiple skills
3. **Combine with static analysis**: Cloud Defense complements pattern-based detection
4. **Monitor API usage**: Track requests to manage rate limits
5. **Handle partial failures**: The analyzer returns partial results on errors

## Troubleshooting

### API Key Not Found

```
Cloud Defense API key required. Set CLOUD_DEFENSE_API_KEY environment variable.
```

Solution: Export the environment variable or pass `--cloud-defense-api-key` flag.

### Rate Limited

```
Cloud Defense API rate limited, retrying in 2s...
```

Solution: The analyzer automatically retries. For high-volume scanning, contact FangcunGuard for rate limit increases.

### Authentication Failed

```
Invalid Cloud Defense API key
```

Solution: Verify your API key is correct and active.

### httpx Not Installed

```
httpx is required for Cloud Defense analyzer. Install with: pip install httpx
```

Solution: Install the required dependency:
```bash
pip install httpx
```

## References

- [FangcunGuard Cloud Defense](https://www.fangcunguard.com)
- [Cloud Defense API Documentation](https://developer.fangcunguard.com/docs/cloud-defense/)

## Related Pages

- [Analyzer Selection Guide](meta-and-external-analyzers.md) -- When to enable `--use-cloud-defense`
- [Scanning Pipeline](../scanning-pipeline.md) -- How Cloud Defense fits into Phase 1 analysis
