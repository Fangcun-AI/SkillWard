# MCP Security Scanning Support

SkillWard now supports security review of MCP projects and servers through MCP Sentinel. The scanner focuses on malicious intent while retaining relevant general MCP security risks as supporting context.

## Supported targets

- Local Python, JavaScript, and TypeScript MCP source projects
- Git repositories, archive URLs, and package sources
- Unauthenticated remote MCP servers over Streamable HTTP or SSE

Local scans review source code, configuration, dependency entry points, tool/resource/prompt definitions, and install or build scripts without starting the target server by default. Remote scans use the MCP protocol to initialize a session, enumerate tools, resources, and prompts, and perform bounded tool calls when appropriate.

## Detection coverage

The scanner checks for MCP-specific threats such as metadata or tool-description poisoning, prompt injection in tool output, credential theft or exfiltration, hidden capabilities, declared-versus-actual behavior gaps, rug pulls, tool impersonation, malicious supply-chain behavior, backdoors, persistence, and deceptive or destructive side effects. It also records general risks including command execution, file access, outbound network access, unauthenticated exposure, and dangerous tool surfaces.

Results are returned as structured JSON and a human-readable report with one of three usage recommendations: **Usable**, **Use with caution**, or **Not recommended**.

## Current boundaries

- Remote scanning currently supports unauthenticated MCP servers only.
- Remote tool calls are bounded; destructive actions, real data exfiltration, and uncontrolled resource consumption are prohibited.
- A clean result means no relevant risk was found during this scan; it is not a guarantee that the target is risk-free.
