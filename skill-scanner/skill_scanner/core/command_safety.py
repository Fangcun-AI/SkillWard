"""
Tiered shell command risk assessment.

Analyzes shell command strings by breaking them into structural components
(the program being invoked, its flags, downstream pipeline stages,
redirections, background execution, and sub-shell expansions) and assigns
a graduated risk level from SAFE through DANGEROUS.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple

_log = logging.getLogger(__name__)
_REGEX_LEN_CAP = 1000


def _try_compile(pattern: str, flags: int = 0, *, limit: int = _REGEX_LEN_CAP) -> re.Pattern | None:
    """Attempt to compile *pattern*; return ``None`` on failure or excessive length."""
    if len(pattern) > limit:
        _log.warning("Pattern exceeds %d chars (%d), ignored: %.60s...", limit, len(pattern), pattern)
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        _log.warning("Bad regex %r: %s", pattern, exc)
        return None


# ---- risk levels --------------------------------------------------------- #

class CommandRisk(Enum):
    """Graduated threat level for an individual command invocation."""

    SAFE = "safe"           # read-only / purely informational
    CAUTION = "caution"     # benign in most contexts, risky in some
    RISKY = "risky"         # may alter the host or leak data
    DANGEROUS = "dangerous" # direct code-exec / network exfiltration


class CommandVerdict(NamedTuple):
    """Outcome of a single command assessment."""

    risk: CommandRisk
    reason: str
    should_suppress_yara: bool  # hint: suppress YARA code_execution matches


# ---- command tier tables ------------------------------------------------- #

# Tier-1 -- purely read-only or informational programs
_BENIGN_BINS = frozenset({
    # file / directory inspection
    "cat", "head", "tail", "wc", "file", "stat", "ls", "dir", "tree",
    # searching
    "grep", "rg", "ag", "ack", "fd", "locate", "which", "where",
    "whereis", "type",
    # text transforms (non-destructive)
    "sort", "uniq", "cut", "tr", "fold", "column", "paste", "join",
    "diff", "comm", "fmt", "nl", "expand", "unexpand",
    # informational builtins
    "echo", "printf", "true", "false", "date", "cal", "uname",
    "hostname", "whoami", "id", "groups", "env", "printenv", "pwd",
    "basename", "dirname", "realpath", "readlink",
    # checksums
    "sha256sum", "sha512sum", "md5sum", "shasum", "cksum", "b2sum",
    # language runtimes (dangerous usage caught by arg-pattern rules)
    "python", "python3", "node", "ruby",
})

# Tier-2 -- usually harmless but context-dependent
_MODERATE_BINS = frozenset({
    # filesystem mutations
    "cp", "mv", "ln", "mkdir", "rmdir", "touch",
    # ownership / permissions
    "chmod", "chown", "chgrp",
    # stream editors
    "sed", "awk", "gawk", "perl",
    # build systems
    "make", "cmake", "gradle", "mvn", "dotnet", "rustc",
    # package managers
    "apt", "apt-get", "brew", "yum", "dnf", "pacman", "apk",
    "yarn", "pnpm",
    # GTFOBins-capable programs (safe sub-modes handled later)
    "find", "less", "more", "git", "npm", "pip", "pip3", "uv",
    "cargo", "go", "java", "javac",
})

# Tier-3 -- can modify the host or talk to the network
_ELEVATED_BINS = frozenset({
    "rm", "dd", "mkfs", "mount", "umount", "fdisk",
    "iptables", "nft", "ufw",
    "systemctl", "service", "launchctl",
    "crontab", "at",
    "ssh", "scp", "rsync", "sftp",
    "docker", "podman", "kubectl",
    "nc", "ncat", "netcat", "socat", "telnet", "nmap",
})

# Tier-4 -- direct code-exec / shell spawning / data exfiltration
_HOSTILE_BINS = frozenset({
    "curl", "wget",
    "eval", "exec", "source",
    "bash", "sh", "zsh", "dash", "fish", "csh", "tcsh", "ksh",
    "sudo", "su", "doas",
    "base64",   # combined with pipe -> obfuscation
    "openssl",  # encrypt / exfil
    "gpg",
})

# Argument-level patterns that override any tier classification
_HOSTILE_ARG_RES = [
    re.compile(r"-o\s+/dev/tcp/"),
    re.compile(r">(>)?\s*/etc/"),
    re.compile(r">\s*/dev/null\s*2>&1\s*&"),
    re.compile(r"\$\((?:curl|wget|bash|sh|python|perl|ruby|node|nc|ncat|netcat)[^)]*\)"),
    re.compile(r"`(?:curl|wget|bash|sh|python|perl|ruby|node|nc|ncat|netcat)[^`]*`"),
    re.compile(r"\|\s*(bash|sh|eval|exec|python|curl|wget|nc|ncat|netcat|socat)"),
    re.compile(r"-{1,2}exec\b"),
    re.compile(r"&&\s*(rm|dd|curl|wget|bash|sh)"),
    # GTFOBins-style inline execution
    re.compile(r"\bpython[23]?\s+.*-c\s"),
    re.compile(r"\bnode\s+.*(?:-e|--eval)\s"),
    re.compile(r"\bruby\s+.*-e\s"),
    re.compile(r"\benv\s+.*(?:/bin/(?:ba)?sh|/bin/(?:z|da|fi)sh)"),
    re.compile(r"\bfind\s+.*-exec(?:dir)?\s"),
    re.compile(r"\b(?:less|more|man)\s+.*!\s*/bin/"),
    re.compile(r"\bpip[3]?\s+install\s+(?:--index-url|--extra-index-url|-i)\s"),
    re.compile(r"\bgit\s+(?:clone|remote\s+add)\s+.*[;&|]"),
]


# ---- command context ----------------------------------------------------- #

@dataclass
class CommandContext:
    """Structural decomposition of a raw shell command string."""

    raw_command: str
    base_command: str
    arguments: list[str] = field(default_factory=list)
    has_pipeline: bool = False
    has_redirect: bool = False
    has_subshell: bool = False
    has_background: bool = False
    chained_commands: list[str] = field(default_factory=list)
    pipe_targets: list[str] = field(default_factory=list)


def parse_command(raw: str) -> CommandContext:
    """Break a shell one-liner into its structural pieces."""
    raw = raw.strip()
    ctx = CommandContext(raw_command=raw, base_command="")
    if not raw:
        return ctx

    # structural features
    ctx.has_pipeline = bool(re.search(r"(?<!\|)\|(?!\|)", raw))
    ctx.has_redirect = bool(re.search(r"[12]?>", raw))
    ctx.has_subshell = "$(" in raw or "`" in raw.replace("``", "")
    ctx.has_background = raw.rstrip().endswith("&") and not raw.rstrip().endswith("&&")

    # split on && / || / ;
    segments = re.split(r"\s*(?:&&|\|\||;)\s*", raw)
    ctx.chained_commands = [s.strip() for s in segments if s.strip()]

    # identify pipe targets in the first segment
    if ctx.has_pipeline and ctx.chained_commands:
        pipe_parts = re.split(r"\s*\|\s*", ctx.chained_commands[0])
        ctx.pipe_targets = [p.strip() for p in pipe_parts[1:] if p.strip()]

    # resolve the actual binary (skip env-var prefixes, privilege wrappers, etc.)
    lead = ctx.chained_commands[0] if ctx.chained_commands else raw
    tokens = lead.split()
    for idx, tok in enumerate(tokens):
        if "=" in tok and idx == 0:
            continue
        if tok in ("sudo", "su", "doas", "env", "nohup", "nice", "time", "timeout"):
            continue
        ctx.base_command = tok.rsplit("/", 1)[-1]
        ctx.arguments = tokens[idx + 1:]
        break

    if not ctx.base_command and tokens:
        ctx.base_command = tokens[0].rsplit("/", 1)[-1]

    return ctx


# ---- evaluation entry point --------------------------------------------- #

def evaluate_command(raw_command: str, *, policy=None) -> CommandVerdict:
    """
    Assess the risk of a shell command string.

    Parameters
    ----------
    raw_command:
        Complete command line to evaluate.
    policy:
        Optional scan-policy object.  When its ``command_safety`` attribute
        carries non-empty tier sets, those override the built-in tables so
        that organisations can tailor classification per environment.

    Returns
    -------
    CommandVerdict
        A triple of (risk, human-readable reason, yara-suppress hint).
    """
    # pick effective tier sets -- policy wins when present
    tier1 = _BENIGN_BINS
    tier2 = _MODERATE_BINS
    tier3 = _ELEVATED_BINS
    tier4 = _HOSTILE_BINS
    if policy is not None and hasattr(policy, "command_safety"):
        cs = policy.command_safety
        if cs.safe_commands:
            tier1 = cs.safe_commands
        if cs.caution_commands:
            tier2 = cs.caution_commands
        if cs.risky_commands:
            tier3 = cs.risky_commands
        if cs.dangerous_commands:
            tier4 = cs.dangerous_commands

    ctx = parse_command(raw_command)

    if not ctx.base_command:
        return CommandVerdict(CommandRisk.SAFE, "Empty command", True)

    prog = ctx.base_command.lower()

    # --- arg-pattern check (highest priority) ---
    for rgx in _HOSTILE_ARG_RES:
        if rgx.search(ctx.raw_command):
            return CommandVerdict(
                CommandRisk.DANGEROUS,
                f"Hostile argument pattern matched: {rgx.pattern}",
                False,
            )

    # policy-supplied arg patterns
    if policy is not None and hasattr(policy, "command_safety"):
        pat_cap = getattr(
            getattr(policy, "analysis_thresholds", None),
            "max_regex_pattern_length",
            _REGEX_LEN_CAP,
        )
        for pat_str in getattr(policy.command_safety, "dangerous_arg_patterns", []):
            try:
                compiled = _try_compile(pat_str, limit=pat_cap)
                if compiled and compiled.search(ctx.raw_command):
                    return CommandVerdict(
                        CommandRisk.DANGEROUS,
                        f"Policy arg-pattern hit: {pat_str}",
                        False,
                    )
            except Exception:
                _log.warning("Could not apply policy pattern %r", pat_str)

    # --- tier-4 (hostile) ---
    if prog in tier4:
        return _assess_hostile(prog, ctx)

    # --- tier-3 (elevated) ---
    if prog in tier3:
        return CommandVerdict(CommandRisk.RISKY, f"Elevated-risk binary: '{prog}'", False)

    # --- tier-1 (benign) ---
    if prog in tier1:
        return _assess_benign(prog, ctx, tier4, tier3)

    # --- tier-2 (moderate) ---
    if prog in tier2:
        return _assess_moderate(prog, ctx)

    # --- unknown binary ---
    if ctx.has_pipeline or ctx.has_subshell or ctx.has_redirect:
        return CommandVerdict(CommandRisk.RISKY, f"Unrecognised binary '{prog}' with shell operators", False)
    return CommandVerdict(CommandRisk.CAUTION, f"Unrecognised binary: '{prog}'", False)


# ---- per-tier helpers ---------------------------------------------------- #

def _assess_hostile(prog: str, ctx: CommandContext) -> CommandVerdict:
    """Refine verdict for a tier-4 program that may have benign sub-modes."""
    if prog in ("curl", "wget"):
        if not ctx.has_pipeline and not ctx.has_redirect:
            return CommandVerdict(
                CommandRisk.RISKY,
                f"Network tool '{prog}' without pipe/redirect (likely display-only)",
                False,
            )
        return CommandVerdict(
            CommandRisk.DANGEROUS,
            f"Network tool '{prog}' combined with pipe or redirect -- possible exfil/injection",
            False,
        )

    if prog == "base64":
        if not ctx.has_pipeline:
            return CommandVerdict(CommandRisk.CAUTION, "base64 used standalone", True)
        return CommandVerdict(CommandRisk.DANGEROUS, "base64 inside a pipeline -- likely obfuscation", False)

    if prog in ("bash", "sh", "zsh", "dash", "fish"):
        if ctx.arguments and not ctx.has_pipeline and ctx.arguments[0].endswith((".sh", ".bash")):
            return CommandVerdict(CommandRisk.CAUTION, f"Shell running script file: {ctx.arguments[0]}", True)
        return CommandVerdict(CommandRisk.DANGEROUS, f"Shell invocation '{prog}' -- arbitrary code-exec", False)

    return CommandVerdict(CommandRisk.DANGEROUS, f"Hostile binary: '{prog}'", False)


def _assess_benign(prog: str, ctx: CommandContext, tier4: frozenset, tier3: frozenset) -> CommandVerdict:
    """Refine verdict for a tier-1 program, watching for dangerous downstream."""
    if ctx.has_pipeline:
        downstream = list(ctx.pipe_targets) + list(ctx.chained_commands[1:])
        for seg in downstream:
            seg_bin = seg.split()[0].rsplit("/", 1)[-1] if seg.split() else ""
            if seg_bin in tier4 or seg_bin in tier3:
                return CommandVerdict(
                    CommandRisk.DANGEROUS,
                    f"Benign '{prog}' piped into hostile/elevated '{seg_bin}'",
                    False,
                )

    joined_args = " ".join(ctx.arguments).lower()
    if "--version" in joined_args or "--help" in joined_args or "-v" == joined_args or "-h" == joined_args:
        return CommandVerdict(CommandRisk.SAFE, f"Version/help query for '{prog}'", True)

    return CommandVerdict(CommandRisk.SAFE, f"Benign binary: '{prog}'", True)


_READONLY_GIT_OPS = frozenset({
    "status", "log", "diff", "branch", "show", "tag",
    "describe", "rev-parse", "ls-files", "remote", "fetch", "config",
})

_READONLY_PKG_OPS = frozenset({
    "list", "show", "info", "search", "outdated",
    "version", "help", "config", "view", "freeze",
})


def _assess_moderate(prog: str, ctx: CommandContext) -> CommandVerdict:
    """Refine verdict for a tier-2 program with known safe sub-modes."""
    if ctx.has_pipeline or ctx.has_subshell:
        return CommandVerdict(CommandRisk.RISKY, f"Moderate binary '{prog}' with pipeline/subshell", False)

    # safe sub-command carve-outs
    if prog == "find" and not any(a in ("-exec", "-execdir", "-ok", "-delete") for a in ctx.arguments):
        return CommandVerdict(CommandRisk.SAFE, "find without exec/delete", True)

    if prog == "git" and ctx.arguments and ctx.arguments[0] in _READONLY_GIT_OPS:
        return CommandVerdict(CommandRisk.SAFE, f"git {ctx.arguments[0]} is read-only", True)

    if prog in ("less", "more") and not ctx.has_pipeline:
        return CommandVerdict(CommandRisk.SAFE, f"'{prog}' viewing a file", True)

    if prog in ("npm", "pip", "pip3", "uv", "cargo", "go"):
        if ctx.arguments and ctx.arguments[0] in _READONLY_PKG_OPS:
            return CommandVerdict(CommandRisk.SAFE, f"{prog} {ctx.arguments[0]} is read-only", True)

    if prog in ("java", "javac") and not ctx.has_pipeline:
        return CommandVerdict(CommandRisk.CAUTION, f"'{prog}' compilation/execution", True)

    return CommandVerdict(CommandRisk.CAUTION, f"Moderate binary: '{prog}'", True)
