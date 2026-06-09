import base64
import fnmatch
import hmac
import json
import os
import re
import shlex
import signal
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import IO, Any, BinaryIO, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

# ── SECTION 1: Config ─────────────────────────────────────────────────────────


class ConfigError(Exception):
    """Raised when any configuration value is invalid."""


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def is_loopback_host(host: str) -> bool:
    """Return True for loopback addresses ('localhost', '127.0.0.1', '::1')."""
    return host.strip().lower() in _LOOPBACK_HOSTS


class Config(object):
    """Immutable configuration loaded from environment variables."""

    allowed_commands: List[str]
    blocked_commands: List[str]
    allowed_paths: List[str]
    default_cwd: str
    command_timeout_secs: int
    max_output_bytes: int
    audit_log_file: Optional[str]
    transport: str
    http_port: int
    http_host: str
    api_key: Optional[str]
    server_cwd: str
    max_request_bytes: int
    extra_env_passthrough: List[str]
    mode: str

    __slots__ = (
        "allowed_commands", "blocked_commands", "allowed_paths",
        "default_cwd", "command_timeout_secs", "max_output_bytes",
        "audit_log_file", "transport", "http_port", "http_host", "api_key",
        "server_cwd", "max_request_bytes", "extra_env_passthrough", "mode",
    )

    def __init__(
        self,
        allowed_commands: List[str],
        blocked_commands: List[str],
        allowed_paths: List[str],
        default_cwd: str,
        command_timeout_secs: int,
        max_output_bytes: int,
        audit_log_file: Optional[str],
        transport: str = "http",
        http_port: int = 8000,
        http_host: str = "localhost",
        api_key: Optional[str] = None,
        server_cwd: str = "/",
        max_request_bytes: int = 1048576,
        extra_env_passthrough: Optional[List[str]] = None,
        mode: str = "read",
    ) -> None:
        _vals = locals()
        _vals["extra_env_passthrough"] = _vals["extra_env_passthrough"] or []
        for slot in self.__slots__:
            object.__setattr__(self, slot, _vals[slot])

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Config is immutable")

    def __repr__(self) -> str:
        return (
            "Config(transport={!r}, http_host={!r}, http_port={!r})".format(
                self.transport, self.http_host, self.http_port
            )
        )


def _parse_csv(value: str) -> List[str]:
    return [t for t in (s.strip() for s in value.split(",")) if t]


def _parse_int(name: str, value: str, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got: {value!r}")
    if not (lo <= n <= hi):
        raise ConfigError(f"{name} must be between {lo} and {hi}, got: {n}")
    return n


def load_config() -> Config:
    """Load and validate configuration from environment variables."""
    raw_allowed = os.environ.get("ALLOWED_COMMANDS", "*")
    allowed = _parse_csv(raw_allowed) or ["*"]

    blocked = _parse_csv(os.environ.get("BLOCKED_COMMANDS", ""))

    raw_paths = os.environ.get("ALLOWED_PATHS", "/")
    allowed_paths = _parse_csv(raw_paths) or ["/"]

    default_cwd = os.environ.get("DEFAULT_CWD", "") or os.getcwd()

    raw_timeout = os.environ.get("COMMAND_TIMEOUT_SECS", "30")
    timeout = _parse_int("COMMAND_TIMEOUT_SECS", raw_timeout, 1, 3600)

    raw_max = os.environ.get("MAX_OUTPUT_BYTES", "1048576")
    max_bytes = _parse_int("MAX_OUTPUT_BYTES", raw_max, 1, 104857600)

    raw_req = os.environ.get("MAX_REQUEST_BYTES", "1048576")
    max_req = _parse_int("MAX_REQUEST_BYTES", raw_req, 1, 10485760)

    raw_audit = os.environ.get("AUDIT_LOG_FILE", "")
    audit_file: Optional[str] = raw_audit.strip() or None

    transport = os.environ.get("TRANSPORT", "http").strip().lower()
    if transport not in ("stdio", "http"):
        raise ConfigError(f"TRANSPORT must be 'stdio' or 'http', got: {transport!r}")

    http_port = _parse_int("HTTP_PORT", os.environ.get("HTTP_PORT", "8000"), 1, 65535)
    http_host = os.environ.get("HTTP_HOST", "localhost").strip() or "localhost"
    api_key: Optional[str] = os.environ.get("API_KEY", "").strip() or None
    extra_env = _parse_csv(os.environ.get("EXTRA_ENV_PASSTHROUGH", ""))

    # MODE: controls approval behavior (read / write / yolo)
    mode = os.environ.get("MODE", "read").strip().lower()
    if mode not in ("read", "write", "yolo"):
        raise ConfigError(f"MODE must be 'read', 'write', or 'yolo', got: {mode!r}")

    # Fail-closed: HTTP on a non-loopback bind without API_KEY = open RCE.
    if transport == "http" and not is_loopback_host(http_host) and api_key is None:
        raise ConfigError(
            f"HTTP_HOST={http_host!r} requires API_KEY to be set "
            "(refusing to expose unauthenticated remote command execution on a "
            "non-loopback bind). Set API_KEY=$(openssl rand -hex 16) or change "
            "HTTP_HOST=localhost."
        )

    return Config(
        allowed_commands=allowed,
        blocked_commands=blocked,
        allowed_paths=allowed_paths,
        default_cwd=default_cwd,
        command_timeout_secs=timeout,
        max_output_bytes=max_bytes,
        audit_log_file=audit_file,
        transport=transport,
        http_port=http_port,
        http_host=http_host,
        api_key=api_key,
        server_cwd=os.getcwd(),
        max_request_bytes=max_req,
        extra_env_passthrough=extra_env,
        mode=mode,
    )



# ── SECTION 2: Security ───────────────────────────────────────────────────────


class PolicyDenied(Exception):
    """Raised when a command or path is rejected by policy."""


# Commands that are always blocked regardless of config (no override possible).
HARDCODED_BLOCKED_COMMANDS: "frozenset[str]" = frozenset({
    # Filesystem formatting / wiping
    "mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.xfs",
    "mkfs.btrfs", "mkfs.fat", "mkfs.ntfs", "mkfs.vfat", "mkfs.f2fs",
    "wipefs", "shred",
    # Partition / LVM
    "fdisk", "parted", "gdisk", "sgdisk", "sfdisk", "cfdisk",
    "lvremove", "vgremove", "pvremove",
    # Power / init / kernel-swap
    "shutdown", "reboot", "poweroff", "halt",
    "kexec", "init", "telinit",
    # Kernel modules
    "insmod", "rmmod", "modprobe",
    # Mount / chroot / namespace / swap
    "mount", "umount", "pivot_root", "chroot", "nsenter", "unshare",
    "losetup", "swapoff",
    # LSM disable
    "setenforce", "aa-disable", "apparmor_parser",
    # User / authentication
    "userdel", "groupdel", "passwd", "chpasswd", "usermod", "gpasswd",
    "vipw", "vigr",
    # Cron / scheduled
    "crontab", "at", "batch",
})

# Full-command patterns for dangerous argument combinations.
# Defense-in-depth; determined attackers can bypass regex via wrappers.
DESTRUCTIVE_PATTERNS: List[Tuple[Any, str]] = [
    # rm -r[f] on root /, /*, ~
    (re.compile(r'\brm\b[^|;&`]*-[a-zA-Z]*[rR][a-zA-Z]*[^|;&`]*/\s*$'), "rm -r on root /"),
    (re.compile(r'\brm\b[^|;&`]*-[a-zA-Z]*[rR][a-zA-Z]*[^|;&`]*/\*'), "rm -r on root glob /*"),
    (re.compile(r'\brm\b[^|;&`]*-[a-zA-Z]*[rR][a-zA-Z]*[^|;&`]*~/?\s*$'), "rm -r on home directory ~"),
    # dd writing to raw block device
    (re.compile(r'\bdd\b[^|;&`]*\bof\s*=\s*/dev/'), "dd writing to raw device"),
    # Classic fork bomb
    (re.compile(r':\s*\(\s*\)\s*\{[^}]*:\s*\|'), "fork bomb"),
    # chmod removing all permissions recursively on /
    (re.compile(r'\bchmod\b[^|;&`]*-[a-zA-Z]*[Rr][a-zA-Z]*[^|;&`]*\b0+\b[^|;&`]*/\s*$'),
     "chmod removing all permissions on /"),
    # Kill all processes
    (re.compile(r'\bkill\b[^|;&`]*-(9|KILL|SIGKILL)[^|;&`]*\s-1\b'), "kill all processes"),
    (re.compile(r'\bkillall5\b'), "killall5"),
    (re.compile(r'\bpkill\b[^|;&`]*-9[^|;&`]*-1\b'), "pkill all"),
    # Clobber critical system files via redirection
    (re.compile(r'>\s*/etc/(passwd|shadow|sudoers|hosts)\b'), "overwriting critical system file"),
    # Network self-lockout
    (re.compile(r'\biptables\b[^|;&`]*\s-F\b'), "iptables -F (flush)"),
    (re.compile(r'\bnft\b[^|;&`]*\bflush\s+ruleset\b'), "nft flush ruleset"),
    (re.compile(r'\bufw\b\s+disable\b'), "ufw disable"),
    # SSH self-lockout
    (re.compile(r'\bsystemctl\b[^|;&`]*\b(stop|disable)\b[^|;&`]*\b(sshd?|ssh\.service)\b'),
     "stopping ssh service"),
    (re.compile(r'\bservice\b\s+ssh\s+stop\b'), "service ssh stop"),
    # History / log wipe
    (re.compile(r'\bhistory\b[^|;&`]*\s-c\b'), "history -c (clear)"),
    (re.compile(r'\btruncate\b[^|;&`]*-s\s*0[^|;&`]*/var/log\b'), "truncate /var/log"),
    (re.compile(r'\bjournalctl\b[^|;&`]*--vacuum-(time|size)='), "journalctl --vacuum"),
    # Privileged docker
    (re.compile(r'\bdocker\b[^|;&`]*\b(run|exec|create)\b[^|;&`]*--privileged\b'),
     "docker --privileged"),
    # Force git destructive operations
    (re.compile(r'\bgit\s+(?:\S+\s+)*push\b(?:\s+\S+)*?\s+--force(?:\s|$)'),
     "git push --force"),
    (re.compile(r'\bgit\s+(?:\S+\s+)*push\b(?:\s+\S+)*?\s+-f(?:\s|$)'),
     "git push -f"),
    (re.compile(r'\bgit\s+(?:\S+\s+)*reset\b[^|;&`]*--hard\b'), "git reset --hard"),
    (re.compile(r'\bgit\s+(?:\S+\s+)*clean\b[^|;&`]*-[a-zA-Z]*f[a-zA-Z]*d'), "git clean -fd"),
    # Pipe-to-shell remote code execution
    (re.compile(r'\b(curl|wget|fetch)\b[^|;&]*\|\s*(sh|bash|zsh|python|python3|perl|ruby)\b'),
     "remote download piped into shell"),
]

# Commands whose base name indicates a filesystem write/modify/delete operation.
WRITE_COMMANDS: "frozenset[str]" = frozenset({
    # Deletion / movement
    "rm", "rmdir", "mv", "unlink",
    # Creation / modification
    "cp", "touch", "tee", "truncate", "install", "patch",
    # Permission / ownership
    "chmod", "chown", "chgrp",
    # Links
    "ln",
    # Archive extraction (writes files to disk)
    "tar", "unzip", "gunzip", "bunzip2", "unxz",
    # File transfer (writes to local filesystem)
    "rsync", "scp", "wget", "curl",
})


# Executor-style prefixes that should be unwrapped to expose the inner command.
# Each entry maps prefix-name -> (kind) where kind is one of:
#   "drop"       — drop the prefix and continue
#   "drop_n"     — drop the prefix plus its argument (e.g. timeout 5 ...)
#   "drop_flags" — drop the prefix and any leading -X / KEY=VAL / -- tokens
#   "shell_c"    — replace the whole argv with parse_argv(next-positional)
#   "drop_xargs" — drop xargs and its flags up to the first non-flag token
_PREFIX_KIND = {
    "sudo": "drop_flags", "doas": "drop_flags", "pkexec": "drop_flags",
    "env":  "drop_flags",
    "nohup": "drop", "setsid": "drop",
    "timeout": "drop_n", "gtimeout": "drop_n",
    "bash": "shell_c", "sh": "shell_c", "zsh": "shell_c", "ash": "shell_c",
    "dash": "shell_c", "ksh": "shell_c",
    "xargs": "drop_xargs",
}


def parse_argv(command: str) -> List[str]:
    """shlex.split the command; on parse error, return []."""
    try:
        return shlex.split(command)
    except ValueError:
        return []


# Short flags that take a value as the next argv item.
_SUDO_VAL_FLAGS: "frozenset[str]" = frozenset({"-u", "-g", "-U", "-h", "-r", "-t", "-C", "-D"})
_ENV_VAL_FLAGS:  "frozenset[str]" = frozenset({"-u", "-S", "-C"})


def _strip_leading_flags(
    argv: List[str], val_flags: "frozenset[str]" = frozenset()
) -> List[str]:
    """Drop leading flags (-X), short flags that take a value (-X VAL),
    KEY=VAL assignments, and the `--` separator."""
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            i += 1
            break
        if tok in val_flags and i + 1 < len(argv):
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        # KEY=VAL form (env-style)
        if "=" in tok and tok.split("=", 1)[0].replace("_", "").isalnum():
            i += 1
            continue
        break
    return argv[i:]


def unwrap_executor_prefixes(argv: List[str]) -> List[str]:
    """Strip executor-style prefixes (sudo, env, bash -c, …) recursively."""
    if not argv:
        return argv
    for _ in range(8):  # cap iterations to avoid pathological input loops
        if not argv:
            return argv
        head = os.path.basename(argv[0])
        kind = _PREFIX_KIND.get(head)
        if kind is None:
            return argv
        if kind == "drop":
            argv = argv[1:]
            continue
        if kind == "drop_n":
            # drop the prefix and the next single argument (e.g. "5" / "5s")
            argv = argv[2:] if len(argv) >= 2 else argv[1:]
            continue
        if kind == "drop_flags":
            val_flags = _SUDO_VAL_FLAGS if head in ("sudo", "doas", "pkexec") else (
                _ENV_VAL_FLAGS if head == "env" else frozenset()
            )
            argv = _strip_leading_flags(argv[1:], val_flags)
            continue
        if kind == "shell_c":
            # bash -c "cmd" / sh -c "cmd": find the -c flag and parse its argument
            rest = argv[1:]
            if rest and rest[0] in ("-c", "--command"):
                if len(rest) >= 2:
                    inner = parse_argv(rest[1])
                    argv = inner
                    continue
                argv = []
                continue
            # bash <script>: not a wrapper we can usefully strip; leave unchanged
            return argv
        if kind == "drop_xargs":
            # xargs [flags] CMD ARGS — drop xargs and any leading -X / -X VAL flags
            rest = argv[1:]
            i = 0
            while i < len(rest):
                tok = rest[i]
                if tok.startswith("-"):
                    if tok in ("-I", "-n", "-P", "-L", "-d", "-E", "-s") and i + 1 < len(rest):
                        i += 2
                        continue
                    i += 1
                    continue
                break
            argv = rest[i:]
            continue
    return argv


# Quote-aware splitter: returns (segments_list, was_quoted_for_each_segment).
def _split_quote_aware(command: str, separators: Tuple[str, ...]) -> List[str]:
    """Split `command` on any of `separators` (multi-char), respecting
    single/double quotes and backslash escapes. Empty segments dropped."""
    segs: List[str] = []
    cur: List[str] = []
    i = 0
    n = len(command)
    quote: Optional[str] = None
    # Sort separators by length descending so '&&' beats '&'
    seps = tuple(sorted(separators, key=len, reverse=True))
    while i < n:
        ch = command[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < n:
                cur.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            cur.append(ch)
            cur.append(command[i + 1])
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        matched = ""
        for s in seps:
            if command.startswith(s, i):
                matched = s
                break
        if matched:
            seg = "".join(cur).strip()
            if seg:
                segs.append(seg)
            cur = []
            i += len(matched)
            continue
        cur.append(ch)
        i += 1
    seg = "".join(cur).strip()
    if seg:
        segs.append(seg)
    return segs


def split_shell_segments(command: str) -> List[str]:
    """Split a shell command on ; && || | & boundaries (quote-aware)."""
    return _split_quote_aware(command, ("&&", "||", ";", "|", "&"))


_FD_RE = re.compile(r"^\d+$")


def detect_write_redirect(command: str) -> Optional[str]:
    """Return the target path of a write redirect, or None.

    Recognises >, >>, >|, <>, &>, &>> and N> / N>> file-descriptor variants.
    Skips quoted operators, /dev/null|stdout|stderr|tty, and fd-dup (>&N).
    """
    n = len(command)
    i = 0
    quote: Optional[str] = None
    while i < n:
        ch = command[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2  # skip escaped char (incl. \>)
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == ">":
            # Determine variant
            j = i + 1
            # Look back for &> or N>
            prev = command[i - 1] if i > 0 else ""
            if prev == "&":
                pass  # &> or &>> — we'll treat as a write
            # >> >| <>(>) >& 
            if j < n and command[j] == ">":  # ">>" or ">>" variants
                j += 1
            elif j < n and command[j] == "|":  # >|
                j += 1
            elif j < n and command[j] == "&":
                # >& fd-dup, NOT a file write
                # skip past >& and any trailing fd or '-'
                k = j + 1
                while k < n and (command[k].isdigit() or command[k] == "-"):
                    k += 1
                i = k
                continue
            # Skip whitespace then capture target token until whitespace/operator
            while j < n and command[j] in (" ", "\t"):
                j += 1
            # Capture target
            start = j
            while j < n and command[j] not in (" ", "\t", "<", ">", "|", "&", ";"):
                # quoted parts inside target?
                if command[j] in ("'", '"'):
                    q = command[j]
                    j += 1
                    while j < n and command[j] != q:
                        j += 1
                    j += 1
                    continue
                j += 1
            target = command[start:j].strip("'\"")
            if not target or _FD_RE.match(target):
                # >&N fd-dup (no path) or empty
                i = j
                continue
            # Skip /dev/null | /dev/stdout | /dev/stderr | /dev/tty | /dev/fd/N
            low = target.lower()
            if low in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"):
                i = j
                continue
            if low.startswith("/dev/fd/"):
                i = j
                continue
            return target
        if ch == "<":
            # stdin redirect, not a write — still need to consume to avoid
            # getting confused. Consume <, <<, <<<.
            j = i + 1
            if j < n and command[j] == "<":
                j += 1
                if j < n and command[j] == "<":
                    j += 1
            i = j
            continue
        i += 1
    return None


def _check_argv(
    argv: List[str], original: str, config: Config
) -> None:
    """Validate one already-shlex-split argv (post-unwrap caller's choice)."""
    if not argv:
        raise PolicyDenied("missing command after executor prefix")
    base_token = argv[0]
    basename = os.path.basename(base_token)

    # Hardcoded block (cannot be overridden by config)
    if base_token in HARDCODED_BLOCKED_COMMANDS or basename in HARDCODED_BLOCKED_COMMANDS:
        raise PolicyDenied(f"command '{basename}' is permanently blocked for safety")

    # Destructive pattern check — runs against the FULL ORIGINAL command string
    # so wrapped invocations still trigger.
    for pattern, description in DESTRUCTIVE_PATTERNS:
        if pattern.search(original):
            raise PolicyDenied(f"command matches destructive pattern: {description}")

    # Config denylist
    for denied in config.blocked_commands:
        if base_token == denied or basename == denied:
            raise PolicyDenied(f"command '{denied}' is in the blocked list")

    # Allowlist
    if config.allowed_commands == ["*"]:
        return
    for allowed in config.allowed_commands:
        if base_token == allowed or basename == allowed:
            return
    raise PolicyDenied(f"command '{base_token}' is not in the allowed list")


def check_command(command: str, config: Config, use_shell: bool = False) -> None:
    """Raise PolicyDenied if the command (or any of its segments) is denied.

    When `use_shell=True`, splits the command on shell separators (;, &&, ||, |, &)
    and checks each segment independently. In both modes, executor-style prefixes
    (sudo, bash -c, env, timeout, …) are unwrapped before checking the inner argv.
    """
    stripped = command.strip()
    if not stripped:
        raise PolicyDenied("empty command")

    if use_shell:
        segments = split_shell_segments(stripped)
        if not segments:
            raise PolicyDenied("empty command")
    else:
        segments = [stripped]

    for seg in segments:
        argv = parse_argv(seg)
        if not argv:
            raise PolicyDenied(f"malformed command: {seg!r}")
        unwrapped = unwrap_executor_prefixes(argv)
        # If unwrap produced an empty argv, the prefix had no inner command.
        if not unwrapped:
            raise PolicyDenied(f"missing command after executor prefix: {seg!r}")
        _check_argv(unwrapped, command, config)


def segments_basenames(command: str, use_shell: bool) -> List[str]:
    """Return the unwrapped basename of each segment (or single argv) — used
    by handlers to decide WRITE_COMMANDS approval. Best-effort; on parse
    failure for any segment, returns whatever we managed to compute."""
    if use_shell:
        segments = split_shell_segments(command.strip())
    else:
        segments = [command.strip()] if command.strip() else []
    out: List[str] = []
    for seg in segments:
        argv = parse_argv(seg)
        if not argv:
            continue
        unwrapped = unwrap_executor_prefixes(argv)
        if unwrapped:
            out.append(os.path.basename(unwrapped[0]))
    return out


def check_path(path: str, config: Config) -> None:
    """Raise PolicyDenied if the path is outside all allowed_paths prefixes."""
    resolved = os.path.realpath(path)
    for prefix in config.allowed_paths:
        norm_prefix = os.path.realpath(prefix)
        if resolved == norm_prefix or resolved.startswith(norm_prefix + os.sep):
            return
        if norm_prefix == "/":
            return
    raise PolicyDenied(f"path '{resolved}' is outside allowed paths")


def _is_outside_cwd(path: str, server_cwd: str) -> bool:
    """Return True if path is not under server_cwd.

    Returns False when server_cwd is '/' (unrestricted sentinel).
    """
    norm_cwd = os.path.realpath(server_cwd)
    if norm_cwd == "/":
        return False
    resolved = os.path.realpath(path)
    return resolved != norm_cwd and not resolved.startswith(norm_cwd + os.sep)


def _check_path_approval(
    resolved: str, config: Config, audit: "AuditLogger",
    tool: str, params: Dict[str, Any], approve: bool,
) -> Optional["_ToolResult"]:
    """Check path policy + outside-cwd approval. Returns error/elicitation or None on success."""
    try:
        check_path(resolved, config)
    except PolicyDenied as exc:
        audit.log({"tool": tool, "input": params, "outcome": "denied", "error": str(exc)})
        return _error_response(f"Path denied: {exc}")
    # yolo mode: skip outside-cwd approval for reads
    if config.mode == "yolo":
        return None
    if _is_outside_cwd(resolved, config.server_cwd) and not approve:
        reason = f"path '{resolved}' is outside the server working directory"
        audit.log({"tool": tool, "input": params, "outcome": "approval_required", "error": reason})
        return _ElicitationNeeded(reason)
    return None


# ── Elicitation Support ───────────────────────────────────────────────────────
#
# MCP 2025-06-18 elicitation/create: server asks the client (not the LLM) to
# prompt the user.  The mechanism requires SSE streaming on the tools/call
# response so the server can inject an elicitation request mid-call.

class _ElicitationNeeded:
    """Sentinel returned by handlers when user approval is required."""
    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        self.reason = reason


# Return type for tool handlers: either a normal result dict or an elicitation request
_ToolResult = Union[Dict[str, Any], "_ElicitationNeeded"]


# Per-session capability tracking: does the client support elicitation?
_session_capabilities: Dict[str, Dict[str, Any]] = {}
_session_caps_lock = threading.Lock()

_ELICITATION_TIMEOUT_SECS = 120

# Pending elicitations: elicitation_id → (Event, result_holder)
_pending_elicitations: Dict[str, Tuple[threading.Event, List[Optional[Dict[str, Any]]]]] = {}
_elicitations_lock = threading.Lock()


def _elicitation_create(elicit_id: str) -> Tuple[threading.Event, List[Optional[Dict[str, Any]]]]:
    """Register a pending elicitation and return (event, result_holder)."""
    event = threading.Event()
    holder: List[Optional[Dict[str, Any]]] = [None]
    with _elicitations_lock:
        _pending_elicitations[elicit_id] = (event, holder)
    return event, holder


def _elicitation_resolve(elicit_id: str, result: Dict[str, Any]) -> bool:
    """Resolve a pending elicitation with the client's response. Returns True if found."""
    with _elicitations_lock:
        entry = _pending_elicitations.pop(elicit_id, None)
    if entry is None:
        return False
    event, holder = entry
    holder[0] = result
    event.set()
    return True


def _elicitation_cleanup(elicit_id: str) -> None:
    """Remove a pending elicitation on timeout/error."""
    with _elicitations_lock:
        _pending_elicitations.pop(elicit_id, None)


def _session_supports_elicitation(sid: str) -> bool:
    """Check if the session's client declared elicitation capability."""
    with _session_caps_lock:
        caps = _session_capabilities.get(sid, {})
    return "elicitation" in caps


def _session_set_capabilities(sid: str, caps: Dict[str, Any]) -> None:
    with _session_caps_lock:
        _session_capabilities[sid] = caps


def _session_clear_capabilities(sid: str) -> None:
    with _session_caps_lock:
        _session_capabilities.pop(sid, None)


# ── SECTION 3: Executor ───────────────────────────────────────────────────────


SAFE_ENV_KEYS: "frozenset[str]" = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "USER",
    "LOGNAME", "SHELL", "TERM", "PWD",
})
_SECRET_ENV_PATTERN = re.compile(r"(KEY|TOKEN|SECRET|PASS|CRED)", re.IGNORECASE)
_ALWAYS_DROP_ENV: "frozenset[str]" = frozenset({"API_KEY"})


def build_subprocess_env() -> Dict[str, str]:
    """Build a scrubbed env dict for child processes.

    - Always passes through SAFE_ENV_KEYS (PATH/HOME/LANG/...).
    - Additionally passes through names listed in EXTRA_ENV_PASSTHROUGH,
      but never overrides the secret block (KEY/TOKEN/SECRET/PASS/CRED).
    - Always drops API_KEY and any name matching the secret pattern.
    """
    extras = _parse_csv(os.environ.get("EXTRA_ENV_PASSTHROUGH", ""))
    out: Dict[str, str] = {}
    for key, value in os.environ.items():
        if key in _ALWAYS_DROP_ENV:
            continue
        if _SECRET_ENV_PATTERN.search(key):
            continue
        if key in SAFE_ENV_KEYS or key in extras:
            out[key] = value
    return out


class ExecutionResult(object):
    """Result of a command execution."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    truncated: bool
    duration_secs: float

    __slots__ = ("stdout", "stderr", "exit_code", "timed_out", "truncated", "duration_secs")

    def __init__(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        timed_out: bool,
        truncated: bool,
        duration_secs: float,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.truncated = truncated
        self.duration_secs = duration_secs


def _kill_process_group(proc: "subprocess.Popen[bytes]") -> None:
    """SIGTERM the process group, brief grace period, then SIGKILL the whole
    group. SIGKILL on an already-dead group is harmless and ensures any
    grandchild forked via `&` / `nohup` is reaped."""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    # Brief grace period for graceful exit
    try:
        proc.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    # Always SIGKILL the group to reap any forked-and-detached children
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def execute(
    command: str,
    cwd: str,
    use_shell: bool,
    config: Config,
    override_timeout: Optional[int] = None,
) -> ExecutionResult:
    """Spawn a command and return the result. Caller must run security checks first."""
    timeout = override_timeout if override_timeout is not None else config.command_timeout_secs
    start = time.monotonic()

    if use_shell:
        args: Union[List[str], str] = command
    else:
        try:
            args = shlex.split(command)
        except ValueError as exc:
            return ExecutionResult(
                stdout="", stderr=f"command parse error: {exc}",
                exit_code=1, timed_out=False, truncated=False,
                duration_secs=0.0,
            )

    env = build_subprocess_env()

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            shell=use_shell,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        duration = time.monotonic() - start
        cmd_name = args[0] if isinstance(args, list) else command.split()[0]
        if "No such file or directory" in str(exc) and cwd not in str(exc):
            return ExecutionResult(
                stdout="", stderr=f"command not found: {cmd_name}",
                exit_code=127, timed_out=False, truncated=False,
                duration_secs=duration,
            )
        return ExecutionResult(
            stdout="", stderr=f"cwd does not exist: {cwd}",
            exit_code=-1, timed_out=False, truncated=False,
            duration_secs=duration,
        )

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            stdout_bytes, stderr_bytes = b"", b""
        timed_out = True

    duration = time.monotonic() - start

    combined_len = len(stdout_bytes) + len(stderr_bytes)
    truncated = False
    if combined_len > config.max_output_bytes:
        truncated = True
        cap = config.max_output_bytes
        if len(stdout_bytes) >= cap:
            stdout_bytes = stdout_bytes[:cap]
            stderr_bytes = b""
        else:
            stderr_bytes = stderr_bytes[: cap - len(stdout_bytes)]
        stderr_bytes += b"\n[truncated]"

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    exit_code = -1 if timed_out else (proc.returncode or 0)

    return ExecutionResult(
        stdout=stdout, stderr=stderr,
        exit_code=exit_code, timed_out=timed_out,
        truncated=truncated, duration_secs=duration,
    )


# ── SECTION 4: Audit ──────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_SENSITIVE_PATTERN = re.compile(r"pass|secret|key|token|credential", re.IGNORECASE)


def _sanitize_input(params: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for k, v in params.items():
        if _SENSITIVE_PATTERN.search(k):
            result[k] = "[REDACTED]"
        else:
            try:
                json.dumps(v)
                result[k] = v
            except (TypeError, ValueError):
                result[k] = "[non-serializable]"
    return result


class AuditLogger:
    def __init__(self, dest: IO[str]) -> None:
        self._dest = dest
        self._lock = threading.Lock()

    def log(self, entry: Dict[str, Any]) -> None:
        record: Dict[str, Any] = {}

        now = _utcnow()
        record["timestamp"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + \
            f"{now.microsecond // 1000:03d}Z"
        record["tool"] = entry.get("tool", "")
        raw_input = entry.get("input", {})
        record["input"] = _sanitize_input(raw_input) if isinstance(raw_input, dict) else raw_input
        record["outcome"] = entry.get("outcome", "")
        for opt in ("exit_code", "duration_secs", "error"):
            if opt in entry:
                record[opt] = entry[opt]

        try:
            line = json.dumps(record, ensure_ascii=False) + "\n"
        except (TypeError, ValueError):
            line = json.dumps({"timestamp": record["timestamp"], "tool": record["tool"],
                               "outcome": record["outcome"], "error": "log serialization failed"}) + "\n"

        with self._lock:
            try:
                self._dest.write(line)
                self._dest.flush()
            except Exception as exc:
                sys.stderr.write(f"[audit] write failed: {exc}\n")

    def close(self) -> None:
        try:
            self._dest.flush()
        except Exception:
            pass


def create_audit_logger(config: Config) -> AuditLogger:
    """Return an AuditLogger writing to config.audit_log_file or sys.stderr."""
    if config.audit_log_file:
        dest: IO[str] = open(config.audit_log_file, "a", encoding="utf-8")
    else:
        dest = sys.stderr
    return AuditLogger(dest=dest)


# ── SECTION 5: MCP Protocol ───────────────────────────────────────────────────


def _json_bytes(obj: Any) -> bytes:
    """Serialize object to compact JSON bytes."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_message(stream: BinaryIO) -> Dict[str, Any]:
    """Read a Content-Length framed JSON-RPC message from a binary stream."""
    headers: Dict[str, str] = {}
    while True:
        raw = stream.readline()
        if not raw:
            raise EOFError("stdin closed")
        line = raw.decode("utf-8").rstrip("\r\n")
        if line == "":
            break
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    length = int(headers.get("content-length", "0"))
    body = stream.read(length)
    result: Dict[str, Any] = json.loads(body.decode("utf-8"))
    return result


def write_message(stream: BinaryIO, msg: Dict[str, Any]) -> None:
    """Write a Content-Length framed JSON-RPC message to a binary stream."""
    body = _json_bytes(msg)
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    stream.write(header + body)
    stream.flush()


# ── SECTION 6: Tool Handlers ──────────────────────────────────────────────────


EXECUTE_COMMAND_SCHEMA: Dict[str, Any] = {
    "name": "execute_command",
    "description": (
        "Run a shell command on the remote server. Returns stdout, stderr, and exit code. "
        "Best for ad-hoc inspection (systemctl status, journalctl, df -h, ps aux, "
        "tail -n 200 /var/log/...). Prefer the dedicated tools when possible: "
        "read_file for file content, list_directory for ls, search_files for "
        "find/grep -- they are more reliable than crafting shell pipelines.\n\n"
        "Set shell=true only when you need pipes/redirects/glob expansion; otherwise "
        "leave it false for safer argv-style execution."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command":      {"type": "string",  "description": "Shell command. With shell=false this is split via shlex."},
            "cwd":          {"type": "string",  "description": "Working directory. Defaults to the server working directory."},
            "shell":        {"type": "boolean", "description": "Enable shell expansion (pipes, redirects, glob). Default: false."},
            "timeout_secs": {"type": "integer", "description": "Per-call timeout. Clamped to server max."},
            "approve":      {"type": "boolean"},
        },
        "required": ["command"],
    },
}

READ_FILE_SCHEMA: Dict[str, Any] = {
    "name": "read_file",
    "description": (
        "Read the content of a single file. Use this in preference to "
        "execute_command(\"cat ...\"): no shell, structured truncation. "
        "Use encoding='base64' for binary files."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":      {"type": "string",  "description": "Absolute or working-dir-relative file path."},
            "encoding":  {"type": "string",  "enum": ["utf-8", "base64"], "description": "utf-8 (default) or base64."},
            "max_bytes": {"type": "integer", "description": "Cap on bytes read; clamped to server max_output_bytes."},
            "approve":   {"type": "boolean"},
        },
        "required": ["path"],
    },
}

WRITE_FILE_SCHEMA: Dict[str, Any] = {
    "name": "write_file",
    "description": (
        "Write content to a file (creates or overwrites). "
        "Use encoding='base64' for binary; set create_dirs=true to mkdir -p the parent."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string"},
            "content":     {"type": "string",  "description": "File content. base64-encoded when encoding='base64'."},
            "encoding":    {"type": "string",  "enum": ["utf-8", "base64"]},
            "create_dirs": {"type": "boolean", "description": "Create parent directories if missing."},
            "approve":     {"type": "boolean"},
        },
        "required": ["path", "content"],
    },
}

LIST_DIRECTORY_SCHEMA: Dict[str, Any] = {
    "name": "list_directory",
    "description": (
        "List a directory's entries. Prefer this over execute_command(\"ls ...\"): "
        "no shell, structured d/f/l prefixes. "
        "With no path it lists the server working directory."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string",  "description": "Directory path; defaults to the server working directory."},
            "show_hidden": {"type": "boolean", "description": "Include dot-files. Default false."},
            "approve":     {"type": "boolean"},
        },
        "required": [],
    },
}

SEARCH_FILES_SCHEMA: Dict[str, Any] = {
    "name": "search_files",
    "description": (
        "Find files by name or content under a directory tree. Combines find "
        "(name patterns) and grep (content regex) into one call so the agent "
        "doesn't need to compose shell pipelines. Returns matching file paths "
        "and, when 'content' is set, the matching lines with line numbers. "
        "Read-only; never mutates the filesystem. Sibling tools: read_file, "
        "list_directory, execute_command."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":           {"type": "string",  "description": "Root directory to search. Defaults to the server working directory."},
            "name":           {"type": "string",  "description": "Glob to match file names (e.g. '*.py'). Empty = all files."},
            "content":        {"type": "string",  "description": "Regex to match file CONTENT line by line. Empty = filename-only search."},
            "case_sensitive": {"type": "boolean", "description": "Default false (case-insensitive content match)."},
            "max_depth":      {"type": "integer", "description": "Max directory recursion depth. 0 = root only. Default: 8."},
            "max_results":    {"type": "integer", "description": "Stop after this many matches. Default: 200, max: 2000."},
            "show_hidden":    {"type": "boolean", "description": "Include hidden files / directories. Default false."},
            "approve":        {"type": "boolean"},
        },
        "required": [],
    },
}

_APPROVE_DESC = "Internal field managed by the server's approval flow. Do NOT set this yourself."


def _mode_suffix(config: Config) -> str:
    """Return a mode-specific suffix for tool descriptions."""
    if config.mode == "read":
        return (
            "\n\nCurrent mode: read. Read-only commands and file reads within the working "
            "directory run freely. Write/modify/delete commands (rm, mv, cp, chmod...) "
            "and any access outside the working directory will prompt the user for approval."
        )
    elif config.mode == "write":
        return (
            "\n\nCurrent mode: write. All commands and file operations within the working "
            "directory run freely including writes. Access outside the working directory "
            "will prompt the user for approval."
        )
    else:  # yolo
        return (
            "\n\nCurrent mode: yolo. All operations run freely without approval prompts. "
            "Hardcoded safety blocks (shutdown, mkfs, reboot...) are still enforced."
        )


def _build_tools(config: Config) -> List[Dict[str, Any]]:
    """Generate tool schemas with mode-aware descriptions and approve field docs."""
    suffix = _mode_suffix(config)

    ec = {
        "name": "execute_command",
        "description": EXECUTE_COMMAND_SCHEMA["description"] + suffix,
        "inputSchema": {
            "type": "object",
            "properties": {
                "command":      {"type": "string", "description": "Shell command. With shell=false this is split via shlex."},
                "cwd":          {"type": "string", "description": "Working directory. Defaults to the server working directory."},
                "shell":        {"type": "boolean", "description": "Enable shell expansion (pipes, redirects, glob). Default: false."},
                "timeout_secs": {"type": "integer", "description": "Per-call timeout. Clamped to server max."},
                "approve":      {"type": "boolean", "description": _APPROVE_DESC},
            },
            "required": ["command"],
        },
    }

    rf = {
        "name": "read_file",
        "description": READ_FILE_SCHEMA["description"] + suffix,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":      {"type": "string", "description": "Absolute or working-dir-relative file path."},
                "encoding":  {"type": "string", "enum": ["utf-8", "base64"], "description": "utf-8 (default) or base64."},
                "max_bytes": {"type": "integer", "description": "Cap on bytes read; clamped to server max_output_bytes."},
                "approve":   {"type": "boolean", "description": _APPROVE_DESC},
            },
            "required": ["path"],
        },
    }

    wf_base = (
        "Write content to a file (creates or overwrites). "
        "Use encoding='base64' for binary; set create_dirs=true to mkdir -p the parent."
    )
    if config.mode == "read":
        wf_mode = " All writes require user approval (a confirmation dialog will appear)."
    elif config.mode == "write":
        wf_mode = " Writes within the working directory proceed freely. Outside-cwd writes prompt for user approval."
    else:
        wf_mode = " All writes proceed freely without approval. Hardcoded safety blocks still enforced."

    wf = {
        "name": "write_file",
        "description": wf_base + wf_mode,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":        {"type": "string"},
                "content":     {"type": "string", "description": "File content. base64-encoded when encoding='base64'."},
                "encoding":    {"type": "string", "enum": ["utf-8", "base64"]},
                "create_dirs": {"type": "boolean", "description": "Create parent directories if missing."},
                "approve":     {"type": "boolean", "description": _APPROVE_DESC},
            },
            "required": ["path", "content"],
        },
    }

    ld = {
        "name": "list_directory",
        "description": LIST_DIRECTORY_SCHEMA["description"] + suffix,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":        {"type": "string", "description": "Directory path; defaults to the server working directory."},
                "show_hidden": {"type": "boolean", "description": "Include dot-files. Default false."},
                "approve":     {"type": "boolean", "description": _APPROVE_DESC},
            },
            "required": [],
        },
    }

    sf = {
        "name": "search_files",
        "description": SEARCH_FILES_SCHEMA["description"] + suffix,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":           {"type": "string", "description": "Root directory to search. Defaults to the server working directory."},
                "name":           {"type": "string", "description": "Glob to match file names (e.g. '*.py'). Empty = all files."},
                "content":        {"type": "string", "description": "Regex to match file CONTENT line by line. Empty = filename-only search."},
                "case_sensitive": {"type": "boolean", "description": "Default false (case-insensitive content match)."},
                "max_depth":      {"type": "integer", "description": "Max directory recursion depth. 0 = root only. Default: 8."},
                "max_results":    {"type": "integer", "description": "Stop after this many matches. Default: 200, max: 2000."},
                "show_hidden":    {"type": "boolean", "description": "Include hidden files / directories. Default false."},
                "approve":        {"type": "boolean", "description": _APPROVE_DESC},
            },
            "required": [],
        },
    }

    return [ec, rf, wf, ld, sf]


# Keep static TOOLS for backward-compatible imports; dispatch uses _build_tools(config).
TOOLS: List[Dict[str, Any]] = [
    EXECUTE_COMMAND_SCHEMA,
    READ_FILE_SCHEMA,
    WRITE_FILE_SCHEMA,
    LIST_DIRECTORY_SCHEMA,
    SEARCH_FILES_SCHEMA,
]


def _error_response(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _ok_response(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def handle_execute_command(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> _ToolResult:
    command = str(params.get("command", ""))
    cwd_param: Optional[str] = params.get("cwd")
    use_shell = bool(params.get("shell", False))
    timeout_param: Optional[int] = params.get("timeout_secs")
    approve = bool(params.get("approve", False))

    try:
        check_command(command, config, use_shell=use_shell)
    except PolicyDenied as exc:
        audit.log({"tool": "execute_command", "input": params, "outcome": "denied", "error": str(exc)})
        return _error_response(f"Command denied: {exc}")

    cwd = cwd_param or config.default_cwd
    if cwd_param:
        try:
            check_path(cwd_param, config)
        except PolicyDenied as exc:
            audit.log({"tool": "execute_command", "input": params, "outcome": "denied", "error": str(exc)})
            return _error_response(f"Working directory denied: {exc}")

    # Soft blocks: mode-dependent approval checks
    outside_cwd = _is_outside_cwd(cwd, config.server_cwd)

    if config.mode != "yolo":
        # Outside-cwd check (applies in read and write modes)
        if outside_cwd and not approve:
            reason = f"working directory '{cwd}' is outside the server working directory"
            audit.log({"tool": "execute_command", "input": params, "outcome": "approval_required", "error": reason})
            return _ElicitationNeeded(reason)

        # Write command check: in read mode always require approval;
        # in write mode only require approval if outside cwd
        write_basenames = [b for b in segments_basenames(command, use_shell) if b in WRITE_COMMANDS]
        if write_basenames and not approve:
            if config.mode == "read" or outside_cwd:
                reason = f"'{write_basenames[0]}' is a write/modify/delete operation"
                audit.log({"tool": "execute_command", "input": params, "outcome": "approval_required", "error": reason})
                return _ElicitationNeeded(reason)

        # Shell redirect check: same logic as write commands
        if use_shell and not approve:
            target = detect_write_redirect(command)
            if target is not None:
                if config.mode == "read" or outside_cwd:
                    reason = f"shell redirect writes to '{target}'"
                    audit.log({"tool": "execute_command", "input": params, "outcome": "approval_required", "error": reason})
                    return _ElicitationNeeded(reason)

    effective_timeout = min(
        timeout_param if timeout_param is not None else config.command_timeout_secs,
        config.command_timeout_secs,
    )

    result = execute(command, cwd, use_shell, config, override_timeout=effective_timeout)

    if result.timed_out:
        outcome = "timeout"
    elif result.exit_code == 0:
        outcome = "success"
    else:
        outcome = "error"

    audit.log({
        "tool": "execute_command",
        "input": params,
        "outcome": outcome,
        "exit_code": result.exit_code,
        "duration_secs": result.duration_secs,
    })

    text = (
        f"Exit code: {result.exit_code}\n"
        f"Timed out: {result.timed_out}\n"
        f"\nSTDOUT:\n{result.stdout}"
        f"\nSTDERR:\n{result.stderr}"
    )
    if result.truncated:
        text += f"\n[Output truncated at {config.max_output_bytes} bytes]"

    is_error = result.timed_out or result.exit_code != 0
    response: Dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        response["isError"] = True
    return response


def handle_read_file(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> _ToolResult:
    path_str = str(params.get("path", ""))
    encoding = str(params.get("encoding", "utf-8"))
    max_bytes_param: Optional[int] = params.get("max_bytes")
    approve = bool(params.get("approve", False))
    cap = min(max_bytes_param if max_bytes_param is not None else config.max_output_bytes,
              config.max_output_bytes)

    resolved = str(Path(path_str).resolve())

    # Hard block + soft approval check
    denied = _check_path_approval(resolved, config, audit, "read_file", params, approve)
    if denied is not None:
        return denied

    p = Path(resolved)
    if p.is_dir():
        audit.log({"tool": "read_file", "input": params, "outcome": "error", "error": "path is a directory"})
        return _error_response("path is a directory, not a file")

    try:
        raw = p.read_bytes()
    except OSError as exc:
        audit.log({"tool": "read_file", "input": params, "outcome": "error", "error": str(exc)})
        return _error_response(f"Read error: {exc}")

    truncated = len(raw) > cap
    raw = raw[:cap]

    if encoding == "base64":
        content: str = base64.b64encode(raw).decode("ascii")
    else:
        content = raw.decode("utf-8", errors="replace")

    if truncated:
        content += f"\n[Truncated at {cap} bytes]"

    audit.log({"tool": "read_file", "input": params, "outcome": "success"})
    return _ok_response(content)


def handle_write_file(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> _ToolResult:
    path_str = str(params.get("path", ""))
    content_str = str(params.get("content", ""))
    encoding = str(params.get("encoding", "utf-8"))
    create_dirs = bool(params.get("create_dirs", False))
    approve = bool(params.get("approve", False))

    resolved = str(Path(path_str).resolve())

    # Hard block: path outside allowed_paths
    try:
        check_path(resolved, config)
    except PolicyDenied as exc:
        audit.log({"tool": "write_file", "input": params, "outcome": "denied", "error": str(exc)})
        return _error_response(f"Path denied: {exc}")

    # Soft block: mode-dependent write approval
    outside = _is_outside_cwd(resolved, config.server_cwd)
    if config.mode == "yolo":
        pass  # no approval needed
    elif config.mode == "write" and not outside:
        pass  # write mode: cwd-internal writes are free
    elif not approve:
        reasons = ["write_file requires explicit user approval"]
        if outside:
            reasons.append(f"path '{resolved}' is outside the server working directory")
        reason = "; ".join(reasons)
        audit.log({"tool": "write_file", "input": params, "outcome": "approval_required", "error": reason})
        return _ElicitationNeeded(reason)

    p = Path(resolved)
    if create_dirs:
        p.parent.mkdir(parents=True, exist_ok=True)

    if encoding == "base64":
        try:
            data = base64.b64decode(content_str)
        except Exception as exc:
            audit.log({"tool": "write_file", "input": params, "outcome": "error", "error": str(exc)})
            return _error_response(f"Base64 decode error: {exc}")
    else:
        data = content_str.encode("utf-8")

    try:
        p.write_bytes(data)
    except OSError as exc:
        audit.log({"tool": "write_file", "input": params, "outcome": "error", "error": str(exc)})
        return _error_response(f"Write error: {exc}")

    audit.log({"tool": "write_file", "input": params, "outcome": "success"})
    return _ok_response(f"Written {len(data)} bytes to {resolved}")


def handle_list_directory(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> _ToolResult:
    path_str = str(params.get("path", ""))
    show_hidden = bool(params.get("show_hidden", False))
    approve = bool(params.get("approve", False))

    # Default to server_cwd when no path is given, to avoid resolving the
    # Python process CWD (which may differ from the server's working directory)
    resolved = str(Path(path_str).resolve()) if path_str else config.server_cwd

    # Hard block + soft approval check
    denied = _check_path_approval(resolved, config, audit, "list_directory", params, approve)
    if denied is not None:
        return denied

    p = Path(resolved)
    if p.is_file():
        audit.log({"tool": "list_directory", "input": params, "outcome": "error",
                   "error": "path is a file"})
        return _error_response("path is a file, not a directory")

    try:
        entries = list(p.iterdir())
    except OSError as exc:
        audit.log({"tool": "list_directory", "input": params, "outcome": "error", "error": str(exc)})
        return _error_response(f"List error: {exc}")

    lines: List[str] = []
    dirs: List[str] = []
    files: List[str] = []

    for entry in entries:
        name = entry.name
        if not show_hidden and name.startswith("."):
            continue
        if entry.is_symlink():
            target = os.readlink(entry)
            lines.append(f"l  {name} -> {target}")
        elif entry.is_dir():
            dirs.append(name)
        else:
            files.append(name)

    dirs.sort()
    files.sort()
    formatted = [f"d  {n}/" for n in dirs] + [f"f  {n}" for n in files]
    all_lines = formatted + lines

    audit.log({"tool": "list_directory", "input": params, "outcome": "success"})
    return _ok_response("\n".join(all_lines))


def handle_search_files(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> _ToolResult:
    """Find files by name and/or content under a directory tree."""
    raw_path = str(params.get("path", "") or "")
    name_glob = str(params.get("name", "") or "")
    content = str(params.get("content", "") or "")
    case_sensitive = bool(params.get("case_sensitive", False))
    show_hidden = bool(params.get("show_hidden", False))
    approve = bool(params.get("approve", False))

    # Default + clamp numeric params
    try:
        max_depth = int(params.get("max_depth", 8))
    except (TypeError, ValueError):
        max_depth = 8
    if max_depth < 0:
        max_depth = 0
    try:
        max_results = int(params.get("max_results", 200))
    except (TypeError, ValueError):
        max_results = 200
    if max_results < 1:
        max_results = 1
    if max_results > 2000:
        max_results = 2000

    # Resolve root
    if raw_path:
        root = str(Path(raw_path).resolve())
    else:
        root = config.server_cwd

    # Hard block + soft approval check
    denied = _check_path_approval(root, config, audit, "search_files", params, approve)
    if denied is not None:
        return denied

    p = Path(root)
    if not p.exists():
        audit.log({"tool": "search_files", "input": params, "outcome": "error", "error": "no such path"})
        return _error_response(f"path does not exist: {root}")
    if not p.is_dir():
        audit.log({"tool": "search_files", "input": params, "outcome": "error", "error": "not a directory"})
        return _error_response("path is not a directory")

    # Compile content regex
    pattern: Optional[Any] = None
    if content:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(content, flags)
        except re.error as exc:
            audit.log({"tool": "search_files", "input": params, "outcome": "error", "error": str(exc)})
            return _error_response(f"invalid content regex: {exc}")

    name_pattern = name_glob or "*"
    file_size_cap = max(1, config.max_output_bytes // 2)
    line_cap = 5000

    matches: List[str] = []
    files_seen: "set[str]" = set()
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Depth check
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth > max_depth:
            dirnames[:] = []
            continue
        # Hidden-dir prune
        if not show_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        # Sort for stable output
        dirnames.sort()
        filenames.sort()
        for fname in filenames:
            if not show_hidden and fname.startswith("."):
                continue
            if not fnmatch.fnmatch(fname, name_pattern):
                continue
            full = os.path.join(dirpath, fname)
            if pattern is None:
                matches.append(full)
                files_seen.add(full)
                if len(matches) >= max_results:
                    truncated = True
                    break
                continue
            # Content match
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > file_size_cap:
                continue
            try:
                fh = open(full, "rb")
            except (OSError, PermissionError):
                continue
            try:
                for line_no, raw_line in enumerate(fh, start=1):
                    if line_no > line_cap:
                        break
                    text_line = raw_line.decode("utf-8", errors="replace").rstrip("\n").rstrip("\r")
                    if pattern.search(text_line):
                        matches.append(f"{full}:{line_no}: {text_line}")
                        files_seen.add(full)
                        if len(matches) >= max_results:
                            truncated = True
                            break
            except OSError:
                pass
            finally:
                fh.close()
            if truncated:
                break
        if truncated:
            break

    audit.log({"tool": "search_files", "input": params, "outcome": "success"})

    if not matches:
        return _ok_response("no matches")

    body_lines: List[str] = matches[:]
    if pattern is None:
        body_lines.append(f"{len(matches)} matches")
    else:
        body_lines.append(f"{len(matches)} matches in {len(files_seen)} files")
    if truncated:
        body_lines.append(
            f"\u2026{max_results} results -- truncated. Narrow your query "
            "(name=, content=, path=, max_depth=)."
        )
    return _ok_response("\n".join(body_lines))


# ── SECTION 7: Server Entry Point ─────────────────────────────────────────────

_VERSION = "0.1.0"

TOOL_HANDLERS: Dict[str, Callable[..., _ToolResult]] = {
    "execute_command": handle_execute_command,
    "read_file":       handle_read_file,
    "write_file":      handle_write_file,
    "list_directory":  handle_list_directory,
    "search_files":    handle_search_files,
}


def _build_instructions(config: Config) -> str:
    """Human-readable description sent in the MCP `initialize` response."""
    mode_desc = {
        "read": "You can read files and run read-only commands freely within the working directory. Any write operation or access outside the working directory will prompt the user for approval",
        "write": "You can read and write files freely within the working directory. Access outside the working directory will prompt the user for approval",
        "yolo": "Full read/write access to all paths without approval prompts (hardcoded safety blocks still enforced)",
    }
    return (
        "Mario is a REMOTE MCP server running on a separate Linux host. "
        "ALL file and command operations you perform through this MCP happen "
        "on the REMOTE server — not on your local machine. When the user asks "
        "you to read, write, or manage files on the server, you MUST use these "
        "MCP tools (read_file, write_file, list_directory, search_files, "
        "execute_command). Do NOT use your local filesystem tools for server operations. "
        f"The remote server's working directory is {config.server_cwd!r}. "
        f"Current mode: {config.mode} — {mode_desc[config.mode]}. "
        "Hardcoded blocks (mkfs, fdisk, shutdown, reboot, mount, kexec, "
        "crontab, ...) cannot be overridden regardless of mode. "
        "Prefer dedicated tools over shell: read_file over cat, "
        "list_directory over ls, search_files over find/grep."
    )


def dispatch(
    msg: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> "Optional[Union[Dict[str, Any], _ElicitationNeeded]]":
    """Dispatch a JSON-RPC message and return the response dict, or None for notifications."""
    msg_id = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params") or {}

    if method == "initialized":
        return None  # notification, no response

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}, "elicitation": {}},
                "serverInfo": {"name": "mario", "version": _VERSION},
                "instructions": _build_instructions(config),
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": _build_tools(config)}}

    if method == "tools/call":
        tool_name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            result: Any = _error_response(f"Unknown tool: {tool_name}")
        else:
            result = handler(arguments, config, audit)
        # _ElicitationNeeded sentinel propagates to caller (do_POST handles it)
        if isinstance(result, _ElicitationNeeded):
            return result
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    return {
        "jsonrpc": "2.0", "id": msg_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


def run_server(
    config: Config,
    audit: AuditLogger,
    stdin: Optional[BinaryIO] = None,
    stdout: Optional[BinaryIO] = None,
) -> None:
    """stdio transport: read JSON-RPC messages and dispatch to handlers."""
    _in = stdin if stdin is not None else sys.stdin.buffer
    _out = stdout if stdout is not None else sys.stdout.buffer

    while True:
        try:
            msg = read_message(_in)
        except EOFError:
            break
        except json.JSONDecodeError:
            resp: Dict[str, Any] = {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": "Parse error"}}
            write_message(_out, resp)
            continue

        response = dispatch(msg, config, audit)
        if response is not None:
            if isinstance(response, _ElicitationNeeded):
                # stdio transport cannot do elicitation; deny the operation
                response = {
                    "jsonrpc": "2.0", "id": msg.get("id"),
                    "result": {"content": [{"type": "text", "text":
                        f"\u26a0\ufe0f  Operation denied: {response.reason}\n\n"
                        "Elicitation not supported on stdio transport."}], "isError": True},
                }
            write_message(_out, response)


# ── Streamable HTTP Transport ─────────────────────────────────────────────────
#
# Implements the MCP Streamable HTTP transport (spec 2025-03-26):
#   - Single endpoint /mcp serving POST/GET/DELETE/OPTIONS.
#   - POST  → 200 application/json with the JSON-RPC response, OR 202 for
#            notifications-only payloads.
#   - GET   → 405 (this server has no server-initiated streams).
#   - DELETE → 200, optionally clearing a known Mcp-Session-Id.
#   - OPTIONS → CORS preflight.

# Active session IDs (set + insertion order) for Mcp-Session-Id validation.
# Capped at _MAX_SESSIONS, oldest evicted FIFO.
_active_sessions: "Dict[str, float]" = {}
_sessions_lock = threading.Lock()
_MAX_SESSIONS = 256


def _session_create() -> str:
    sid = uuid.uuid4().hex
    with _sessions_lock:
        _active_sessions[sid] = time.monotonic()
        # Evict oldest if over cap
        while len(_active_sessions) > _MAX_SESSIONS:
            oldest = next(iter(_active_sessions))
            _active_sessions.pop(oldest, None)
    return sid


def _session_known(sid: str) -> bool:
    with _sessions_lock:
        return sid in _active_sessions


def _session_delete(sid: str) -> None:
    with _sessions_lock:
        _active_sessions.pop(sid, None)
    _session_clear_capabilities(sid)


def _msg_is_request(msg: Any) -> bool:
    """A JSON-RPC request has a method AND an id; notifications have no id."""
    return isinstance(msg, dict) and "method" in msg and "id" in msg


def _msg_method(msg: Any) -> str:
    return msg.get("method", "") if isinstance(msg, dict) else ""


def _process_message(
    msg: Any, config: Config, audit: AuditLogger,
) -> "Optional[Union[Dict[str, Any], _ElicitationNeeded]]":
    """Dispatch a single message. Returns response dict, _ElicitationNeeded, or None."""
    if not isinstance(msg, dict):
        return {
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32600, "message": "Invalid Request"},
        }
    return dispatch(msg, config, audit)


class _HttpHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the MCP Streamable HTTP transport."""

    # These are set by run_http_server before the server starts
    _config: Config
    _audit: AuditLogger

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # suppress default access log

    # ---- helpers -------------------------------------------------------------

    def _check_auth(self) -> bool:
        """Return True if the request is authorised (or no key configured)."""
        if not self._config.api_key:
            return True
        auth = self.headers.get("Authorization", "")
        expected = "Bearer " + self._config.api_key
        try:
            return hmac.compare_digest(auth.encode("utf-8"), expected.encode("utf-8"))
        except Exception:
            return False

    def _send_status(self, status: int, body: bytes = b"",
                     extra_headers: Optional[Dict[str, str]] = None,
                     content_type: Optional[str] = None) -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, status: int, payload: Any,
                   extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = _json_bytes(payload)
        self._send_status(status, body, extra_headers=extra_headers,
                          content_type="application/json")

    # ---- route handlers ------------------------------------------------------

    def _check_endpoint(self) -> bool:
        """Validate /mcp path and auth. Returns False if error was sent."""
        if urlparse(self.path).path != "/mcp":
            self.send_error(404, "Not Found")
            return False
        if not self._check_auth():
            self.send_error(401, "Unauthorized")
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._check_endpoint():
            return
        # We do not push server-initiated messages.
        self.send_error(405, "Method Not Allowed")

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._check_endpoint():
            return
        sid = self.headers.get("Mcp-Session-Id", "").strip()
        if sid:
            _session_delete(sid)
        self._send_status(200, b"")

    def do_OPTIONS(self) -> None:  # noqa: N802
        # CORS preflight is unauthenticated by design (browsers can't add
        # Authorization to preflight); the actual call still requires auth.
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, Mcp-Session-Id, Accept",
        )
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_endpoint():
            return

        # Reject Transfer-Encoding: chunked — BaseHTTPRequestHandler doesn't
        # decode it and treating it as 0 bytes is a request-smuggling foothold.
        te = self.headers.get("Transfer-Encoding", "").strip().lower()
        if te:
            self.send_error(400, "chunked transfer-encoding not supported")
            return

        # Validate Content-Length BEFORE reading the body so a hostile client
        # can't tie up memory/bandwidth.
        cl_raw = self.headers.get("Content-Length")
        if cl_raw is None:
            self.send_error(411, "Length Required")
            return
        try:
            length = int(cl_raw)
        except ValueError:
            self.send_error(400, "Bad Request")
            return
        if length < 0 or length > self._config.max_request_bytes:
            self.send_error(413, "Payload Too Large")
            return

        body = self.rfile.read(length) if length > 0 else b""

        # Parse JSON-RPC.
        try:
            msg = json.loads(body.decode("utf-8")) if body else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "Parse error"}},
            )
            return
        if msg is None:
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32600, "message": "Invalid Request"}},
            )
            return

        # Handle JSON-RPC *responses* from the client (elicitation answers).
        is_batch = isinstance(msg, list)
        items: List[Any] = msg if is_batch else [msg]

        # A JSON-RPC response has "id" + ("result" or "error"), no "method".
        if not is_batch and "method" not in msg and "id" in msg:
            elicit_id = str(msg["id"])
            result_payload = msg.get("result")
            if result_payload and isinstance(result_payload, dict):
                _elicitation_resolve(elicit_id, result_payload)
            self._send_status(202, b"")
            return

        has_initialize = any(_msg_method(m) == "initialize" for m in items)

        # Session validation
        sid_header = self.headers.get("Mcp-Session-Id", "").strip()
        if sid_header and not _session_known(sid_header) and not has_initialize:
            self.send_error(404, "session not found")
            return

        # Dispatch. Collect responses while preserving batch shape.
        responses: List[Dict[str, Any]] = []
        elicitation_needed: Optional[Tuple[Any, _ElicitationNeeded]] = None
        for item in items:
            resp = _process_message(item, self._config, self._audit)
            if resp is None:
                continue
            if isinstance(resp, _ElicitationNeeded):
                # Only handle elicitation for single (non-batch) requests
                elicitation_needed = (item, resp)
                break
            responses.append(resp)

        # Issue a new session ID on initialize and store client capabilities.
        extra_headers: Optional[Dict[str, str]] = None
        if has_initialize:
            new_sid = _session_create()
            extra_headers = {"Mcp-Session-Id": new_sid}
            # Store client capabilities for elicitation detection
            for item in items:
                if _msg_method(item) == "initialize":
                    client_caps = (item.get("params") or {}).get("capabilities") or {}
                    _session_set_capabilities(new_sid, client_caps)

        # Handle elicitation flow via SSE streaming
        if elicitation_needed is not None:
            orig_msg, sentinel = elicitation_needed
            # Check if client supports elicitation
            active_sid = sid_header or (extra_headers or {}).get("Mcp-Session-Id", "")
            if not _session_supports_elicitation(active_sid):
                # Client doesn't support elicitation → deny the operation
                denied = {
                    "jsonrpc": "2.0",
                    "id": orig_msg.get("id"),
                    "result": {
                        "content": [{"type": "text", "text":
                            f"\u26a0\ufe0f  Operation denied: {sentinel.reason}\n\n"
                            "Client does not support user confirmation (elicitation)."}],
                        "isError": True,
                    },
                }
                self._send_json(200, denied, extra_headers=extra_headers)
                return
            self._handle_elicitation(orig_msg, sentinel, extra_headers)
            return

        # No responses (notifications-only batch) → 202 Accepted.
        if not responses:
            self._send_status(202, b"", extra_headers=extra_headers)
            return

        # Match request shape: array in → array out, single in → single out.
        payload: Any = responses if is_batch else responses[0]
        self._send_json(200, payload, extra_headers=extra_headers)

    def _handle_elicitation(
        self,
        orig_msg: Dict[str, Any],
        sentinel: "_ElicitationNeeded",
        extra_headers: Optional[Dict[str, str]],
    ) -> None:
        """Switch to SSE mode, send elicitation/create, wait for user, return tool result."""
        elicit_id = uuid.uuid4().hex
        msg_id = orig_msg.get("id")

        # Build elicitation/create request
        elicit_request: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": elicit_id,
            "method": "elicitation/create",
            "params": {
                "message": f"\u26a0\ufe0f  Approval required: {sentinel.reason}\n\nDo you approve this operation?",
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "approve": {
                            "type": "boolean",
                            "title": "Approve",
                            "description": sentinel.reason,
                            "default": False,
                        },
                    },
                    "required": ["approve"],
                },
            },
        }

        # Register pending elicitation
        event, holder = _elicitation_create(elicit_id)

        # Start SSE stream
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

        # Send the elicitation/create request as an SSE event
        self._write_sse_event(elicit_request)

        # Wait for client to POST back the response
        accepted = event.wait(timeout=_ELICITATION_TIMEOUT_SECS)
        _elicitation_cleanup(elicit_id)

        if not accepted or holder[0] is None:
            # Timeout or no response → deny
            result_payload: Dict[str, Any] = {
                "content": [{"type": "text", "text":
                    f"\u26a0\ufe0f  Operation denied: {sentinel.reason}\n\n"
                    "User did not respond within the timeout period."}],
                "isError": True,
            }
        else:
            elicit_result = holder[0]
            action = elicit_result.get("action", "cancel")
            content = elicit_result.get("content") or {}
            if action == "accept" and content.get("approve") is True:
                # Re-run the tool with approve=True
                params = (orig_msg.get("params") or {})
                arguments = dict(params.get("arguments") or {})
                arguments["approve"] = True
                tool_name = str(params.get("name", ""))
                handler = TOOL_HANDLERS.get(tool_name)
                if handler is None:
                    result_payload = _error_response(f"Unknown tool: {tool_name}")
                else:
                    r = handler(arguments, self._config, self._audit)
                    # Should not be _ElicitationNeeded again since approve=True
                    if isinstance(r, _ElicitationNeeded):
                        result_payload = _error_response(f"Unexpected: {r.reason}")
                    else:
                        result_payload = r
            else:
                result_payload = {
                    "content": [{"type": "text", "text":
                        f"\u26a0\ufe0f  Operation declined by user: {sentinel.reason}"}],
                    "isError": True,
                }

        # Send the final tools/call response on the SSE stream
        final_response: Dict[str, Any] = {
            "jsonrpc": "2.0", "id": msg_id, "result": result_payload,
        }
        self._write_sse_event(final_response)

        # Close the stream (flush and done)
        try:
            self.wfile.flush()
        except OSError:
            pass

    def _write_sse_event(self, data: Any) -> None:
        """Write a single SSE event (data: JSON\\n\\n)."""
        payload = _json_bytes(data).decode("utf-8")
        chunk = f"data: {payload}\n\n".encode("utf-8")
        try:
            self.wfile.write(chunk)
            self.wfile.flush()
        except OSError:
            pass


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def run_http_server(config: Config, audit: AuditLogger) -> None:
    """Streamable HTTP transport: start an HTTP server serving POST/GET/DELETE
    on /mcp."""

    class Handler(_HttpHandler):
        _config = config
        _audit = audit

    server = _ThreadingHTTPServer((config.http_host, config.http_port), Handler)
    sys.stderr.write(
        f"  listen    : http://{config.http_host}:{config.http_port}/mcp\n"
    )
    server.serve_forever()


def main() -> None:
    try:
        config = load_config()
    except ConfigError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        sys.exit(1)

    audit = create_audit_logger(config)

    extra_cwd = (
        f"  default_cwd: {config.default_cwd}\n"
        if config.default_cwd != config.server_cwd else ""
    )
    auth_state = "ENABLED (Bearer)" if config.api_key else (
        "DISABLED \u2014 only safe for loopback"
    )
    sys.stderr.write(
        f"mario starting\n"
        f"  transport : {config.transport}\n"
        f"  cwd       : {config.server_cwd}\n"
        f"{extra_cwd}"
        f"  mode      : {config.mode}\n"
        f"  auth      : {auth_state}\n"
        f"  timeout   : {config.command_timeout_secs}s\n"
        f"  allowlist : {', '.join(config.allowed_commands)}\n"
        f"  blocklist : {', '.join(config.blocked_commands) or '(none)'}\n"
        f"  body cap  : {config.max_request_bytes} bytes\n"
    )
    if config.api_key is None and config.transport == "http":
        sys.stderr.write(
            "  warning   : no API_KEY set; safe only on loopback "
            "('localhost'/'127.0.0.1'/'::1')\n"
        )

    def _shutdown(signum: int, frame: object) -> None:
        audit.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    if config.transport == "http":
        run_http_server(config, audit)
    else:
        run_server(config, audit)
    audit.close()


if __name__ == "__main__":
    main()
