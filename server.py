# server.py — Shell MCP Server
# Single-file MCP server for DevOps operations (Python stdlib only)
#
# Sections:
#   1. Config
#   2. Security
#   3. Executor
#   4. Audit
#   5. MCP Protocol (wire format)
#   6. Tool Handlers
#   7. Server Entry Point



import base64
import json
import os
import queue
import re
import shlex
import signal
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import IO, Any, BinaryIO, Callable, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

# ── SECTION 1: Config ─────────────────────────────────────────────────────────


class ConfigError(Exception):
    """Raised when any configuration value is invalid."""


@dataclass(frozen=True)
class Config:
    allowed_commands: List[str]
    blocked_commands: List[str]
    allowed_paths: List[str]
    default_cwd: str
    command_timeout_secs: int
    max_output_bytes: int
    audit_log_file: Optional[str]
    transport: str = "sse"         # 'stdio' or 'sse'
    sse_port: int = 8000
    sse_host: str = "0.0.0.0"
    api_key: Optional[str] = None  # None = no auth required


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

    default_cwd = os.environ.get("DEFAULT_CWD", "") or os.environ.get("HOME", "/tmp")

    raw_timeout = os.environ.get("COMMAND_TIMEOUT_SECS", "30")
    timeout = _parse_int("COMMAND_TIMEOUT_SECS", raw_timeout, 1, 3600)

    raw_max = os.environ.get("MAX_OUTPUT_BYTES", "1048576")
    max_bytes = _parse_int("MAX_OUTPUT_BYTES", raw_max, 1, 104857600)

    raw_audit = os.environ.get("AUDIT_LOG_FILE", "")
    audit_file: Optional[str] = raw_audit.strip() or None

    transport = os.environ.get("TRANSPORT", "sse").strip().lower()
    if transport not in ("stdio", "sse"):
        raise ConfigError(f"TRANSPORT must be 'stdio' or 'sse', got: {transport!r}")

    sse_port = _parse_int("SSE_PORT", os.environ.get("SSE_PORT", "8000"), 1, 65535)
    sse_host = os.environ.get("SSE_HOST", "0.0.0.0").strip() or "0.0.0.0"
    api_key: Optional[str] = os.environ.get("API_KEY", "").strip() or None

    return Config(
        allowed_commands=allowed,
        blocked_commands=blocked,
        allowed_paths=allowed_paths,
        default_cwd=default_cwd,
        command_timeout_secs=timeout,
        max_output_bytes=max_bytes,
        audit_log_file=audit_file,
        transport=transport,
        sse_port=sse_port,
        sse_host=sse_host,
        api_key=api_key,
    )



# ── SECTION 2: Security ───────────────────────────────────────────────────────


class PolicyDenied(Exception):
    """Raised when a command or path is rejected by policy."""


def check_command(command: str, config: Config) -> None:
    """Raise PolicyDenied if the command is not permitted by policy."""
    stripped = command.strip()
    if not stripped:
        raise PolicyDenied("empty command")

    base_token = stripped.split()[0]
    basename = os.path.basename(base_token)

    # Denylist checked first
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


# ── SECTION 3: Executor ───────────────────────────────────────────────────────


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    truncated: bool
    duration_secs: float


def execute(command: str, cwd: str, use_shell: bool, config: Config) -> ExecutionResult:
    """Spawn a command and return the result. Caller must run security checks first."""
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

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            shell=use_shell,
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
        stdout_bytes, stderr_bytes = proc.communicate(timeout=config.command_timeout_secs)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_bytes, stderr_bytes = proc.communicate()
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

        from datetime import datetime, timezone
        record["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
            f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
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
    body = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    stream.write(header + body)
    stream.flush()


# ── SECTION 6: Tool Handlers ──────────────────────────────────────────────────


EXECUTE_COMMAND_SCHEMA: Dict[str, Any] = {
    "name": "execute_command",
    "description": (
        "Execute a shell command on the server and return stdout, stderr, and exit code. "
        "Use for DevOps tasks such as checking service status, viewing logs, or running scripts."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command":      {"type": "string",  "description": "Shell command to execute."},
            "cwd":          {"type": "string",  "description": "Working directory. Defaults to DEFAULT_CWD."},
            "shell":        {"type": "boolean", "description": "Enable shell expansion (pipes, redirects). Default: false."},
            "timeout_secs": {"type": "integer", "description": "Override timeout (seconds). Clamped to server max."},
        },
        "required": ["command"],
    },
}

READ_FILE_SCHEMA: Dict[str, Any] = {
    "name": "read_file",
    "description": "Read the contents of a file on the server.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":      {"type": "string"},
            "encoding":  {"type": "string", "enum": ["utf-8", "base64"]},
            "max_bytes": {"type": "integer"},
        },
        "required": ["path"],
    },
}

WRITE_FILE_SCHEMA: Dict[str, Any] = {
    "name": "write_file",
    "description": "Write content to a file on the server. Creates or overwrites.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string"},
            "content":     {"type": "string"},
            "encoding":    {"type": "string", "enum": ["utf-8", "base64"]},
            "create_dirs": {"type": "boolean"},
        },
        "required": ["path", "content"],
    },
}

LIST_DIRECTORY_SCHEMA: Dict[str, Any] = {
    "name": "list_directory",
    "description": "List the contents of a directory on the server.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string"},
            "show_hidden": {"type": "boolean"},
        },
        "required": ["path"],
    },
}

TOOLS: List[Dict[str, Any]] = [
    EXECUTE_COMMAND_SCHEMA,
    READ_FILE_SCHEMA,
    WRITE_FILE_SCHEMA,
    LIST_DIRECTORY_SCHEMA,
]


def _error_response(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _ok_response(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def handle_execute_command(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> Dict[str, Any]:
    command = str(params.get("command", ""))
    cwd_param: Optional[str] = params.get("cwd")
    use_shell = bool(params.get("shell", False))
    timeout_param: Optional[int] = params.get("timeout_secs")

    try:
        check_command(command, config)
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

    effective_timeout = min(
        timeout_param if timeout_param is not None else config.command_timeout_secs,
        config.command_timeout_secs,
    )
    cfg = Config(
        allowed_commands=config.allowed_commands,
        blocked_commands=config.blocked_commands,
        allowed_paths=config.allowed_paths,
        default_cwd=config.default_cwd,
        command_timeout_secs=effective_timeout,
        max_output_bytes=config.max_output_bytes,
        audit_log_file=config.audit_log_file,
    )

    result = execute(command, cwd, use_shell, cfg)

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
) -> Dict[str, Any]:
    path_str = str(params.get("path", ""))
    encoding = str(params.get("encoding", "utf-8"))
    max_bytes_param: Optional[int] = params.get("max_bytes")
    cap = min(max_bytes_param if max_bytes_param is not None else config.max_output_bytes,
              config.max_output_bytes)

    resolved = str(Path(path_str).resolve())
    try:
        check_path(resolved, config)
    except PolicyDenied as exc:
        audit.log({"tool": "read_file", "input": params, "outcome": "denied", "error": str(exc)})
        return _error_response(f"Path denied: {exc}")

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
) -> Dict[str, Any]:
    path_str = str(params.get("path", ""))
    content_str = str(params.get("content", ""))
    encoding = str(params.get("encoding", "utf-8"))
    create_dirs = bool(params.get("create_dirs", False))

    resolved = str(Path(path_str).resolve())
    try:
        check_path(resolved, config)
    except PolicyDenied as exc:
        audit.log({"tool": "write_file", "input": params, "outcome": "denied", "error": str(exc)})
        return _error_response(f"Path denied: {exc}")

    p = Path(resolved)
    if create_dirs:
        p.parent.mkdir(parents=True, exist_ok=True)

    if encoding == "base64":
        try:
            data = base64.b64decode(content_str)
        except Exception as exc:
            audit.log({"tool": "write_file", "input": params, "outcome": "error", "error": str(exc)})
            return _error_response(f"Base64 decode error: {exc}")
        try:
            p.write_bytes(data)
            n = len(data)
        except OSError as exc:
            audit.log({"tool": "write_file", "input": params, "outcome": "error", "error": str(exc)})
            return _error_response(f"Write error: {exc}")
    else:
        try:
            p.write_text(content_str, encoding="utf-8")
            n = len(content_str.encode("utf-8"))
        except OSError as exc:
            audit.log({"tool": "write_file", "input": params, "outcome": "error", "error": str(exc)})
            return _error_response(f"Write error: {exc}")

    audit.log({"tool": "write_file", "input": params, "outcome": "success"})
    return _ok_response(f"Written {n} bytes to {resolved}")


def handle_list_directory(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> Dict[str, Any]:
    path_str = str(params.get("path", ""))
    show_hidden = bool(params.get("show_hidden", False))

    resolved = str(Path(path_str).resolve())
    try:
        check_path(resolved, config)
    except PolicyDenied as exc:
        audit.log({"tool": "list_directory", "input": params, "outcome": "denied", "error": str(exc)})
        return _error_response(f"Path denied: {exc}")

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
    # symlinks inserted in discovery order; re-sort together
    sym_lines = [l for l in lines]
    all_lines = formatted + sym_lines

    audit.log({"tool": "list_directory", "input": params, "outcome": "success"})
    return _ok_response("\n".join(all_lines))


# ── SECTION 7: Server Entry Point ─────────────────────────────────────────────

_VERSION = "0.1.0"

TOOL_HANDLERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "execute_command": handle_execute_command,
    "read_file":       handle_read_file,
    "write_file":      handle_write_file,
    "list_directory":  handle_list_directory,
}


def dispatch(
    msg: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> Optional[Dict[str, Any]]:
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
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mario", "version": _VERSION},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            result = _error_response(f"Unknown tool: {tool_name}")
        else:
            result = handler(arguments, config, audit)
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
            write_message(_out, response)


# ── SSE Transport ─────────────────────────────────────────────────────────────

# Per-session SSE queues: session_id -> Queue of response dicts
_sse_sessions: Dict[str, "queue.Queue[Optional[Dict[str, Any]]]"] = {}
_sse_sessions_lock = threading.Lock()


class _SseHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP SSE transport."""

    # These are set by run_sse_server before the server starts
    _config: Config
    _audit: AuditLogger

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # suppress default access log

    def _check_auth(self) -> bool:
        """Return True if the request is authorised (or no key configured)."""
        if not self._config.api_key:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {self._config.api_key}"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/sse":
            self.send_error(404, "Not Found")
            return

        if not self._check_auth():
            self.send_error(401, "Unauthorized")
            return

        session_id = str(uuid.uuid4())
        q: queue.Queue[Optional[Dict[str, Any]]] = queue.Queue()
        with _sse_sessions_lock:
            _sse_sessions[session_id] = q

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            # Send the endpoint event so the client knows where to POST
            endpoint_event = (
                f"event: endpoint\n"
                f"data: /message?sessionId={session_id}\n\n"
            )
            self.wfile.write(endpoint_event.encode("utf-8"))
            self.wfile.flush()

            # Stream responses until client disconnects (sentinel None)
            while True:
                try:
                    item = q.get(timeout=30)
                except queue.Empty:
                    # Send a keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue

                if item is None:  # shutdown sentinel
                    break

                data = json.dumps(item, separators=(",", ":"), ensure_ascii=False)
                sse_msg = f"event: message\ndata: {data}\n\n"
                self.wfile.write(sse_msg.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _sse_sessions_lock:
                _sse_sessions.pop(session_id, None)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/message":
            self.send_error(404, "Not Found")
            return

        if not self._check_auth():
            self.send_error(401, "Unauthorized")
            return

        qs = parse_qs(parsed.query)
        session_ids = qs.get("sessionId", [])
        if not session_ids:
            self.send_error(400, "Missing sessionId")
            return

        session_id = session_ids[0]
        with _sse_sessions_lock:
            q = _sse_sessions.get(session_id)

        if q is None:
            self.send_error(404, "Session not found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        # Process in background thread to avoid blocking the POST handler
        def _process() -> None:
            try:
                msg = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                q.put({
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                })
                return
            response = dispatch(msg, self._config, self._audit)
            if response is not None:
                q.put(response)

        threading.Thread(target=_process, daemon=True).start()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def run_sse_server(config: Config, audit: AuditLogger) -> None:
    """SSE transport: start an HTTP server that proxies MCP over SSE."""

    class Handler(_SseHandler):
        _config = config
        _audit = audit

    server = _ThreadingHTTPServer((config.sse_host, config.sse_port), Handler)
    sys.stderr.write(
        f"  listen    : http://{config.sse_host}:{config.sse_port}/sse\n"
    )
    server.serve_forever()


def main() -> None:
    try:
        config = load_config()
    except ConfigError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        sys.exit(1)

    audit = create_audit_logger(config)

    sys.stderr.write(
        f"mario starting\n"
        f"  transport : {config.transport}\n"
        f"  cwd       : {config.default_cwd}\n"
        f"  timeout   : {config.command_timeout_secs}s\n"
        f"  allowlist : {', '.join(config.allowed_commands)}\n"
        f"  blocklist : {', '.join(config.blocked_commands) or '(none)'}\n"
    )

    def _shutdown(signum: int, frame: object) -> None:
        audit.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    if config.transport == "sse":
        run_sse_server(config, audit)
    else:
        run_server(config, audit)
    audit.close()




if __name__ == "__main__":
    main()
