# Spec 00 — Overall Architecture

## Goal

Build a Model Context Protocol (MCP) server that enables AI agents to perform DevOps and operations tasks by executing shell commands and manipulating files on the server host.

---

## Tech Constraints

- **Language**: Python 3.6+
- **Dependencies**: stdlib only (no pip packages in production)
- **Single file**: all production code lives in `server.py`
- **Type hints**: use `typing.List`, `typing.Dict`, `typing.Tuple`, `typing.Optional`, etc. — do **not** use PEP 585 lowercase generics (`list[...]`, `tuple[...]`) or PEP 604 union syntax (`X | Y`) as these require Python 3.9+ and 3.10+ respectively

---

## Single-File Layout

All code lives in `server.py`, organised into clearly separated sections:

```
server.py
│
├── # ── SECTION 1: Config ──────────────────────────────────────
│   class ConfigError(Exception)
│   class Config(dataclass)
│   def load_config() -> Config
│
├── # ── SECTION 2: Security ─────────────────────────────────────
│   class PolicyDenied(Exception)
│   def check_command(command: str, config: Config) -> None   # raises PolicyDenied
│   def check_path(path: str, config: Config) -> None        # raises PolicyDenied
│
├── # ── SECTION 3: Executor ─────────────────────────────────────
│   @dataclass class ExecutionResult
│   def execute(command: str, cwd: str, use_shell: bool, config: Config) -> ExecutionResult
│
├── # ── SECTION 4: Audit ────────────────────────────────────────
│   class AuditLogger
│   def create_audit_logger(config: Config) -> AuditLogger
│
├── # ── SECTION 5: MCP Protocol ─────────────────────────────────
│   def read_message(stdin) -> dict
│   def write_message(stdout, msg: dict) -> None
│   TOOLS: list[dict]  (tool schemas)
│
├── # ── SECTION 6: Tool Handlers ────────────────────────────────
│   def handle_execute_command(params, config, audit) -> dict
│   def handle_read_file(params, config, audit) -> dict
│   def handle_write_file(params, config, audit) -> dict
│   def handle_list_directory(params, config, audit) -> dict
│
└── # ── SECTION 7: Server Entry Point ───────────────────────────
    def run_server(config: Config) -> None
    if __name__ == '__main__': main()
```

---

## MCP Protocol (stdio transport only)

The server communicates over stdin/stdout using the MCP stdio transport, which follows the JSON-RPC 2.0 framing with `Content-Length` headers (identical to LSP):

```
Content-Length: <N>\r\n
\r\n
<N bytes of UTF-8 JSON>
```

Supported JSON-RPC methods:

| Method | Description |
|--------|-------------|
| `initialize` | Handshake; return server capabilities |
| `initialized` | Notification; no response required |
| `tools/list` | Return list of available tools |
| `tools/call` | Invoke a tool by name |
| `ping` | Return `pong` |

---

## MCP Tools Exposed

| Tool Name | Handler | Description |
|-----------|---------|-------------|
| `execute_command` | `handle_execute_command` | Run a shell command, return stdout/stderr/exitCode |
| `read_file` | `handle_read_file` | Read a file's content |
| `write_file` | `handle_write_file` | Write content to a file |
| `list_directory` | `handle_list_directory` | List entries in a directory |

---

## Data Flow

```
Agent → MCP Client
  → stdin (Content-Length framed JSON-RPC)
    → read_message()
      → dispatch on method
        → handle_<tool>()
          → check_command() / check_path()   [security]
          → execute() / fs I/O               [executor / stdlib]
          → audit.log()                      [audit]
          → return tool result dict
    → write_message() → stdout
```

---

## Configuration Surface (see spec 01)

| Env Var | Default | Description |
|---------|---------|-------------|
| `ALLOWED_COMMANDS` | `*` | Comma-separated allowlist (`*` = all) |
| `BLOCKED_COMMANDS` | _(empty)_ | Comma-separated denylist (always enforced) |
| `ALLOWED_PATHS` | `/` | Comma-separated path prefixes for filesystem tools |
| `DEFAULT_CWD` | `$HOME` or `/tmp` | Default working directory |
| `COMMAND_TIMEOUT_SECS` | `30` | Max execution time per command (seconds) |
| `MAX_OUTPUT_BYTES` | `1048576` | Max stdout+stderr bytes returned (1 MB) |
| `AUDIT_LOG_FILE` | _(empty → stderr)_ | File path for audit log |

---

## Security Model

1. Denylist always evaluated before allowlist.
2. `ALLOWED_COMMANDS=*` means all commands except those in denylist.
3. Filesystem tools restricted to `ALLOWED_PATHS` prefixes.
4. Commands spawned with `shell=False` by default.
5. No secrets hardcoded; all config from environment.

---

## Non-Goals (v1)

- SSE / HTTP transport (stdio only)
- Streaming real-time output
- Interactive / PTY sessions
- Windows support

---

## Acceptance Criteria (architecture level)

- [ ] `server.py` is a single file with no imports outside Python stdlib.
- [ ] MCP server starts and responds to `tools/list` with all 4 tools.
- [ ] All tool calls are recorded in the audit log.
- [ ] `mypy server.py` passes with zero errors.
- [ ] `pytest` passes with ≥ 90% coverage on core functions.
