# Spec 00 — Overall Architecture

## Goal

Build a Model Context Protocol (MCP) server that lets AI agents perform DevOps and operations tasks by executing shell commands and manipulating files on a remote host. Single-file deployment (`scp` or `curl | bash`-friendly), no third-party dependencies, fail-closed network defaults, and strong agent UX hints so the agent picks the right tool on the first call.

---

## Tech Constraints

- **Language**: Python 3.6+
- **Dependencies**: stdlib only (no pip packages in production)
- **Single file**: all production code lives in `server.py`
- **Type hints**: use `typing.List`, `typing.Dict`, `typing.Tuple`, `typing.Optional`, etc. — do **not** use PEP 585 lowercase generics (`list[...]`, `tuple[...]`) or PEP 604 union syntax (`X | Y`) as these require Python 3.9+ and 3.10+ respectively
- **POSIX only**: `os.killpg` and `start_new_session` are required — Windows is out of scope

---

## Single-File Layout

All code lives in `server.py`, organised into clearly separated sections:

```
server.py
│
├── # ── SECTION 1: Config ──────────────────────────────────────
│   class ConfigError(Exception)
│   class Config(immutable, __slots__)
│   def is_loopback_host(host: str) -> bool
│   def load_config() -> Config                # fail-closed startup checks
│
├── # ── SECTION 2: Security ─────────────────────────────────────
│   class PolicyDenied(Exception)
│   HARDCODED_BLOCKED_COMMANDS / DESTRUCTIVE_PATTERNS / WRITE_COMMANDS
│   def parse_argv / unwrap_executor_prefixes  # sudo/bash -c/env/timeout/...
│   def split_shell_segments / detect_write_redirect
│   def check_command(command, config, use_shell=False) -> None
│   def check_path(path, config) -> None
│
├── # ── SECTION 3: Executor ─────────────────────────────────────
│   def build_subprocess_env() -> Dict[str, str]   # scrubs API_KEY/SECRET/...
│   class ExecutionResult
│   def execute(...)                                # process group + timeout
│
├── # ── SECTION 4: Audit ────────────────────────────────────────
│   class AuditLogger
│   def create_audit_logger(config) -> AuditLogger
│
├── # ── SECTION 5: MCP Protocol ─────────────────────────────────
│   def read_message / write_message            # stdio framing
│   TOOLS: List[dict]                            # 5 tool schemas
│   def dispatch(msg, config, audit)             # method router
│
├── # ── SECTION 6: Tool Handlers ────────────────────────────────
│   def handle_execute_command / handle_read_file / handle_write_file
│   def handle_list_directory / handle_search_files
│
└── # ── SECTION 7: Server Entry Point ───────────────────────────
    def run_server(config, audit, ...)              # stdio transport
    class _HttpHandler(BaseHTTPRequestHandler)      # streamable HTTP
    def run_http_server(config, audit)              # streamable HTTP
    def main()
```

---

## MCP Transports

The server supports **two** transports, selected via `TRANSPORT`:

### 1. stdio  (`TRANSPORT=stdio`)
For local agent connections. Communicates over stdin/stdout using the MCP stdio framing (Content-Length + JSON, identical to LSP):

```
Content-Length: <N>\r\n
\r\n
<N bytes of UTF-8 JSON>
```

### 2. Streamable HTTP  (`TRANSPORT=http`, default)

Implements the **Streamable HTTP** transport from MCP spec **2025-03-26**, replacing the deprecated HTTP+SSE transport. Single endpoint `/mcp` over HTTP/1.1:

| Method | Behaviour |
|---|---|
| `POST /mcp` | Send a JSON-RPC request (or notification, or batch). For requests, server replies `200 OK` with `Content-Type: application/json` and the JSON-RPC response. For notifications-only, server replies `202 Accepted`. |
| `GET /mcp`  | Reserved for server→client streaming; this server has no server-initiated messages, so it returns `405 Method Not Allowed`. |
| `DELETE /mcp` | Client-initiated session termination. Returns `200 OK`. |
| `OPTIONS /mcp` | CORS preflight. |

The response to `initialize` carries an `Mcp-Session-Id` header; clients SHOULD echo it on subsequent `POST` / `DELETE` requests, and the server validates known IDs when present.

Supported JSON-RPC methods (both transports):

| Method | Description |
|--------|-------------|
| `initialize` | Handshake; return server capabilities (tools, elicitation) + `instructions` |
| `initialized` | Notification; no response |
| `tools/list` | Return list of available tools |
| `tools/call` | Invoke a tool by name |
| `ping` | Return `{}` |

---

## MCP Tools Exposed

| # | Tool | Handler | Description |
|---|------|---------|-------------|
| 1 | `execute_command` | `handle_execute_command` | Run a shell command, return stdout/stderr/exitCode. Shell-aware approval gate via elicitation. |
| 2 | `read_file`        | `handle_read_file`        | Read a file's content (utf-8 / base64). |
| 3 | `write_file`       | `handle_write_file`       | Write content to a file (always requires user confirmation via elicitation). |
| 4 | `list_directory`   | `handle_list_directory`   | List entries (defaults to server cwd). |
| 5 | `search_files`     | `handle_search_files`     | `find` + `grep` in a single read-only call. |

All tool descriptions cross-reference each other so the agent picks the right tool on the first call (e.g. `execute_command`'s description tells the agent to prefer `read_file` over `cat`).

---

## Data Flow

```
Agent → MCP Client
  ├── (stdio)         → stdin/stdout (Content-Length framed)
  └── (http)          → POST /mcp (JSON in, JSON out)
       ↓
    read_message / parse JSON-RPC
       ↓
    dispatch(method, params)
       ├── initialize   → result + instructions
       ├── tools/list   → 5 tool schemas
       └── tools/call   → handle_<tool>
              ↓
            check_command / check_path        (security)
            execute / fs I/O                  (executor / stdlib)
            audit.log                         (audit, NDJSON)
              ↓
            return content blocks
       ↓
    write_message  →  stdout / HTTP body
```

---

## Configuration Surface (see spec 01)

| Env Var | Default | Description |
|---------|---------|-------------|
| `TRANSPORT` | `http` | `stdio` or `http` |
| `HTTP_HOST` | `localhost` | Bind address (loopback by default; non-loopback requires `API_KEY`) |
| `HTTP_PORT` | `8000` | Bind port |
| `API_KEY` | _(empty)_ | Bearer token; required when `HTTP_HOST` is non-loopback |
| `MODE` | `read` | Approval mode: `read` (cwd writes need approval), `write` (cwd reads+writes free), `yolo` (all path-based approvals skipped) |
| `MAX_REQUEST_BYTES` | `1048576` | POST body cap |
| `ALLOWED_COMMANDS` | `*` | Comma-separated allowlist (`*` = all) |
| `BLOCKED_COMMANDS` | _(empty)_ | Comma-separated denylist (always enforced) |
| `ALLOWED_PATHS` | `/` | Filesystem path prefixes for filesystem tools |
| `DEFAULT_CWD` | _(server cwd)_ | Default working directory |
| `COMMAND_TIMEOUT_SECS` | `30` | Max execution time per command |
| `MAX_OUTPUT_BYTES` | `1048576` | Max stdout+stderr bytes returned |
| `EXTRA_ENV_PASSTHROUGH` | _(empty)_ | Additional env names forwarded to children (KEY/TOKEN/SECRET/PASS/CRED still dropped) |
| `AUDIT_LOG_FILE` | _(empty → stderr)_ | NDJSON audit log path |

---

## Security Model (see spec 02 for full detail)

1. **Hardcoded blocklist** — destructive commands (mkfs, fdisk, shutdown, reboot, mount, kexec, crontab, …) are permanently refused; bypass-resistant against `sudo`/`bash -c`/`xargs`/`env`/`nohup`/`timeout`/`setsid`.
2. **Destructive-pattern regex** — defense-in-depth against `rm -rf /`, `dd of=/dev/sda`, fork bombs, `iptables -F`, `git push --force`, `curl … | sh`, etc.
3. **Path policy** — `ALLOWED_PATHS` is a hard block; paths outside `server_cwd` (the launch directory) require user confirmation via elicitation (soft block).
4. **MODE-aware write approval gate** — Approval behavior is governed by `MODE`: in `read` mode (default) cwd-internal writes need approval; in `write` mode cwd-internal reads+writes are free; in `yolo` mode all path-based approvals are skipped. `write_file` requires confirmation per mode rules. `execute_command` requires it for write-class commands AND shell write redirects, following the same mode logic. Hardcoded blocks are never bypassed regardless of mode. Confirmation is obtained via the MCP `elicitation/create` protocol when the client supports it; otherwise the operation is denied.
5. **Elicitation (MCP 2025-06-18)** — when a tool call requires approval, the server switches to SSE streaming on the HTTP response, sends an `elicitation/create` JSON-RPC request to the client, and waits for the user's accept/decline/cancel response (120s timeout). Clients that do not declare `elicitation` capability are denied immediately.
5. **Subprocess env scrubbing** — only `PATH/HOME/LANG/...` plus opt-in `EXTRA_ENV_PASSTHROUGH` are forwarded; `API_KEY` and any name matching `(KEY|TOKEN|SECRET|PASS|CRED)` are unconditionally dropped.
6. **Process-group isolation** — `start_new_session=True` + `os.killpg(SIGTERM/SIGKILL)` on timeout, so `&`/`nohup` grandchildren are reaped instead of orphaned.
7. **Constant-time auth** — `hmac.compare_digest` for the `Authorization: Bearer …` check.
8. **Request-size cap** — POST `Content-Length` bounded by `max_request_bytes`; missing/non-numeric → 411/400, oversized → 413, **before** any body bytes are read.
9. **Transport hardening** — `Transfer-Encoding: chunked` is rejected (we don't support chunked decoding; treating an unknown TE as 0-length would be a smuggling foothold).
10. **Fail-closed startup** — when `TRANSPORT=http` and `HTTP_HOST` is non-loopback, `API_KEY` is mandatory; otherwise startup aborts with a `ConfigError`.

---

## Non-Goals (v2)

- Server-initiated streaming (GET /mcp returns 405)
- Real-time progress notifications (`notifications/progress`)
- Resumability (`Last-Event-ID`)
- Interactive / PTY sessions
- Windows support
- TLS termination — operators put mario behind nginx/caddy

---

## Acceptance Criteria (architecture level)

- [ ] `server.py` is a single file with no imports outside Python stdlib.
- [ ] MCP server responds to `tools/list` with all **5** tools.
- [ ] Both `TRANSPORT=stdio` and `TRANSPORT=http` start successfully.
- [ ] HTTP endpoint accepts `POST /mcp`, replies `200 application/json`.
- [ ] HTTP endpoint replies `405` to `GET /mcp`.
- [ ] HTTP endpoint replies `200` to `DELETE /mcp`.
- [ ] HTTP endpoint replies `400` to `Transfer-Encoding: chunked`.
- [ ] All tool calls produce one audit log entry.
- [ ] `mypy server.py` passes with zero errors.
- [ ] `pytest` is all-green; baseline ≥ 300 tests covering security parsing, fail-closed, transport, env scrubbing, search_files, and HTTP endpoint behaviour.
