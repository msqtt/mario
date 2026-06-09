# Spec 01 — Config

## Goal

Load, validate, and expose all server configuration from environment variables at startup. Provide a single immutable `Config` instance consumed by all other sections of `server.py`. Fail fast on invalid or insecure combinations.

---

## Scope

- Read environment variables via `os.environ`.
- Validate types and constraints (positive integers, recognised strings, host/port).
- Return a frozen `Config` instance.
- Detect insecure combinations and reject startup (fail-closed).
- No third-party libraries.

---

## API Contract

```python
class ConfigError(Exception):
    """Raised when any configuration value is invalid or unsafe."""

class Config:                       # __slots__ + frozen via __setattr__ guard
    allowed_commands: List[str]
    blocked_commands: List[str]
    allowed_paths: List[str]
    default_cwd: str
    command_timeout_secs: int
    max_output_bytes: int
    audit_log_file: Optional[str]
    transport: str                  # 'stdio' | 'http'
    http_host: str                  # bind address for HTTP transport
    http_port: int                  # bind port for HTTP transport
    api_key: Optional[str]
    server_cwd: str
    max_request_bytes: int          # POST body size cap
    extra_env_passthrough: List[str]
    mode: str                       # 'read' | 'write' | 'yolo'

def load_config() -> Config: ...
def is_loopback_host(host: str) -> bool: ...
```

> **Naming change vs v1**: the SSE transport has been replaced by Streamable HTTP. Config field names follow suit:
> - `sse_host` → `http_host`
> - `sse_port` → `http_port`
> - `transport` enum: `stdio | http` (was `stdio | sse`)
>
> Environment variables are renamed accordingly: `SSE_HOST` → `HTTP_HOST`, `SSE_PORT` → `HTTP_PORT`. There is no backward-compatibility alias — operators must update their env vars.

---

## Environment Variables

| Env Var | Type | Default | Constraints |
|---------|------|---------|-------------|
| `ALLOWED_COMMANDS` | str | `*` | Comma-separated; `*` = all |
| `BLOCKED_COMMANDS` | str | (empty) | Comma-separated |
| `ALLOWED_PATHS` | str | `/` | Comma-separated absolute paths |
| `DEFAULT_CWD` | str | `os.getcwd()` | Non-empty |
| `COMMAND_TIMEOUT_SECS` | int | `30` | 1–3600 |
| `MAX_OUTPUT_BYTES` | int | `1048576` | 1–104857600 |
| `MAX_REQUEST_BYTES` | int | `1048576` | 1–10485760 — POST body cap |
| `AUDIT_LOG_FILE` | str | (empty → stderr) | |
| `TRANSPORT` | enum | **`http`** | `stdio` or `http` |
| `HTTP_PORT` | int | `8000` | 1–65535 |
| `HTTP_HOST` | str | **`localhost`** | Bind address |
| `API_KEY` | str | (empty → None) | Bearer token |
| `MODE` | enum | `read` | Approval mode: `read`, `write`, or `yolo` |
| `EXTRA_ENV_PASSTHROUGH` | str | (empty) | Comma-separated env names to forward to children (KEY/TOKEN/SECRET/PASS/CRED names are still dropped) |

**Default change vs v1**: `TRANSPORT` defaults to `http` (was `sse`); `HTTP_HOST` defaults to `localhost` (was `0.0.0.0`). Operators must opt in to network exposure explicitly.

---

## Fail-Closed Startup Rules

`load_config()` must raise `ConfigError` (caught in `main()` to exit 1) when **any** of these are true:

1. `transport == "http"` AND `http_host` is a non-loopback bind AND `api_key` is `None`.
   - Loopback hosts: `localhost`, `127.0.0.1`, `::1`.
   - Other values (including `0.0.0.0`, public IPs, hostnames) require `API_KEY` to be set.
   - Error message: `"HTTP_HOST=<host> requires API_KEY to be set (refusing to expose unauthenticated remote command execution on a non-loopback bind). Set API_KEY=$(openssl rand -hex 16) or change HTTP_HOST=localhost."`
2. `MAX_REQUEST_BYTES` outside the integer range above.
3. Any of the existing v1 ConfigError conditions (timeout/max_output_bytes/http_port out of range, invalid transport).

---

## Parsing Rules

- Comma-separated values: split on `,`, strip whitespace, drop empties.
- `ALLOWED_COMMANDS=` (empty) → `["*"]`.
- Integer fields: parse with `int()`; out-of-range or non-numeric → `ConfigError`.
- `DEFAULT_CWD` falls back to `os.getcwd()`.
- `HTTP_HOST=` (empty after strip) → `"localhost"`.
- `MODE=` (empty after strip) → `"read"`. Unrecognised values → `ConfigError`.
- `EXTRA_ENV_PASSTHROUGH=A,B` → `["A","B"]` (validated only at executor time).

---

## Edge Cases

- `ALLOWED_COMMANDS=` → `["*"]`.
- `HTTP_HOST=0.0.0.0` with no `API_KEY` → `ConfigError`.
- `HTTP_HOST=127.0.0.1` with no `API_KEY` → OK.
- `HTTP_HOST=::1` with no `API_KEY` → OK.
- `HTTP_HOST=10.0.0.5` with `API_KEY=secret` → OK.
- `TRANSPORT=stdio`, `HTTP_HOST=0.0.0.0`, no `API_KEY` → OK (HTTP not used).
- `MODE=read` → `mode == "read"`.
- `MODE=write` → `mode == "write"`.
- `MODE=yolo` → `mode == "yolo"`.
- `MODE=invalid` → `ConfigError`.
- `MAX_REQUEST_BYTES=0` → `ConfigError`.

---

## Acceptance Criteria

- [ ] `load_config()` returns a valid `Config` when all env vars are valid or absent.
- [ ] `load_config()` raises `ConfigError` for each invalid value.
- [ ] `ALLOWED_COMMANDS=''` → `allowed_commands == ['*']`.
- [ ] `Config` is immutable (assignment raises `AttributeError`).
- [ ] **Default `transport` is `"http"`.**
- [ ] **Default `http_host` is `"localhost"`.**
- [ ] **`HTTP_HOST=0.0.0.0` without `API_KEY` raises `ConfigError`.**
- [ ] **`HTTP_HOST=127.0.0.1` without `API_KEY` does NOT raise.**
- [ ] **`HTTP_HOST=::1` without `API_KEY` does NOT raise.**
- [ ] **`TRANSPORT=stdio` ignores HTTP host fail-closed checks.**
- [ ] `MAX_REQUEST_BYTES` defaults to 1048576.
- [ ] `MAX_REQUEST_BYTES=0` raises `ConfigError`.
- [ ] `EXTRA_ENV_PASSTHROUGH` parses to a list.
- [ ] `MODE` defaults to `"read"` when env var is absent or empty.
- [ ] `MODE=write` → `config.mode == "write"`.
- [ ] `MODE=yolo` → `config.mode == "yolo"`.
- [ ] `MODE=invalid` raises `ConfigError`.
- [ ] `mypy server.py` passes.
