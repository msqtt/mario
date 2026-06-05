# Spec 07 — MCP Protocol & Server Entry Point

## Goal

Implement the MCP stdio transport (JSON-RPC 2.0 with Content-Length framing) and the server main loop using Python stdlib only.

---

## Scope

- `Content-Length` framed JSON-RPC reader/writer over `sys.stdin.buffer` / `sys.stdout.buffer`.
- Handle MCP methods: `initialize`, `initialized`, `tools/list`, `tools/call`, `ping`.
- Dispatch `tools/call` to the correct handler.
- Print startup info to `sys.stderr` only.
- Handle `SIGINT` / `SIGTERM` for graceful shutdown.
- Entry point: `if __name__ == '__main__':`.

---

## MCP Wire Format

```
Content-Length: <N>\r\n
\r\n
<N bytes of UTF-8 JSON>
```

**read_message(stream)**:
1. Read headers line by line until blank line.
2. Parse `Content-Length` header value.
3. Read exactly N bytes.
4. Decode as UTF-8 and parse with `json.loads`.

**write_message(stream, msg)**:
1. `json.dumps(msg, separators=(',', ':'), ensure_ascii=False)`.
2. Encode to UTF-8, compute byte length N.
3. Write `b'Content-Length: N\r\n\r\n' + body` to stream.
4. Flush immediately.

---

## API Contract

```python
from typing import BinaryIO, Any

def read_message(stream: BinaryIO) -> dict[str, Any]: ...
def write_message(stream: BinaryIO, msg: dict[str, Any]) -> None: ...
def run_server(config: Config, audit: AuditLogger) -> None: ...
```

---

## JSON-RPC Dispatch

| Method | Response |
|--------|----------|
| `initialize` | `{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"shell-mcp-server","version":"<ver>"}}` |
| `initialized` | No response (notification) |
| `tools/list` | `{"tools": [<4 schemas>]}` |
| `tools/call` | `{"result": <handler return>}` |
| `ping` | `{"result": {}}` |
| Unknown | `{"error": {"code": -32601, "message": "Method not found"}}` |

---

## Tool Dispatch

```python
TOOL_HANDLERS: dict[str, Callable] = {
    "execute_command": handle_execute_command,
    "read_file":       handle_read_file,
    "write_file":      handle_write_file,
    "list_directory":  handle_list_directory,
}
```

For `tools/call`: extract `params['name']` and `params['arguments']`; call handler; wrap in `{"result": ...}`.

---

## Startup Output (stderr)

```
shell-mcp-server starting
  transport : stdio
  cwd       : /home/ops
  timeout   : 30s
  allowlist : *
  blocklist : (none)
```

---

## Graceful Shutdown

```python
signal.signal(signal.SIGTERM, _shutdown_handler)
signal.signal(signal.SIGINT,  _shutdown_handler)
```

On signal: `audit.close()` then `sys.exit(0)`.

---

## Edge Cases

- Malformed JSON in stdin -> send JSON-RPC error `code: -32700` and continue loop.
- Unknown tool name -> return `isError: True`, `"Unknown tool: <name>"`.
- `load_config()` raises `ConfigError` -> print to stderr, `sys.exit(1)`.
- EOF on stdin -> exit cleanly with code 0.
- Nothing written to stdout before the server loop starts.

---

## Acceptance Criteria

- [ ] `read_message` / `write_message` correctly frame and parse Content-Length messages.
- [ ] `initialize` returns correct `protocolVersion` and `serverInfo`.
- [ ] `tools/list` returns all 4 tool schemas.
- [ ] `tools/call` dispatches to the correct handler and wraps the response.
- [ ] Unknown method returns JSON-RPC error `code: -32601`.
- [ ] Malformed JSON returns JSON-RPC error `code: -32700` without crashing.
- [ ] `ConfigError` at startup exits with code 1.
- [ ] EOF on stdin exits with code 0.
- [ ] Nothing is written to stdout before the server loop.
- [ ] `mypy server.py` passes.
