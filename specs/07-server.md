# Spec 07 — MCP Protocol & Server Entry Point

## Goal

Implement the MCP stdio **and SSE** transports using Python stdlib only. stdio is for local agent connections; SSE (HTTP) enables remote agent access over the network.

---

## Scope

- `Content-Length` framed JSON-RPC reader/writer over `sys.stdin.buffer` / `sys.stdout.buffer` (stdio).
- HTTP SSE transport using `http.server.HTTPServer` + `socketserver.ThreadingMixIn` (sse).
- Handle MCP methods: `initialize`, `initialized`, `tools/list`, `tools/call`, `ping`.
- Dispatch `tools/call` to the correct handler.
- Print startup info to `sys.stderr` only.
- Handle `SIGINT` / `SIGTERM` for graceful shutdown.
- Entry point: `if __name__ == '__main__':`.

---

## MCP Wire Format (stdio)

```
Content-Length: <N>\r\n
\r\n
<N bytes of UTF-8 JSON>
```

## MCP SSE Transport (HTTP)

MCP SSE transport uses two HTTP endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sse` | GET | Client connects; server sends SSE events |
| `/message` | POST | Client sends JSON-RPC; server replies via SSE |

**Handshake**:
1. Client `GET /sse` — if `API_KEY` is set, server checks `Authorization: Bearer <key>` header; returns `401` on mismatch.
2. Server responds with `Content-Type: text/event-stream`.
3. Server immediately sends: `event: endpoint\ndata: /message?sessionId=<uuid>\n\n`
4. Client POSTs JSON-RPC to `/message?sessionId=<uuid>` — same `Authorization` header required.
5. Server dispatches, then sends response via SSE: `event: message\ndata: <json>\n\n`.
6. Server returns `202 Accepted` to the POST.

**Authentication**:
- Checked on every `GET /sse` and `POST /message` request.
- Expected header: `Authorization: Bearer <API_KEY>`.
- `API_KEY` not set (or empty) → no auth, all requests accepted.
- Wrong or missing key → HTTP `401 Unauthorized`.

**Session lifecycle**: each `GET /sse` creates a UUID session. The session is cleaned up when the client disconnects.

---

## API Contract

```python
from typing import BinaryIO, Any

def read_message(stream: BinaryIO) -> dict[str, Any]: ...
def write_message(stream: BinaryIO, msg: dict[str, Any]) -> None: ...
def dispatch(msg: dict[str, Any], config: Config, audit: AuditLogger) -> Optional[dict[str, Any]]: ...
def run_server(config: Config, audit: AuditLogger,
               stdin: Optional[BinaryIO] = None,
               stdout: Optional[BinaryIO] = None) -> None: ...
def run_sse_server(config: Config, audit: AuditLogger) -> None: ...
```

`dispatch()` is the shared JSON-RPC dispatch logic used by both transports.

---

## JSON-RPC Dispatch

| Method | Response |
|--------|----------|
| `initialize` | `{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mario","version":"<ver>"}}` |
| `initialized` | `None` (notification, no response) |
| `tools/list` | `{"tools": [<4 schemas>]}` |
| `tools/call` | `{"result": <handler return>}` |
| `ping` | `{"result": {}}` |
| Unknown | `{"error": {"code": -32601, "message": "Method not found"}}` |

---

## SSE Event Format

```
event: endpoint
data: /message?sessionId=550e8400-e29b-41d4-a716-446655440000

event: message
data: {"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}
```

Each SSE event ends with `\n\n`.

---

## Startup Output (stderr)

stdio:
```
mario starting
  transport : stdio
  cwd       : /home/ops
  timeout   : 30s
  allowlist : *
  blocklist : (none)
```

sse:
```
mario starting
  transport : sse
  listen    : http://0.0.0.0:8000/sse
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

On signal: `audit.close()`, then `sys.exit(0)`.

---

## Edge Cases

- Malformed JSON → JSON-RPC error `code: -32700`, continue.
- Unknown tool → `isError: True` response.
- `ConfigError` at startup → print to stderr, `sys.exit(1)`.
- EOF on stdin (stdio) → exit code 0.
- POST to unknown `sessionId` → HTTP 404.
- SSE client disconnects → server cleans up session, no crash.

---

## Acceptance Criteria

- [ ] `read_message` / `write_message` correctly frame and parse Content-Length messages.
- [ ] `initialize` returns correct `protocolVersion` and `serverInfo`.
- [ ] `tools/list` returns all 4 tool schemas.
- [ ] `tools/call` dispatches to the correct handler.
- [ ] Unknown method returns JSON-RPC error `code: -32601`.
- [ ] Malformed JSON returns JSON-RPC error `code: -32700` without crashing.
- [ ] EOF on stdin exits with code 0.
- [ ] SSE server starts on configured host:port.
- [ ] SSE `GET /sse` returns `text/event-stream` with `endpoint` event.
- [ ] SSE `POST /message` with valid JSON-RPC delivers response via SSE stream.
- [ ] POST to unknown sessionId returns HTTP 404.
- [ ] `mypy server.py` passes.


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
| `initialize` | `{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mario","version":"<ver>"}}` |
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
mario starting
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
