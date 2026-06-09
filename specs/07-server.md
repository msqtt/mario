# Spec 07 — MCP Protocol & Server Entry Point

## Goal

Implement the MCP **stdio** and **Streamable HTTP** transports using Python stdlib only. stdio is for local agent connections; Streamable HTTP (MCP spec 2025-03-26) is the wire protocol for remote agent access — it replaces the now-deprecated HTTP+SSE transport.

The server authenticates with constant-time comparison, caps request bodies, surfaces a clear `instructions` payload to clients, and refuses to start in obviously insecure configurations.

---

## Scope

- `Content-Length` framed JSON-RPC reader/writer (stdio).
- HTTP server using `http.server.HTTPServer` + `socketserver.ThreadingMixIn`.
- Single endpoint `/mcp` accepting `POST`, `GET`, `DELETE`, `OPTIONS`.
- Handle MCP methods: `initialize`, `initialized`, `tools/list`, `tools/call`, `ping`.
- Print startup info to `sys.stderr` only.
- Handle `SIGINT` / `SIGTERM` for graceful shutdown.
- **Constant-time auth comparison** (`hmac.compare_digest`).
- **Bound `Content-Length`** on POST bodies to `config.max_request_bytes`.
- **Reject `Transfer-Encoding: chunked`** (we don't support chunked decoding; treating an unsupported TE as 0-length is a request-smuggling foothold).
- **Reject non-loopback bind without `API_KEY`** at config-load time (defense in depth alongside the actual HTTP handler).

---

## MCP Wire Format (stdio) — unchanged from v1.

```
Content-Length: <N>\r\n
\r\n
<N bytes of UTF-8 JSON>
```

---

## MCP Streamable HTTP Transport

### Endpoint

A single endpoint, `/mcp`. All other paths return `404 Not Found`.

### Methods

| Method | Behaviour |
|---|---|
| `POST /mcp`   | Send a JSON-RPC request, notification, response, or batch. Server replies `200 OK` + `application/json` for normal requests, `200 OK` + `text/event-stream` for requests requiring elicitation, or `202 Accepted` for notifications/responses. |
| `GET /mcp`    | Reserved for server-initiated SSE streaming. This server has no server-initiated messages, so it returns `405 Method Not Allowed`. |
| `DELETE /mcp` | Client-initiated session termination. Returns `200 OK`. If a known `Mcp-Session-Id` is present, the entry is removed from the in-memory session set. |
| `OPTIONS /mcp` | CORS preflight. Returns `200` with `Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS`, `Access-Control-Allow-Headers: Authorization, Content-Type, Mcp-Session-Id`. |

### Request format (POST)

- `Content-Type: application/json` (required).
- `Accept` SHOULD include `application/json, text/event-stream` per spec; the server does not enforce, since we only ever return `application/json` (no SSE).
- Body: a single JSON-RPC message OR a JSON array (batch).

### Response format (POST)

- Notifications-only / responses-only payload → `202 Accepted`, no body.
- Normal tool calls → `200 OK` with `Content-Type: application/json` and a single JSON-RPC response (or array, matching the request batch shape).
- **Elicitation-required tool calls** → `200 OK` with `Content-Type: text/event-stream` (SSE). The stream contains:
  1. An `elicitation/create` JSON-RPC request (server→client) asking the user for approval.
  2. After the client responds (via a separate POST), the final `tools/call` JSON-RPC response.
  3. Stream closes after the final response.

### Handling client JSON-RPC responses (elicitation answers)

When a `POST /mcp` body is a JSON-RPC **response** (has `id` + `result`/`error`, no `method`), the server resolves the corresponding pending elicitation and returns `202 Accepted`.

### Session management

- On the **first** `initialize` POST, the server generates a session ID via `uuid.uuid4()` and returns it on the response as `Mcp-Session-Id: <id>`.
- Clients SHOULD echo the `Mcp-Session-Id` header on subsequent `POST` and `DELETE` calls.
- The server MAINTAINS an in-memory set of active session IDs (capped at 256, oldest evicted on overflow).
- When a request arrives with `Mcp-Session-Id` set:
  - If the value is in the active set → accept.
  - If the value is **not** in the active set → respond `404 Not Found` with body `session not found`.
- Requests **without** the header are accepted (permissive — agents that don't speak sessions still work; the security boundary is `API_KEY`, not the session ID).
- `DELETE /mcp` with a known `Mcp-Session-Id` removes it from the set; with no header it is a no-op `200`.

### Authentication

- `Authorization: Bearer <API_KEY>` is required on every `POST`, `GET`, and `DELETE` when `API_KEY` is set.
- Comparison MUST use `hmac.compare_digest(provided.encode(), expected.encode())` to avoid timing leaks.
- Missing header / wrong key → HTTP `401 Unauthorized` with body `unauthorized`.

### Request size cap

- For `POST /mcp`:
  - If `Transfer-Encoding: chunked` is present → `400 Bad Request` (`chunked transfer-encoding not supported`).
  - Read `Content-Length` header.
  - If header is missing → `411 Length Required`.
  - If non-numeric → `400 Bad Request`.
  - If negative or > `config.max_request_bytes` → `413 Payload Too Large`, **without reading any body bytes**.
  - Then read **exactly** `Content-Length` bytes.

### CORS

- `Access-Control-Allow-Origin: *` retained for non-credentialed access.
- `Access-Control-Allow-Credentials` is NOT set.
- `Access-Control-Expose-Headers: Mcp-Session-Id` so client JS (where applicable) can read the session header.

---

## `initialize` Response (enriched)

The MCP `initialize` response now includes an `instructions` field describing what the server is for and how to use it. This dramatically improves agent first-call accuracy:

```python
{
    "protocolVersion": "2025-06-18",
    "capabilities": {"tools": {}, "elicitation": {}},
    "serverInfo": {"name": "mario", "version": "<ver>"},
    "instructions": _build_instructions(config),
}
```

`_build_instructions(config)` generates a mode-aware instruction string containing:
1. **Identity & purpose**: Mario is the agent's hands on a REMOTE Linux server. Connecting to mario means the agent has been granted server-control: every file path and shell command resolves on the REMOTE host, never on the agent's local environment. Whenever the user says "the server", "this host", "remote machine", "server上的代码", or asks to view / open / read / edit / modify line N of a file, the agent MUST route the request through these MCP tools.
2. **User-intent → tool mapping** (the most important section — eliminates retries):
   - View / open / read / inspect a file → `read_file`.
   - Modify a specific line or range → `read_file` to fetch current content, mutate in memory, then `write_file` with the **full** new file content. Mario has no partial-edit primitive; `write_file` always overwrites.
   - Create or replace a file outright → `write_file`.
   - Browse a directory / list files → `list_directory`.
   - Find a file by name → `search_files(name="...")`.
   - Search code for a string / regex → `search_files(content="...")`.
   - Run an arbitrary shell command (status, logs, processes, package mgmt) → `execute_command`.
3. **Working directory**: The resolved `server_cwd` path.
4. **Mode + permissions matrix**: Mode-specific summary of what runs freely vs what triggers user approval:
   - `read`: "You can read files and run read-only commands in {cwd} freely. Any write operation or access outside {cwd} will prompt the user for approval."
   - `write`: "You can read and write files freely within {cwd}. Access outside {cwd} will prompt the user for approval."
   - `yolo`: "You have full read/write access. No approval prompts. Hardcoded safety blocks still enforced."
5. **Tool preference**: prefer `read_file` over `cat`, `list_directory` over `ls`, `search_files` over `find|grep` piped through `execute_command` — the dedicated tools are structured and more reliable.
6. **Approval flow**: do NOT set the `approve` argument manually; the server obtains user confirmation via MCP elicitation when required.
7. **Safety blocks**: Hardcoded blocked commands (mkfs, fdisk, shutdown, reboot, mount, kexec, crontab, ...) cannot be overridden regardless of mode.

The server declares `"elicitation": {}` in its capabilities to indicate it will send `elicitation/create` requests when write operations or out-of-cwd access is attempted. Clients SHOULD declare `{"capabilities": {"elicitation": {}}}` in their `initialize` params to enable this flow.

When delivered over Streamable HTTP, the response also carries a `Mcp-Session-Id` HTTP header. The server stores the client's declared capabilities from `initialize` params to determine if elicitation is supported.

---

## Tool List & Schemas (`tools/list`)

Returns five tools:

1. `execute_command`
2. `read_file`
3. `write_file`
4. `list_directory`
5. `search_files`

### Dynamic tool descriptions (mode-aware)

Tool schemas are **generated at startup** based on `config.mode`. Each tool's `description` includes a **mode-specific suffix** explaining what the agent can do without triggering approval:

- **`read` mode**: descriptions warn that writes require user approval.
- **`write` mode**: descriptions note that cwd-internal writes are free, outside-cwd needs approval.
- **`yolo` mode**: descriptions state no approval needed (safety blocks still enforced).

A function `_build_tools(config)` generates the TOOLS list at startup. The descriptions use a `_mode_suffix(config)` helper to append the mode-specific context to each tool's base description.

### `approve` field documentation

All tool schemas include `"approve": {"type": "boolean", "description": "..."}` with an explanation:

```
"approve": {
    "type": "boolean",
    "description": "Internal field managed by the server's approval flow. Do NOT set this yourself; the server handles user confirmation via elicitation."
}
```

This prevents agents from guessing they should set `approve: true` themselves (which would bypass the human-in-the-loop).

---

## API Contract

```python
def read_message(stream: BinaryIO) -> Dict[str, Any]: ...
def write_message(stream: BinaryIO, msg: Dict[str, Any]) -> None: ...
def dispatch(msg: Dict[str, Any], config: Config, audit: AuditLogger) -> Optional[Dict[str, Any]]: ...
def run_server(config: Config, audit: AuditLogger,
               stdin: Optional[BinaryIO] = None,
               stdout: Optional[BinaryIO] = None) -> None: ...
def run_http_server(config: Config, audit: AuditLogger) -> None: ...
def is_loopback_host(host: str) -> bool: ...
```

---

## JSON-RPC Dispatch (unchanged shapes)

| Method | Response |
|--------|----------|
| `initialize` | result + `instructions` |
| `initialized` | None (notification) |
| `tools/list` | 5 tools |
| `tools/call` | handler return |
| `ping` | `{}` |
| Unknown | error `-32601` |

A JSON-RPC message without an `id` (a notification) returns `None`; on the HTTP transport this triggers a `202 Accepted`.

---

## Startup Output (stderr)

```
mario starting
  transport : http
  cwd       : /home/ops
  mode      : read
  listen    : http://localhost:8000/mcp
  auth      : ENABLED (Bearer)         # or "DISABLED — only safe for loopback"
  timeout   : 30s
  allowlist : *
  blocklist : (none)
  body cap  : 1048576 bytes
```

If `API_KEY` is not set on a loopback bind, print a warning line:

```
  warning   : no API_KEY set; safe only on loopback ('localhost'/'127.0.0.1'/'::1')
```

---

## Edge Cases

- Malformed JSON → JSON-RPC error `code: -32700` returned in the HTTP body, status `200`. (We never crash.)
- Unknown tool → `isError: True` content block.
- `ConfigError` at startup → print to stderr, exit 1.
- EOF on stdin → exit 0.
- POST with unknown `Mcp-Session-Id` → HTTP 404.
- POST `Content-Length` > cap → HTTP 413.
- POST missing or non-numeric `Content-Length` → HTTP 411 / 400.
- POST with `Transfer-Encoding: chunked` → HTTP 400.
- Body shorter than declared length → handler returns whatever was read; the JSON-decode path produces a `-32700` error.
- HTTP client disconnects mid-response → server logs nothing and continues.

---

## Acceptance Criteria

- [ ] `read_message` / `write_message` correctly frame and parse Content-Length messages.
- [ ] `initialize` response **includes `instructions` containing the word "mario"** and the resolved `server_cwd` path and the current `mode`.
- [ ] `initialize` response `instructions` emphasises that all operations go through this server (not locally) and uses the word `remote`.
- [ ] `initialize` response `instructions` explicitly maps user intents to tools: it must mention `read_file`, `write_file`, `list_directory`, `search_files`, and `execute_command` by name.
- [ ] `initialize` response `instructions` documents the line-edit pattern: when the user asks to modify line N, the agent MUST `read_file` first then `write_file` with the full updated content (mario has no partial-edit primitive).
- [ ] `initialize` response `instructions` tells the agent NOT to set the `approve` argument by hand.
- [ ] `tools/list` returns all **5** tool schemas including `search_files`.
- [ ] `tools/list` tool descriptions are **mode-aware**: they include mode-specific guidance text.
- [ ] `tools/list` tool descriptions in `yolo` mode mention "no approval" or equivalent.
- [ ] `tools/list` tool descriptions in `read` mode mention "approval" or "user confirmation".
- [ ] All tool schemas have `approve` field with a `description` telling the agent NOT to set it manually.
- [ ] `tools/call` dispatches to the correct handler.
- [ ] Unknown method returns JSON-RPC error `code: -32601`.
- [ ] Malformed JSON returns `code: -32700` without crashing.
- [ ] EOF on stdin exits with code 0.
- [ ] HTTP server starts on configured `HTTP_HOST:HTTP_PORT` and serves `/mcp`.
- [ ] `POST /mcp` with a request returns `200 OK`, `Content-Type: application/json`, JSON-RPC response in the body.
- [ ] `POST /mcp` with a notification (no `id`) returns `202 Accepted`.
- [ ] `POST /mcp` with a JSON array containing only notifications returns `202 Accepted`.
- [ ] `POST /mcp` with a JSON array containing requests returns `200 OK` with a JSON-array response of matching length and `id`s.
- [ ] `GET /mcp` returns `405 Method Not Allowed`.
- [ ] `DELETE /mcp` returns `200 OK` and clears any matching `Mcp-Session-Id`.
- [ ] `OPTIONS /mcp` returns `200 OK` with the documented CORS headers.
- [ ] `initialize` response carries an `Mcp-Session-Id` HTTP header.
- [ ] A subsequent `POST /mcp` echoing that `Mcp-Session-Id` succeeds.
- [ ] A `POST /mcp` with an unknown `Mcp-Session-Id` returns `404 Not Found`.
- [ ] A `POST /mcp` with no `Mcp-Session-Id` succeeds (permissive).
- [ ] `POST /mcp` with `Content-Length` > `max_request_bytes` returns HTTP 413 without reading the body.
- [ ] `POST /mcp` with non-numeric `Content-Length` returns HTTP 400.
- [ ] `POST /mcp` with missing `Content-Length` returns HTTP 411.
- [ ] `POST /mcp` with `Transfer-Encoding: chunked` returns HTTP 400.
- [ ] **Auth comparison uses `hmac.compare_digest`** (verified by inspecting source).
- [ ] **Wrong API key returns 401**; correct key returns 200.
- [ ] **`HTTP_HOST=0.0.0.0` without `API_KEY` exits with non-zero code at startup.**
- [ ] **`is_loopback_host('localhost')`, `('127.0.0.1')`, `('::1')` all return True; `('0.0.0.0')` and `('10.0.0.5')` return False.**
- [ ] `mypy server.py` passes.
