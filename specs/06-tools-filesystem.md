# Spec 06 — Tool Handlers: Filesystem

## Goal

Implement three MCP tool handlers using Python stdlib `pathlib` / `os`: `read_file`, `write_file`, `list_directory`.

---

## Scope

- Three handler functions following the same pattern as `handle_execute_command`.
- All file I/O uses Python stdlib only.
- No streaming — full content in one operation (subject to `max_output_bytes`).

---

## Tool Schemas

```python
READ_FILE_SCHEMA = {
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

WRITE_FILE_SCHEMA = {
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

LIST_DIRECTORY_SCHEMA = {
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
```

---

## API Contract

```python
def handle_read_file(params: dict[str, Any], config: Config, audit: AuditLogger) -> dict[str, Any]: ...
def handle_write_file(params: dict[str, Any], config: Config, audit: AuditLogger) -> dict[str, Any]: ...
def handle_list_directory(params: dict[str, Any], config: Config, audit: AuditLogger) -> dict[str, Any]: ...
```

---

## Shared Pattern

```
1. resolved = str(Path(params['path']).resolve())
2. check_path(resolved, config) -> if PolicyDenied: audit + return error.
3. Perform I/O.
4. audit.log({outcome: ...}).
5. Return response dict.
```

---

## read_file Behavior

- cap = min(params.get('max_bytes', config.max_output_bytes), config.max_output_bytes)
- Read up to `cap` bytes.
- `encoding='base64'`: read raw bytes, return base64-encoded string.
- Path is a directory -> error: `"path is a directory, not a file"`.
- If truncated: append `'\n[Truncated at <N> bytes]'`.

## write_file Behavior

- `encoding='base64'`: base64-decode `content` before writing raw bytes.
- `create_dirs=True`: `Path(path).parent.mkdir(parents=True, exist_ok=True)`.
- Missing parent + `create_dirs=False` -> I/O error -> `isError: True`.
- Success response: `"Written <N> bytes to <path>"`.

## list_directory Behavior

- Path is a file -> error: `"path is a file, not a directory"`.
- Entry format: `"d  <name>/"` | `"f  <name>"` | `"l  <name> -> <target>"`.
- `show_hidden=False` (default): skip entries starting with `.`.
- Sort: directories first, then files, both alphabetically.
- Empty directory -> empty string content, no error.

---

## Acceptance Criteria

- [ ] All 3 tools appear in `TOOLS` list in `server.py`.
- [ ] `read_file` returns correct file content.
- [ ] `read_file` truncates at `max_bytes` and appends truncation notice.
- [ ] `write_file` creates or overwrites a file correctly.
- [ ] `write_file` with `create_dirs=True` creates missing parent directories.
- [ ] `list_directory` returns formatted list with type indicators.
- [ ] All tools reject paths outside `allowed_paths` with `isError: True`.
- [ ] Every call produces exactly one audit log entry.
- [ ] `mypy server.py` passes.
