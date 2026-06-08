# Spec 06 — Tool Handlers: Filesystem

## Goal

Three MCP tool handlers — `read_file`, `write_file`, `list_directory` — using only Python stdlib `pathlib` / `os`. Tool descriptions are explicit so agents pick the right tool without guessing.

---

## Tool Schemas (richer descriptions)

```python
READ_FILE_SCHEMA = {
    "name": "read_file",
    "description": (
        "Read the content of a single file. Use this in preference to "
        "`execute_command(\"cat …\")`: no shell, no approval needed for paths "
        "inside the server working directory, and structured truncation. "
        "Use encoding='base64' for binary files."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":      {"type": "string",  "description": "Absolute or working-dir-relative file path."},
            "encoding":  {"type": "string",  "enum": ["utf-8", "base64"], "description": "utf-8 (default) or base64."},
            "max_bytes": {"type": "integer", "description": "Cap on bytes read; clamped to server max_output_bytes."},
            "approve":   {"type": "boolean", "description": "Required to read paths outside the server working directory."},
        },
        "required": ["path"],
    },
}

WRITE_FILE_SCHEMA = {
    "name": "write_file",
    "description": (
        "Write content to a file (creates or overwrites). ALWAYS requires "
        "approve=true — every call is a confirmation point. Use encoding='base64' "
        "for binary; set create_dirs=true to mkdir -p the parent."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string"},
            "content":     {"type": "string",  "description": "File content. base64-encoded when encoding='base64'."},
            "encoding":    {"type": "string",  "enum": ["utf-8", "base64"]},
            "create_dirs": {"type": "boolean", "description": "Create parent directories if missing."},
            "approve":     {"type": "boolean", "description": "Must be true to authorise the write."},
        },
        "required": ["path", "content"],
    },
}

LIST_DIRECTORY_SCHEMA = {
    "name": "list_directory",
    "description": (
        "List a directory's entries. Prefer this over `execute_command(\"ls …\")` — "
        "no shell, structured d/f/l prefixes, and no approval needed for paths "
        "inside the server working directory. With no `path` it lists the server "
        "working directory."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string",  "description": "Directory path; defaults to the server working directory."},
            "show_hidden": {"type": "boolean", "description": "Include dot-files. Default false."},
            "approve":     {"type": "boolean", "description": "Required to list paths outside the server working directory."},
        },
        "required": [],
    },
}
```

`list_directory.path` is **no longer required** in the schema — the handler defaults to `server_cwd`.

---

## API Contract — unchanged.

## Shared Pattern — unchanged (resolve, check_path, soft cwd gate, I/O, audit).

---

## read_file Behaviour — unchanged from v1.

## write_file Behaviour — unchanged from v1.

## list_directory Behaviour — unchanged from v1, plus:
- When `path` is missing or empty, default to `config.server_cwd`.

---

## Acceptance Criteria (deltas only — see test file for full set)

- [ ] All 4 filesystem tools (`read_file`, `write_file`, `list_directory`, `search_files`) appear in `TOOLS`.
- [ ] `list_directory.inputSchema.required` does **not** include `path`.
- [ ] `read_file.description` mentions `execute_command` to nudge the agent away from `cat`.
- [ ] `list_directory.description` mentions `execute_command` to nudge the agent away from `ls`.
- [ ] `write_file.description` says "ALWAYS requires approve=true".
- [ ] All filesystem tools reject paths outside `allowed_paths`.
- [ ] `list_directory({})` lists `server_cwd`.
- [ ] One audit entry per call.
- [ ] `mypy server.py` passes.
