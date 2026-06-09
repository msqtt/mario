# Spec 06 — Tool Handlers: Filesystem

## Goal

Three MCP tool handlers — `read_file`, `write_file`, `list_directory` — using only Python stdlib `pathlib` / `os`. Tool descriptions are explicit so agents pick the right tool without guessing.

---

## Tool Schemas (mode-aware dynamic descriptions)

Tool descriptions are **dynamically generated** based on `config.mode` so agents know upfront what triggers approval:

```python
READ_FILE_SCHEMA = {
    "name": "read_file",
    "description": _read_file_description(config),  # dynamic
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":      {"type": "string",  "description": "Absolute or working-dir-relative file path."},
            "encoding":  {"type": "string",  "enum": ["utf-8", "base64"], "description": "utf-8 (default) or base64."},
            "max_bytes": {"type": "integer", "description": "Cap on bytes read; clamped to server max_output_bytes."},
            "approve":   {"type": "boolean", "description": "Internal field managed by the server's approval flow. Do NOT set this yourself."},
        },
        "required": ["path"],
    },
}

WRITE_FILE_SCHEMA = {
    "name": "write_file",
    "description": _write_file_description(config),  # dynamic
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string"},
            "content":     {"type": "string",  "description": "File content. base64-encoded when encoding='base64'."},
            "encoding":    {"type": "string",  "enum": ["utf-8", "base64"]},
            "create_dirs": {"type": "boolean", "description": "Create parent directories if missing."},
            "approve":     {"type": "boolean", "description": "Internal field managed by the server's approval flow. Do NOT set this yourself."},
        },
        "required": ["path", "content"],
    },
}

LIST_DIRECTORY_SCHEMA = {
    "name": "list_directory",
    "description": _list_directory_description(config),  # dynamic
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":        {"type": "string",  "description": "Directory path; defaults to the server working directory."},
            "show_hidden": {"type": "boolean", "description": "Include dot-files. Default false."},
            "approve":     {"type": "boolean", "description": "Internal field managed by the server's approval flow. Do NOT set this yourself."},
        },
        "required": [],
    },
}
```

### Description generation functions

Each `_<tool>_description(config)` function appends a mode-specific suffix via `_mode_suffix(config)`:

- **`read_file`**: Base = "Read a file from the REMOTE server and return its full content. Use this whenever the user asks to view, open, inspect, or look at a file on the server (e.g. 'show me line 42 of foo.py' — fetch with read_file, then count lines locally). Always preferred over execute_command(\"cat ...\") / head / tail: no shell, structured truncation, predictable encoding. Use encoding='base64' for binary files."
  - read: + "Files within the working directory can be read freely. Outside-cwd paths prompt for user approval."
  - write: same as read
  - yolo: + "All files accessible without approval."

- **`write_file`**: Base = "Write content to a file on the REMOTE server (creates or overwrites — there is NO partial/in-place edit primitive). Standard workflow when the user asks to modify line N or a small region: (1) call read_file to fetch the current full content, (2) modify the relevant line(s) locally in your reasoning, (3) call write_file with the COMPLETE updated file content. Use encoding='base64' for binary; set create_dirs=true to mkdir -p the parent."
  - read: + "All writes require user approval (a confirmation dialog will appear)."
  - write: + "Writes within the working directory proceed freely. Outside-cwd writes prompt for user approval."
  - yolo: + "All writes proceed without approval. Hardcoded safety blocks still enforced."

- **`list_directory`**: Base = "List a directory's entries on the REMOTE server. Prefer this over execute_command(\"ls ...\"): no shell, structured d/f/l prefixes. With no path it lists the server working directory."
  - read/write: + "Outside-cwd paths prompt for user approval."
  - yolo: + "All directories accessible without approval."

---

## API Contract — unchanged.

## Shared Pattern — unchanged (resolve, check_path, soft cwd gate, I/O, audit).

---

## read_file Behaviour — MODE-aware:
- In `read` and `write` modes: paths outside `server_cwd` require approval.
- In `yolo` mode: all path-based approvals are skipped.
- `ALLOWED_PATHS` hard block is always enforced.

## write_file Behaviour — MODE-aware:
- In `read` mode (default): always requires approval (elicitation) regardless of path.
- In `write` mode: cwd-internal writes are free; outside-cwd writes require approval.
- In `yolo` mode: all path-based approvals skipped (writes anywhere proceed without elicitation).
- In all modes, `ALLOWED_PATHS` hard block is still enforced (PolicyDenied, not approval).
- Both utf-8 and base64 paths encode content to bytes and call `p.write_bytes(data)`.
  (utf-8 content is encoded with `.encode("utf-8")` before writing.)

## list_directory Behaviour — MODE-aware, plus:
- In `read` and `write` modes: paths outside `server_cwd` require approval.
- In `yolo` mode: all path-based approvals are skipped.
- When `path` is missing or empty, default to `config.server_cwd`.

---

## Acceptance Criteria (deltas only — see test file for full set)

- [ ] All 4 filesystem tools (`read_file`, `write_file`, `list_directory`, `search_files`) appear in `TOOLS`.
- [ ] `list_directory.inputSchema.required` does **not** include `path`.
- [ ] `read_file.description` mentions `execute_command` to nudge the agent away from `cat`.
- [ ] `read_file.description` mentions the word `remote` so the agent understands the file lives on a remote host.
- [ ] `write_file.description` documents the read-modify-write pattern (mentions `read_file` and "overwrite" or "no partial" / "no in-place") so the agent knows how to handle "modify line N" requests.
- [ ] `list_directory.description` mentions `execute_command` to nudge the agent away from `ls`.
- [ ] `write_file` requires approval (elicitation) in `read` mode when `approve` is not `True`.
- [ ] `write_file` in `write` mode: cwd-internal write does NOT require approval.
- [ ] `write_file` in `write` mode: outside-cwd write requires approval.
- [ ] `write_file` in `yolo` mode: no approval required regardless of path.
- [ ] All filesystem tools reject paths outside `allowed_paths` regardless of mode.
- [ ] `list_directory({})` lists `server_cwd`.
- [ ] One audit entry per call.
- [ ] `mypy server.py` passes.
