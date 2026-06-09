# Spec 08 — Tool Handler: search_files

## Goal

Provide a single tool that lets agents combine `find`-style filename matching and `grep`-style content matching across a directory tree, **without** spawning a shell or chaining `execute_command`. This is the highest-leverage UX improvement: most agent retries today come from agents trying to compose `find ... | xargs grep ...` pipelines and getting the syntax wrong.

---

## Scope

- One handler `handle_search_files(params, config, audit)`.
- Pure stdlib: `os.walk` + `re`.
- Read-only — no filesystem mutation.
- Subject to the same `allowed_paths` hard block and `server_cwd` soft approval as other filesystem tools.

---

## Tool Schema

```python
SEARCH_FILES_SCHEMA = {
    "name": "search_files",
    "description": (
        "Find files by name or content under a directory tree on the REMOTE server. "
        "Combines `find` (name patterns) and `grep` (content regex) into one call so the "
        "agent doesn't need to compose shell pipelines. Returns matching file paths and, "
        "when 'content' is set, the matching lines with line numbers. Read-only; never "
        "mutates the filesystem."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path":         {"type": "string",  "description": "Root directory to search. Defaults to the server working directory."},
            "name":         {"type": "string",  "description": "Glob to match file names (e.g. '*.py', 'config.*'). Empty = all files."},
            "content":      {"type": "string",  "description": "Regex to match file CONTENT line by line. Empty = filename-only search."},
            "case_sensitive": {"type": "boolean", "description": "Default false (case-insensitive content match)."},
            "max_depth":    {"type": "integer", "description": "Max directory recursion depth. 0 = root only. Default: 8."},
            "max_results":  {"type": "integer", "description": "Stop after this many matches across all files. Default: 200; max: 2000."},
            "show_hidden":  {"type": "boolean", "description": "Include hidden files / directories (names starting with '.'). Default false."},
            "approve":      {"type": "boolean", "description": "Set true to confirm searches outside the server working directory."},
        },
        "required": [],
    },
}
```

---

## API Contract

```python
def handle_search_files(
    params: Dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> Dict[str, Any]: ...
```

---

## Handler Logic

```
1. root = params.get('path') or config.server_cwd.
2. resolved = realpath(root).
3. check_path(resolved, config) -> if PolicyDenied: audit + error response.
4. If is_outside_cwd(resolved, server_cwd) and not approve:
     return approval-required response.
5. If resolved is not a directory: return error 'path is not a directory'.
6. Compile content regex if provided:
     flags = 0 if case_sensitive else re.IGNORECASE
     pattern = re.compile(content, flags)
   On regex error: return error 'invalid content regex: <msg>'.
7. Walk the tree with os.walk, pruning hidden dirs when show_hidden=False
   and limiting depth via the relative path component count.
8. For each file:
     a. If name pattern set, fnmatch(name, pattern) must succeed.
     b. If content pattern set:
          open file in binary mode; iterate line-by-line up to a 5000-line cap;
          decode each line as utf-8 errors='replace';
          if pattern.search(line): record (path, line_no, line_text).
        Skip files we cannot open (PermissionError / IsADirectoryError on
        broken symlink); record nothing for those.
        Skip files larger than max_output_bytes/2 (cheap binary guard).
     c. If only name pattern set: record (path,) — no line info.
9. Stop iterating once max_results is reached.
10. Format response (see below).
11. audit.log({tool: 'search_files', input, outcome: 'success'/'denied'/'approval_required'/'error'}).
```

### Hidden-file pruning during walk

When `show_hidden == False`:
- Strip dot-prefixed dirnames in-place from `os.walk`'s `dirnames` list each iteration so we don't even descend into `.git`, `.cache`, etc.
- Skip dot-prefixed file names.

### Depth limiting

`max_depth = 0` means only the root directory. `max_depth = 1` means root + immediate children. Depth is the number of `os.sep` segments below `root`.

---

## Response Format

When only filename matches were requested (`content` empty):
```
text:
  /abs/path/file1.py
  /abs/path/sub/file2.py
  3 matches
```

When content matches were requested:
```
text:
  /abs/path/foo.py:12: def some_function():
  /abs/path/foo.py:45:     return some_function()
  /abs/path/bar.py:7: import some_function
  3 matches in 2 files
```

Truncation notice (when stopped at `max_results`):
```
  …200 results — truncated. Narrow your query (name=, content=, path=, max_depth=).
```

Empty result:
```
no matches
```

---

## Edge Cases

- `path` defaults to `server_cwd` when omitted or empty.
- `name` defaults to `*` (match all files) when both `name` and `content` are empty — this surfaces a directory listing limited by depth.
- `content` regex with bad syntax → `isError: True` with reason.
- Symlink loops → `os.walk(followlinks=False)` so we don't loop.
- Binary files → still searchable line-by-line via utf-8 errors='replace'; but files larger than `max_output_bytes/2` are skipped (cheap heuristic).
- Permission denied on a file → silently skipped (not an error).
- `max_depth < 0` → clamp to 0.
- `max_results <= 0` → clamp to 1; > 2000 → clamp to 2000.

---

## Acceptance Criteria

- [ ] `search_files` is in `TOOLS` (5th tool).
- [ ] With `name='*.txt'`, returns paths whose basename matches the glob.
- [ ] With `content='hello'`, returns `path:line_no:line_text` entries for matches.
- [ ] Content matches are case-insensitive by default and honour `case_sensitive=True`.
- [ ] `max_depth=0` only searches the immediate directory.
- [ ] `max_depth=1` includes one level of subdirectories.
- [ ] `max_results` truncates output and emits a truncation notice.
- [ ] `show_hidden=False` (default) excludes `.git/` and `.hidden` files.
- [ ] `show_hidden=True` includes them.
- [ ] Path outside `allowed_paths` → `isError: True`.
- [ ] Path outside `server_cwd` without `approve` → approval-required.
- [ ] Path outside `server_cwd` with `approve=True` → succeeds.
- [ ] Path that is a regular file → error `'path is not a directory'`.
- [ ] Bad content regex → error `'invalid content regex'`.
- [ ] Permission-denied file is silently skipped (no error).
- [ ] One audit entry per call.
- [ ] Description string mentions the word `remote` so the agent understands the search runs on a remote host.
- [ ] `mypy server.py` passes.
