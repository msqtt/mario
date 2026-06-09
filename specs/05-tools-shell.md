# Spec 05 — Tool Handler: execute_command

## Goal

Implement the `execute_command` MCP tool: validate input via the **shell-aware** security checker, run the command in a scrubbed environment within an isolated process group, audit the result, and return a structured MCP tool response. The tool description is written so agents can pick the right tool on the first try.

---

## Tool Schema

The description is **dynamically generated** based on `config.mode`:

```python
def _execute_command_description(config: Config) -> str:
    base = (
        "Run a shell command on the remote server. Returns stdout, stderr, and exit code. "
        "Best for ad-hoc inspection (systemctl status, journalctl, df -h, ps aux, "
        "tail -n 200 /var/log/...). Prefer the dedicated tools when possible: "
        "read_file for file content, list_directory for ls, search_files for "
        "find/grep -- they are more reliable than crafting shell pipelines.\n\n"
        "Set shell=true only when you need pipes/redirects/glob expansion; otherwise "
        "leave it false for safer argv-style execution."
    )
    return base + "\n\n" + _mode_suffix(config)

# _mode_suffix returns mode-specific guidance:
# - read: "Current mode: read. Write/modify/delete commands (rm, mv, cp, chmod...) will prompt the user for approval."
# - write: "Current mode: write. Commands within the working directory run freely including writes. Outside-cwd commands need user approval."
# - yolo: "Current mode: yolo. All commands run without approval prompts. Hardcoded safety blocks (shutdown, mkfs...) still enforced."
```

```python
EXECUTE_COMMAND_SCHEMA = {
    "name": "execute_command",
    "description": _execute_command_description(config),  # dynamic
    "inputSchema": {
        "type": "object",
        "properties": {
            "command":      {"type": "string",  "description": "Shell command. With shell=false this is split via shlex."},
            "cwd":          {"type": "string",  "description": "Working directory. Defaults to the server working directory."},
            "shell":        {"type": "boolean", "description": "Enable shell expansion (pipes, redirects, glob). Default: false."},
            "timeout_secs": {"type": "integer", "description": "Per-call timeout. Clamped to server max."},
            "approve":      {"type": "boolean", "description": "Internal field managed by the server's approval flow. Do NOT set this yourself."},
        },
        "required": ["command"],
    },
}
```

---

## Handler Logic

```
1. Extract params['command'] (must be str, non-empty after strip).
2. use_shell = bool(params.get('shell', False)).
3. check_command(command, config, use_shell=use_shell) -> if PolicyDenied:
     audit(outcome='denied') + error response.
4. cwd = params.get('cwd') or config.default_cwd.
5. If cwd came from params: check_path(cwd, config) -> if PolicyDenied:
     audit + error response.
6. Elicitation gates (MODE-aware; first match wins — returns _ElicitationNeeded(reason)):
     a. _is_outside_cwd(cwd, server_cwd) and mode != 'yolo' and not approve:
          audit(outcome='approval_required') + return _ElicitationNeeded(reason).
     b. ANY unwrapped segment's basename in WRITE_COMMANDS and not approve:
          - mode == 'yolo': skip (no approval needed).
          - mode == 'write': skip (cwd-internal writes are free).
          - mode == 'read': audit + return _ElicitationNeeded(reason).
     c. use_shell AND detect_write_redirect(command) is not None and not approve:
          - mode == 'yolo': skip.
          - mode == 'write': skip (cwd-internal).
          - mode == 'read': audit + return _ElicitationNeeded(reason).
7. timeout = min(params.get('timeout_secs', config.command_timeout_secs),
                 config.command_timeout_secs).
8. result = execute(command, cwd, use_shell, config, override_timeout=timeout).
9. outcome = 'timeout' | 'success' | 'error'.
10. audit.log({...}).
11. Return formatted response.
```

The shell-aware elicitation check (6b) inspects every segment of `split_shell_segments`, applies `unwrap_executor_prefixes`, then matches the basename against `WRITE_COMMANDS`.

The `_ElicitationNeeded` sentinel propagates to the HTTP transport layer (`do_POST`), which switches the response to SSE streaming and sends an `elicitation/create` request to the client. On the stdio transport the operation is immediately denied.

---

## Response Format — unchanged from v1.

---

## Acceptance Criteria

- [ ] Valid command returns stdout/stderr/exit_code in text response.
- [ ] Blocked command (any of: hardcoded, denylist, destructive pattern) returns `isError: True` and audit `outcome='denied'`.
- [ ] Wrapped block — `sudo shutdown` and `bash -c 'reboot'` — returns `isError: True` (denied).
- [ ] Timed-out command returns `isError: True` and `outcome='timeout'`.
- [ ] `cwd` outside allowed paths returns `isError: True`.
- [ ] `timeout_secs` is clamped to server max.
- [ ] Write redirect (`shell=true`, `command='echo x > /tmp/out'`, no `approve`) returns elicitation-required (`_ElicitationNeeded`).
- [ ] Write redirect with `approve=true` succeeds.
- [ ] Pipeline `ls && cp a b` (shell=true, no approve) returns elicitation-required because the second segment is a write command.
- [ ] `sudo cp src dst` (no approve) returns elicitation-required (cp triggers approval after unwrap).
- [ ] Subprocess does NOT see `API_KEY`. Verified by running `echo $API_KEY` (shell=true) → empty stdout.
- [ ] Every call produces exactly one audit log entry.
- [ ] `mode='write'`: write command within cwd (e.g. `cp a b`) does NOT require approval.
- [ ] `mode='write'`: command with cwd outside server_cwd still requires approval.
- [ ] `mode='yolo'`: write command and outside-cwd both skip approval.
- [ ] `mode='read'` (default): write command within cwd requires approval.
- [ ] Description string mentions `read_file`, `list_directory`, `search_files`.
- [ ] `mypy server.py` passes.
