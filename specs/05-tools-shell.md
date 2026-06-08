# Spec 05 — Tool Handler: execute_command

## Goal

Implement the `execute_command` MCP tool: validate input via the **shell-aware** security checker, run the command in a scrubbed environment within an isolated process group, audit the result, and return a structured MCP tool response. The tool description is written so agents can pick the right tool on the first try.

---

## Tool Schema

```python
EXECUTE_COMMAND_SCHEMA = {
    "name": "execute_command",
    "description": (
        "Run a shell command on the host. Returns stdout, stderr, and exit code. "
        "Best for ad-hoc inspection (`systemctl status`, `journalctl -u svc`, `df -h`, "
        "`ps aux`, `tail -n 200 /var/log/...`). Prefer the dedicated tools when you "
        "can: `read_file` for file content, `list_directory` for ls, `search_files` "
        "for find/grep — they don't require approval for read paths inside the server "
        "working directory and are more reliable than crafting shell pipelines.\n\n"
        "Approval rules:\n"
        "  - Write/modify/delete commands (rm, mv, cp, chmod, chown, tar, wget, curl, …) "
        "    require approve=true.\n"
        "  - Shell redirects that write files (>, >>) require approve=true (only when shell=true).\n"
        "  - cwd outside the server working directory requires approve=true.\n"
        "  - Hardcoded blocks (mkfs, fdisk, shutdown, reboot, mount, kexec, crontab, …) "
        "    cannot be overridden.\n\n"
        "shell=true is required only for pipes/redirects/expansions; otherwise leave it "
        "false for safer argv-style execution."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command":      {"type": "string",  "description": "Shell command. With shell=false this is split via shlex."},
            "cwd":          {"type": "string",  "description": "Working directory. Defaults to the server working directory."},
            "shell":        {"type": "boolean", "description": "Enable shell expansion (pipes, redirects, glob). Default: false."},
            "timeout_secs": {"type": "integer", "description": "Per-call timeout. Clamped to server max."},
            "approve":      {"type": "boolean", "description": "Confirm write/modify operations or out-of-cwd execution."},
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
6. Approval gates (in order; first match wins):
     a. _is_outside_cwd(cwd, server_cwd) and not approve:
          audit(outcome='approval_required') + approval response.
     b. ANY unwrapped segment's basename in WRITE_COMMANDS and not approve:
          audit + approval response.
     c. use_shell AND detect_write_redirect(command) is not None and not approve:
          audit + approval response.
7. timeout = min(params.get('timeout_secs', config.command_timeout_secs),
                 config.command_timeout_secs).
8. result = execute(command, cwd, use_shell, config, override_timeout=timeout).
9. outcome = 'timeout' | 'success' | 'error'.
10. audit.log({...}).
11. Return formatted response.
```

The shell-aware approval check (6b) inspects every segment of `split_shell_segments`, applies `unwrap_executor_prefixes`, then matches the basename against `WRITE_COMMANDS`.

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
- [ ] Write redirect (`shell=true`, `command='echo x > /tmp/out'`, no `approve`) returns approval-required.
- [ ] Write redirect with `approve=true` succeeds.
- [ ] Pipeline `ls && cp a b` (shell=true, no approve) returns approval-required because the second segment is a write command.
- [ ] `sudo cp src dst` (no approve) returns approval-required (cp triggers approval after unwrap).
- [ ] Subprocess does NOT see `API_KEY`. Verified by running `echo $API_KEY` (shell=true) → empty stdout.
- [ ] Every call produces exactly one audit log entry.
- [ ] Description string mentions `read_file`, `list_directory`, `search_files`.
- [ ] Description string lists the approval rules.
- [ ] `mypy server.py` passes.
