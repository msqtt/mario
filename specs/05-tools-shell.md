# Spec 05 — Tool Handler: execute_command

## Goal

Implement the `execute_command` MCP tool handler: validate input, enforce security policy, run the command, audit the result, and return a structured MCP tool response dict.

---

## Scope

- Single function `handle_execute_command(params, config, audit)`.
- Orchestrates: security check -> execute -> audit -> format response.

---

## Tool Schema

```python
EXECUTE_COMMAND_SCHEMA = {
    "name": "execute_command",
    "description": (
        "Execute a shell command on the server and return stdout, stderr, and exit code. "
        "Use for DevOps tasks such as checking service status, viewing logs, or running scripts."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command":      {"type": "string",  "description": "Shell command to execute."},
            "cwd":          {"type": "string",  "description": "Working directory. Defaults to DEFAULT_CWD."},
            "shell":        {"type": "boolean", "description": "Enable shell expansion (pipes, redirects). Default: false."},
            "timeout_secs": {"type": "integer", "description": "Override timeout (seconds). Clamped to server max."},
        },
        "required": ["command"],
    },
}
```

---

## API Contract

```python
def handle_execute_command(
    params: dict[str, Any],
    config: Config,
    audit: AuditLogger,
) -> dict[str, Any]:
    """Return an MCP tool result dict."""
```

---

## Handler Logic

```
1. Extract params['command'] (must be str, non-empty).
2. check_command(command, config) -> if PolicyDenied: audit(outcome='denied') + return error response.
3. cwd = params.get('cwd') or config.default_cwd.
4. If cwd came from params: check_path(cwd, config) -> if PolicyDenied: audit + error response.
5. timeout = min(params.get('timeout_secs', config.command_timeout_secs), config.command_timeout_secs).
6. use_shell = bool(params.get('shell', False)).
7. result = execute(command, cwd, use_shell, config).
8. outcome = 'timeout' if result.timed_out else ('success' if result.exit_code == 0 else 'error').
9. audit.log({...}).
10. Return formatted response.
```

---

## Response Format

Success (exit_code == 0):
```python
{"content": [{"type": "text", "text": "Exit code: 0\n\nSTDOUT:\nhello\n\nSTDERR:\n"}]}
```

Non-zero exit or timeout:
```python
{"content": [{"type": "text", "text": "Exit code: 1\nTimed out: False\n\nSTDOUT:\n...\n\nSTDERR:\n..."}], "isError": True}
```

Policy denied:
```python
{"content": [{"type": "text", "text": "Command denied: rm is in the blocked list"}], "isError": True}
```

Truncated output: append `'\n[Output truncated at <N> bytes]'` to text.

---

## Acceptance Criteria

- [ ] Valid command returns stdout/stderr/exit_code in text response.
- [ ] Blocked command returns `isError: True` and audit entry with `outcome='denied'`.
- [ ] Timed-out command returns `isError: True` and audit entry with `outcome='timeout'`.
- [ ] `cwd` outside allowed paths is rejected.
- [ ] `timeout_secs` is clamped to server max.
- [ ] Every call produces exactly one audit log entry.
- [ ] `mypy server.py` passes.
