# Spec 03 — Executor

## Goal

Spawn shell commands as child processes in a controlled, safe manner. Enforce timeouts, cap output size, and return structured results. This is the only section of `server.py` that spawns subprocesses.

---

## Scope

- Spawn commands using Python `subprocess` (stdlib).
- Enforce `command_timeout_secs` from Config.
- Cap combined stdout+stderr at `max_output_bytes`.
- Return a structured `ExecutionResult` dataclass.

---

## API Contract

```python
@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int        # process exit code; -1 if killed by timeout
    timed_out: bool
    truncated: bool       # True if output was capped at max_output_bytes
    duration_secs: float  # wall-clock execution time

def execute(
    command: str,
    cwd: str,
    use_shell: bool,
    config: Config,
) -> ExecutionResult:
    """Execute a command and return the result.
    Caller must run security checks before calling this."""
```

---

## Execution Behavior

1. If `use_shell=False` (default): split command into argv using `shlex.split()`.
2. Spawn with `subprocess.Popen`, capturing stdout and stderr separately.
3. Set `cwd` to the provided argument.
4. Use `communicate(timeout=config.command_timeout_secs)` to wait.
5. If `subprocess.TimeoutExpired`: kill the process, set `timed_out=True`, `exit_code=-1`.
6. Decode stdout/stderr as UTF-8 with `errors='replace'`.
7. If `len(stdout_bytes) + len(stderr_bytes) > max_output_bytes`: truncate and set `truncated=True`.
8. Record `duration_secs` as wall-clock time from spawn to completion.

---

## Edge Cases

- Command not found (FileNotFoundError) -> `exit_code=127`, `stderr='command not found: <cmd>'`.
- Zero-byte output -> `stdout=''`, `stderr=''`, `truncated=False`.
- Non-zero exit code is still a valid result.
- `cwd` does not exist -> catch `FileNotFoundError`, return `exit_code=-1`, `stderr='cwd does not exist: <path>'`.
- Output hitting cap -> truncate at byte boundary; append `'\n[truncated]'` to stderr.
- `use_shell=True` with empty command -> shell returns quickly with empty output.

---

## Acceptance Criteria

- [ ] `execute('echo hello', cwd, False, config)` returns `stdout='hello\n'`, `exit_code=0`, `timed_out=False`, `truncated=False`.
- [ ] A command exceeding `command_timeout_secs` is killed; result has `timed_out=True`, `exit_code=-1`.
- [ ] Output exceeding `max_output_bytes` is truncated; result has `truncated=True`.
- [ ] Non-zero exit code is captured correctly.
- [ ] Non-existent `cwd` returns error result without raising.
- [ ] `duration_secs` is a non-negative float.
- [ ] `mypy server.py` passes.
