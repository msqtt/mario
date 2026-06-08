# Spec 03 — Executor

## Goal

Spawn shell commands as child processes in a controlled, safe manner. Enforce timeouts, cap output size, isolate the process group, and scrub the inherited environment.

---

## Scope

- Spawn commands using Python `subprocess` (stdlib).
- Enforce `command_timeout_secs` from Config.
- Cap combined stdout+stderr at `max_output_bytes`.
- **Isolate** the child via `start_new_session=True` so timeout-kill cleans up grandchildren.
- **Scrub** the environment so secret env vars (e.g. `API_KEY`) are not visible to the spawned command.
- Return a structured `ExecutionResult` dataclass.

---

## API Contract

```python
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
    override_timeout: Optional[int] = None,
) -> ExecutionResult: ...

def build_subprocess_env() -> Dict[str, str]:
    """Return an env dict suitable for child processes — passes through a
    safe whitelist (PATH/HOME/LANG/TZ/USER/etc) plus the comma-separated
    EXTRA_ENV_PASSTHROUGH names; explicitly drops API_KEY and anything
    matching SECRET_KEY_PATTERN."""
```

---

## Execution Behaviour

1. If `use_shell=False` (default): split command into argv using `shlex.split()`.
2. Spawn with `subprocess.Popen`, capturing stdout and stderr separately.
3. **Always** pass `start_new_session=True` so the child becomes its own process-group leader (POSIX). Windows is out of scope.
4. **Always** pass `env=build_subprocess_env()` instead of inheriting the parent's full environment.
5. Set `cwd` to the provided argument.
6. Use `communicate(timeout=…)` to wait.
7. On `subprocess.TimeoutExpired`:
   - Send `SIGTERM` to the **process group** with `os.killpg(proc.pid, SIGTERM)`.
   - Wait up to 1 second for graceful exit.
   - Then `os.killpg(proc.pid, SIGKILL)` to ensure cleanup of any forked children.
   - Set `timed_out=True`, `exit_code=-1`.
8. Decode stdout/stderr as UTF-8 with `errors='replace'`.
9. Truncate combined output at `max_output_bytes`; append `'\n[truncated]'` to stderr.
10. Record `duration_secs` as wall-clock time.

---

## Environment Scrubbing — `build_subprocess_env`

```
SAFE_ENV_KEYS   = {"PATH","HOME","LANG","LC_ALL","LC_CTYPE","TZ","USER",
                   "LOGNAME","SHELL","TERM","PWD"}
SECRET_PATTERN  = re.compile(r"(KEY|TOKEN|SECRET|PASS|CRED)", re.IGNORECASE)
ALWAYS_DROP     = {"API_KEY"}
EXTRA_ENV_PASSTHROUGH = os.environ.get("EXTRA_ENV_PASSTHROUGH", "").split(",")
```

Algorithm:

```
out = {}
for key, value in os.environ.items():
    if key in ALWAYS_DROP:                continue
    if key in SAFE_ENV_KEYS:              out[key] = value; continue
    if key in EXTRA_ENV_PASSTHROUGH:
        if SECRET_PATTERN.search(key):    continue   # never override the secret block
        out[key] = value
return out
```

A child running `env` only sees `SAFE_ENV_KEYS` plus opt-in passthroughs. `API_KEY` is unconditionally absent.

---

## Edge Cases

- Command not found (FileNotFoundError) -> `exit_code=127`.
- Zero-byte output -> `stdout=''`, `stderr=''`, `truncated=False`.
- Non-zero exit code is still a valid result.
- `cwd` does not exist -> `exit_code=-1`, `stderr='cwd does not exist: <path>'`.
- Output hitting cap -> truncate at byte boundary; append `'\n[truncated]'` to stderr.
- Timeout while child has spawned grandchildren (e.g. via `&`, `nohup`) -> `os.killpg` reaps them.
- POSIX-only assumption: `os.killpg` and `start_new_session`. Windows is **not supported**.

---

## Acceptance Criteria

- [ ] `execute('echo hello', cwd, False, config)` returns `stdout='hello\n'`, `exit_code=0`.
- [ ] A command exceeding `command_timeout_secs` is killed: `timed_out=True`, `exit_code=-1`.
- [ ] **Grandchildren of a timed-out shell command are also killed** (no orphans). Validated by spawning `bash -c 'sleep 30 &'` and confirming the sleep PID disappears within 2s of the timeout.
- [ ] Output exceeding `max_output_bytes` is truncated.
- [ ] Non-zero exit code is captured correctly.
- [ ] Non-existent `cwd` returns error result without raising.
- [ ] `duration_secs` is a non-negative float.
- [ ] **`build_subprocess_env()` does NOT include `API_KEY`** even when `os.environ['API_KEY']` is set.
- [ ] **Child running `env` does NOT see `API_KEY` in its output** (integration check).
- [ ] `build_subprocess_env()` includes `PATH` (so commands resolve).
- [ ] `mypy server.py` passes.
