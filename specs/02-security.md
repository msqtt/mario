# Spec 02 — Security

## Goal

Enforce a security policy for every command execution and filesystem operation before it reaches the executor. Provide deterministic allow/deny decisions based on `Config` allowlist, denylist, and path restrictions.

---

## Scope

- Validate shell commands against `allowed_commands` and `blocked_commands`.
- Validate file paths against `allowed_paths`.
- No I/O, no side effects — pure functions only.

---

## API Contract

```python
class PolicyDenied(Exception):
    """Raised when a command or path is rejected by policy."""

def check_command(command: str, config: Config) -> None:
    """Raise PolicyDenied(reason) if the command is not permitted."""

def check_path(path: str, config: Config) -> None:
    """Raise PolicyDenied(reason) if the path is outside allowed_paths."""
```

Callers use try/except; denial is always an exception, never a boolean return.

---

## Command Check Logic

```
1. Strip the command string.
2. If empty -> raise PolicyDenied("empty command").
3. Extract base token: first whitespace-delimited token (may be an absolute path like /usr/bin/ls).
4. Derive basename: os.path.basename(base_token).
5. Check denylist first (exact match on base_token OR basename):
   - If either matches any entry in blocked_commands -> raise PolicyDenied.
6. Check allowlist:
   - If allowed_commands == ['*'] -> allow (return).
   - If base_token or basename matches any entry in allowed_commands -> allow (return).
   - Otherwise -> raise PolicyDenied.
```

---

## Path Check Logic

```
1. Resolve to absolute path: os.path.realpath(path).
2. For each prefix in allowed_paths:
   - If resolved path starts with prefix -> allow (return).
3. If no prefix matched -> raise PolicyDenied.
```

Special case: `allowed_paths == ['/']` allows any absolute path.

---

## Edge Cases

- Empty command -> `PolicyDenied("empty command")`.
- `/usr/bin/rm` -> checked against both `/usr/bin/rm` and `rm`; denylist entry `rm` blocks it.
- Relative paths resolved via `os.path.realpath()` (resolves `..` and symlinks).
- `../../../etc/passwd` -> resolved absolute path falls outside allowed_paths -> denied.
- Denylist entry `rm` does NOT block `rmdir` (exact match only).

---

## Acceptance Criteria

- [ ] `check_command` raises nothing when command is in allowlist and not in denylist.
- [ ] `check_command` raises `PolicyDenied` when command is in denylist, even if allowlist is `['*']`.
- [ ] `check_command` raises `PolicyDenied` when command not in allowlist and allowlist is not `['*']`.
- [ ] `check_command` raises `PolicyDenied` for empty command.
- [ ] `check_path` raises nothing for paths under an `allowed_paths` prefix.
- [ ] `check_path` raises `PolicyDenied` for paths outside all `allowed_paths` prefixes.
- [ ] `check_path` correctly blocks `../` traversal attempts.
- [ ] Both functions are pure (no I/O, deterministic, no mutation of config).
- [ ] `mypy server.py` passes.
