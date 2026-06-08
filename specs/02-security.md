# Spec 02 — Security

## Goal

Enforce a security policy for every command execution and filesystem operation before it reaches the executor. Provide deterministic allow/deny decisions based on `Config` allowlist, denylist, path restrictions, a hardcoded destructive-command block, and a CWD-based approval gate.

---

## Scope

- Validate shell commands against `allowed_commands`, `blocked_commands`, `HARDCODED_BLOCKED_COMMANDS`, and `DESTRUCTIVE_PATTERNS`.
- Validate file paths against `allowed_paths` (hard block) and `server_cwd` (soft approval gate).
- Require explicit user approval (`approve=True`) for write operations and for any access outside `server_cwd`.
- No I/O, no side effects in pure check functions.

---

## API Contract

```python
class PolicyDenied(Exception):
    """Raised when a command or path is rejected by policy (hard block)."""

def check_command(command: str, config: Config) -> None:
    """Raise PolicyDenied(reason) if the command is not permitted."""

def check_path(path: str, config: Config) -> None:
    """Raise PolicyDenied(reason) if the path is outside allowed_paths."""

def _is_outside_cwd(path: str, server_cwd: str) -> bool:
    """Return True if the resolved path is NOT under server_cwd.
    Returns False when server_cwd is '/' (unrestricted sentinel)."""
```

---

## Config: `server_cwd` field

`Config` gains a new non-configurable field:

```python
server_cwd: str  # os.getcwd() captured at server start; not settable via env
```

- Set to `os.getcwd()` in `load_config()`.
- Acts as the **soft security boundary**: paths outside it require user approval.
- `"/"` is a special sentinel meaning no CWD restriction (used in tests).

---

## Command Check Logic

```
1. Strip the command string.
2. If empty -> raise PolicyDenied("empty command").
3. Extract base_token: first whitespace-delimited token.
4. Derive basename: os.path.basename(base_token).
5. Check HARDCODED_BLOCKED_COMMANDS first (base_token OR basename exact match):
   - If matched -> raise PolicyDenied (cannot be overridden by config).
6. Check DESTRUCTIVE_PATTERNS against the full command string:
   - If any pattern matches -> raise PolicyDenied with the pattern description.
7. Check config.blocked_commands (exact match on base_token OR basename):
   - If matched -> raise PolicyDenied.
8. Check allowlist:
   - If allowed_commands == ['*'] -> allow (return).
   - If base_token or basename matches -> allow (return).
   - Otherwise -> raise PolicyDenied.
```

---

## Hardcoded Blocked Commands

`HARDCODED_BLOCKED_COMMANDS` is a module-level `frozenset[str]` that cannot be changed via config:

```
Filesystem formatting/wiping:
  mkfs, mkfs.ext2, mkfs.ext3, mkfs.ext4, mkfs.xfs, mkfs.btrfs,
  mkfs.fat, mkfs.ntfs, mkfs.vfat, mkfs.f2fs, wipefs

Partition management:
  fdisk, parted, gdisk, sgdisk, sfdisk, cfdisk

Secure delete:
  shred

System power/init:
  shutdown, reboot, poweroff, halt

LVM/storage management:
  lvremove, vgremove, pvremove
```

---

## Destructive Patterns

`DESTRUCTIVE_PATTERNS` is a module-level `List[Tuple[re.Pattern[str], str]]` checked against the **full command string**. These are defense-in-depth (not a cryptographic boundary; creative wrapping may bypass regex). Each entry is `(compiled_pattern, human_description)`:

| Pattern intent | Example match |
|---|---|
| `rm -r` on root `/` | `rm -rf /` |
| `rm -r` on root glob `/*` | `rm -rf /*` |
| `rm -r` on home `~` | `rm -rf ~/` |
| `dd` writing to raw device | `dd if=/dev/zero of=/dev/sda` |
| Fork bomb | `:(){ :|:& };:` |
| `chmod` removing all permissions on `/` | `chmod -R 000 /` |
| Kill all processes | `kill -9 -1` |
| Overwriting critical system files | `> /etc/passwd` |

---

## Path Check Logic (Hard Block)

```
1. Resolve to absolute path: os.path.realpath(path).
2. For each prefix in allowed_paths:
   - If resolved path starts with prefix -> allow (return).
3. If no prefix matched -> raise PolicyDenied.
```

Special case: `allowed_paths == ['/']` allows any absolute path.

---

## CWD-Based Approval Gate (Soft Block)

Tool handlers apply an additional check **after** `check_path` passes:

```
if _is_outside_cwd(resolved_path, config.server_cwd) and not approve:
    return _approval_required_response(reason)
```

`_is_outside_cwd(path, server_cwd)`:
- Returns `False` when `server_cwd == "/"` (no restriction).
- Returns `False` when `realpath(path)` is exactly `server_cwd` or starts with `server_cwd + os.sep`.
- Returns `True` otherwise.

---

## Approval Mechanism

All four tool handlers accept an `approve: boolean` parameter (default `false`).

When approval is required but `approve` is `false`, the handler returns:
```python
{
  "content": [{"type": "text", "text": "⚠️  Approval required: <reason>\n\nTo proceed, re-call with \"approve\": true"}],
  "isError": True
}
```

Audit outcome for these responses: `"approval_required"`.

**Design note:** `approve=true` is a UX friction mechanism — it forces the calling agent to receive a clear "approval required" signal and then explicitly re-issue the call. In human-in-the-loop agent setups (e.g., Claude Desktop, Cursor), both the initial denial and the re-call with `approve=true` are surfaced to the user, creating a natural review checkpoint. This is not a cryptographic access control; a determined automated caller can bypass it by setting `approve=true` on the first attempt.

### Per-tool approval rules

| Tool | Triggers approval |
|---|---|
| `read_file` | path is outside `server_cwd` |
| `write_file` | **always** (write ops always require approval); also if outside `server_cwd` |
| `list_directory` | path is outside `server_cwd` |
| `execute_command` | effective cwd (`cwd` param or `config.default_cwd`) is outside `server_cwd`; **or** the base command is a known write/modify/delete operation (see `WRITE_COMMANDS`) |

`approve=true` satisfies **all** approval requirements for a single call.

---

## Write Commands (`WRITE_COMMANDS`)

`WRITE_COMMANDS` is a module-level `frozenset[str]` of command basenames that modify the filesystem. When `execute_command` is called and the base command matches, `approve=true` is required.

```
File deletion / movement:
  rm, rmdir, mv, unlink

File creation / modification:
  cp, touch, tee, truncate, install, patch

Permission / ownership changes:
  chmod, chown, chgrp

Link creation:
  ln

Archive extraction (writes files):
  tar, unzip, gunzip, bunzip2, unxz

File transfer (writes to local filesystem):
  rsync, scp, wget, curl
```

**Limitations (by design):** Shell redirections (`echo foo > file`, `printf >> file`) and pipelines that write files are not detected because the write is performed by the shell, not by the base command. `shell=True` commands with redirections remain the caller's responsibility. This is documented as a known gap.

---

## Default Path for `list_directory` and `read_file`

When the `path` parameter is **absent or empty**, tool handlers must default to `config.server_cwd`, not to `os.getcwd()` (the Python process CWD). This ensures that "list the current directory" always resolves to the server's working directory, not to an unrelated process CWD (e.g. `/root`).

- `list_directory` with no `path` → lists `config.server_cwd`.
- `read_file` with no `path` → should return an error (path is required); no default applies.

Implementation: in `handle_list_directory`, replace `str(Path(path_str).resolve())` with:
```python
resolved = str(Path(path_str).resolve()) if path_str else config.server_cwd
```

---

## Edge Cases

- Empty command -> `PolicyDenied("empty command")`.
- `/usr/bin/rm` -> basename match: denylist entry `rm` blocks it.
- `rm -rf /` with `allowed_commands=["*"]` -> DESTRUCTIVE_PATTERNS block it.
- `mkfs.ext4 /dev/sda1` -> HARDCODED_BLOCKED_COMMANDS match on basename `mkfs.ext4`.
- Relative paths resolved via `os.path.realpath()` (resolves `..` and symlinks).
- `../../../etc/passwd` -> resolved absolute path falls outside allowed_paths -> PolicyDenied.
- `server_cwd="/"` -> `_is_outside_cwd` always returns `False` (no approval gate active).
- `list_directory` with no `path` → resolves to `server_cwd`, not to the Python process CWD.

---

## Acceptance Criteria

- [ ] `check_command` raises nothing when command is in allowlist and not in any denylist.
- [ ] `check_command` raises `PolicyDenied` when command is in `config.blocked_commands`, even if allowlist is `['*']`.
- [ ] `check_command` raises `PolicyDenied` when command not in allowlist.
- [ ] `check_command` raises `PolicyDenied` for empty command.
- [ ] `check_command` raises `PolicyDenied` for any command in `HARDCODED_BLOCKED_COMMANDS`, even if allowlist is `['*']` and `blocked_commands` is empty.
- [ ] `check_command` raises `PolicyDenied` when command matches any `DESTRUCTIVE_PATTERNS` entry.
- [ ] `check_path` raises nothing for paths under an `allowed_paths` prefix.
- [ ] `check_path` raises `PolicyDenied` for paths outside all `allowed_paths` prefixes.
- [ ] `check_path` correctly blocks `../` traversal attempts.
- [ ] `_is_outside_cwd` returns `False` for paths inside `server_cwd`.
- [ ] `_is_outside_cwd` returns `True` for paths outside `server_cwd`.
- [ ] `_is_outside_cwd` returns `False` when `server_cwd == "/"`.
- [ ] `handle_read_file` returns approval-required when path is outside `server_cwd` and `approve=false`.
- [ ] `handle_read_file` proceeds when path is outside `server_cwd` and `approve=true`.
- [ ] `handle_write_file` always returns approval-required when `approve=false`.
- [ ] `handle_write_file` proceeds when `approve=true`.
- [ ] `handle_list_directory` returns approval-required when path is outside `server_cwd` and `approve=false`.
- [ ] `handle_list_directory` with no `path` param defaults to `server_cwd`, not to Python process CWD.
- [ ] `handle_execute_command` returns approval-required when effective cwd is outside `server_cwd` and `approve=false`.
- [ ] `handle_execute_command` returns approval-required when the base command is in `WRITE_COMMANDS` and `approve=false`.
- [ ] `handle_execute_command` proceeds when base command is in `WRITE_COMMANDS` and `approve=true`.
- [ ] `handle_execute_command` checks effective cwd (uses `config.default_cwd` when no explicit `cwd` param).
- [ ] All check functions are pure (no I/O, deterministic, no mutation of config).
- [ ] `mypy server.py` passes.
