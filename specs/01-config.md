# Spec 01 — Config

## Goal

Load, validate, and expose all server configuration from environment variables at startup. Provide a single typed `Config` dataclass consumed by all other sections of `server.py`. Fail fast with a clear error message if required values are invalid.

---

## Scope

- Read environment variables via `os.environ`.
- Validate types and constraints (e.g., positive integers, recognised strings).
- Return a frozen `Config` dataclass instance.
- No dynamic reloading — config is read once at process start.
- **No third-party libraries** (no `python-dotenv`).

---

## API Contract

```python
from dataclasses import dataclass
from typing import Optional

class ConfigError(Exception):
    """Raised when any configuration value is invalid."""

@dataclass(frozen=True)
class Config:
    allowed_commands: list[str]   # ['*'] means unrestricted
    blocked_commands: list[str]
    allowed_paths: list[str]      # path prefixes; ['/'] means unrestricted
    default_cwd: str
    command_timeout_secs: int     # must be > 0
    max_output_bytes: int         # must be > 0
    audit_log_file: Optional[str] # None -> write to stderr

def load_config() -> Config:
    """Load and validate config from environment variables.
    Raises ConfigError with a descriptive message on invalid input."""
```

---

## Environment Variables

| Env Var | Type | Default | Constraints |
|---------|------|---------|-------------|
| `ALLOWED_COMMANDS` | str | `*` | Comma-separated; `*` means all |
| `BLOCKED_COMMANDS` | str | (empty) | Comma-separated |
| `ALLOWED_PATHS` | str | `/` | Comma-separated absolute paths |
| `DEFAULT_CWD` | str | `$HOME` or `/tmp` if HOME unset | Must be non-empty |
| `COMMAND_TIMEOUT_SECS` | int | `30` | Must be 1–3600 |
| `MAX_OUTPUT_BYTES` | int | `1048576` | Must be 1–104857600 (100 MB) |
| `AUDIT_LOG_FILE` | str | (empty -> None) | Must be writable path if set |

---

## Parsing Rules

- Comma-separated values: split on `,`, strip whitespace, filter empty strings.
- `ALLOWED_COMMANDS=` (empty string after stripping) -> treat as `['*']`.
- Integer fields: parse with `int()`; raise `ConfigError` if not a valid integer or out of range.
- `DEFAULT_CWD` falls back to `os.environ.get('HOME', '/tmp')` if not set.

---

## Edge Cases

- `ALLOWED_COMMANDS=` (empty string) -> `['*']`.
- `COMMAND_TIMEOUT_SECS=0` -> `ConfigError`.
- `COMMAND_TIMEOUT_SECS=abc` -> `ConfigError`.
- Unknown env vars are silently ignored.
- `BLOCKED_COMMANDS` take priority over `ALLOWED_COMMANDS`; enforcement is in Section 2 (Security), not here.

---

## Acceptance Criteria

- [ ] `load_config()` returns a valid `Config` when all env vars are valid or absent (defaults apply).
- [ ] `load_config()` raises `ConfigError` with a descriptive message for each invalid value (separate test per field).
- [ ] `ALLOWED_COMMANDS=''` results in `allowed_commands == ['*']`.
- [ ] Returned `Config` is a frozen dataclass (assignment raises `FrozenInstanceError`).
- [ ] No env vars are read outside of `load_config()`.
- [ ] `mypy server.py` passes.
