# Spec 04 — Audit

## Goal

Record a structured, append-only audit log entry for every tool invocation using Python stdlib only.

---

## Scope

- Write one JSON log line per tool call (NDJSON format).
- Log destination: a file path from config, or stderr if not configured.
- Thread-safe writes using `threading.Lock`.
- No log rotation (v1).

---

## API Contract

```python
import threading
from typing import Any, IO

class AuditLogger:
    def __init__(self, dest: IO[str]) -> None: ...
    def log(self, entry: Dict[str, Any]) -> None: ...
    def close(self) -> None: ...

def create_audit_logger(config: Config) -> AuditLogger:
    """Return an AuditLogger writing to config.audit_log_file or sys.stderr."""
```

`log()` entry shape:

```python
{
    "timestamp": "2026-06-05T05:33:20.188Z",  # datetime.utcnow().isoformat() + 'Z'
    "tool": "execute_command",
    "input": { ... },       # sanitized copy of tool input params
    "outcome": "success",   # 'success' | 'denied' | 'error' | 'timeout'
    "exit_code": 0,         # optional
    "duration_secs": 0.042, # optional
    "error": "...",         # optional, present when outcome is 'denied' or 'error'
}
```

---

## Input Sanitization

Keys matching `re.search(r'pass|secret|key|token|credential', key, re.IGNORECASE)` have their value replaced with `"[REDACTED]"`.

---

## Edge Cases

- File write fails -> log error to `sys.stderr`, do NOT raise.
- Concurrent `log()` calls must not interleave lines (use `threading.Lock`).
- Values not serialisable by `json.dumps` -> replace with `"[non-serializable]"`.
- `close()` flushes the underlying file handle.

---

## Acceptance Criteria

- [ ] `log()` writes a valid NDJSON line to the configured destination.
- [ ] Each line contains `timestamp`, `tool`, `input`, `outcome`.
- [ ] Sensitive key names are replaced with `"[REDACTED]"`.
- [ ] Two concurrent `log()` calls produce two separate, non-interleaved lines.
- [ ] A write failure does not raise.
- [ ] `close()` flushes pending writes.
- [ ] When `audit_log_file` is `None`, output goes to stderr.
- [ ] `mypy server.py` passes.
