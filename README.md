# 🍄 mario

**Reach your server from any AI agent.**

A zero-dependency MCP server in a single Python file. No packages to install — just copy `server.py` to any server and AI agents can remotely execute commands, read/write files, and manage processes.

> 中文文档：[README.zh.md](README.zh.md)

---

## Features

- 📦 **Zero dependencies** — pure Python 3.11+ stdlib, upload and run instantly
- 🌐 **SSE transport** — listens on `0.0.0.0:8000` by default, agents connect over the network
- 🔑 **Key auth** — set `API_KEY` to require a Bearer token on every connection
- 🔒 **Security policy** — command allow/blocklist, path restrictions, execution timeout
- 📋 **Audit log** — every tool call is logged as NDJSON
- 🛠 **4 tools** — `execute_command` / `read_file` / `write_file` / `list_directory`

---

## Quick Start

```bash
# 1. Upload server.py to your server
scp server.py user@your-server:~/mario.py

# 2. SSH in and start
ssh user@your-server
API_KEY=your-secret python3 mario.py
```

Output on startup:

```
mario starting
  transport : sse
  listen    : http://0.0.0.0:8000/sse
  cwd       : /home/user
  timeout   : 30s
  allowlist : *
  blocklist : (none)
```

---

## Connecting

### OpenCode

Add to your project `opencode.json` or `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mario": {
      "type": "remote",
      "url": "http://your-server:8000/sse",
      "headers": {
        "Authorization": "Bearer your-secret"
      }
    }
  }
}
```

Remove the `headers` field if you did not set `API_KEY`.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "mario": {
      "url": "http://your-server:8000/sse",
      "headers": {
        "Authorization": "Bearer your-secret"
      }
    }
  }
}
```

### Any MCP client

SSE endpoint: `http://your-server:8000/sse`

Required header when `API_KEY` is set:
```
Authorization: Bearer your-secret
```

---

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `execute_command` | `command`, `cwd?`, `shell?`, `timeout_secs?` | Run a shell command, returns stdout / stderr / exit_code |
| `read_file` | `path`, `encoding?`, `max_bytes?` | Read file content (supports base64) |
| `write_file` | `path`, `content`, `encoding?`, `create_dirs?` | Write content to a file |
| `list_directory` | `path`, `show_hidden?` | List directory entries |

---

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRANSPORT` | `sse` | Transport mode: `sse` (network) or `stdio` (local) |
| `SSE_HOST` | `0.0.0.0` | Bind address |
| `SSE_PORT` | `8000` | Bind port |
| `API_KEY` | _(empty — no auth)_ | Bearer token; required on all connections when set |
| `ALLOWED_COMMANDS` | `*` | Command allowlist, comma-separated; `*` = all allowed |
| `BLOCKED_COMMANDS` | _(empty)_ | Command blocklist, comma-separated; always enforced |
| `ALLOWED_PATHS` | `/` | Filesystem path prefixes accessible to file tools |
| `DEFAULT_CWD` | `$HOME` | Default working directory for command execution |
| `COMMAND_TIMEOUT_SECS` | `30` | Max execution time per command (seconds) |
| `MAX_OUTPUT_BYTES` | `1048576` | Output truncation threshold (bytes, default 1 MB) |
| `AUDIT_LOG_FILE` | _(empty — stderr)_ | Audit log file path |

---

## Security

```bash
# Example: lock down to a specific set of commands and paths
ALLOWED_COMMANDS=systemctl,journalctl,df,free,ps \
BLOCKED_COMMANDS=rm,dd,mkfs \
ALLOWED_PATHS=/var/log,/tmp \
API_KEY=$(openssl rand -hex 16) \
python3 mario.py
```

- **Do not run as root** — use a dedicated low-privilege user
- In production, put mario behind nginx/caddy with TLS
- Pass `API_KEY` via environment variable, never hardcode it

---

## Development

```bash
# Install dev dependencies (pytest + mypy only)
python3 -m venv .venv && .venv/bin/pip install pytest mypy

# Run tests
.venv/bin/pytest

# Type check
.venv/bin/mypy server.py

# Run locally in stdio mode (useful for debugging)
TRANSPORT=stdio python3 server.py
```

---

## License

MIT
