# 🍄 mario

**Reach your server from any AI agent.**

A zero-dependency MCP server in a single Python file. No packages to install — just copy `server.py` to any server and AI agents can remotely execute commands, read/write files, and manage processes.

> 中文文档：[README.zh.md](README.zh.md)

---

## Features

- 📦 **Zero dependencies** — pure Python 3.6+ stdlib, upload and run instantly
- 🌐 **SSE transport** — listens on `0.0.0.0:8000` by default, agents connect over the network
- 🔑 **Key auth** — set `API_KEY` to require a Bearer token on every connection
- 🔒 **Security policy** — command allow/blocklist, path restrictions, execution timeout
- 🛡 **Hardcoded safety block** — destructive commands (`mkfs`, `fdisk`, `shutdown`, `reboot`, etc.) are permanently blocked regardless of config
- ✋ **Write approval gate** — `write_file` always requires explicit `approve: true`; file access outside the server's working directory also requires approval
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
  cwd       : /home/user
  listen    : http://0.0.0.0:8000/sse
  timeout   : 30s
  allowlist : *
  blocklist : (none)
```

`cwd` is the server's launch directory and acts as the **approval boundary** — file access outside it requires the agent to pass `approve: true`.

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
| `execute_command` | `command`, `cwd?`, `shell?`, `timeout_secs?`, `approve?` | Run a shell command, returns stdout / stderr / exit_code |
| `read_file` | `path`, `encoding?`, `max_bytes?`, `approve?` | Read file content (supports base64) |
| `write_file` | `path`, `content`, `encoding?`, `create_dirs?`, `approve?` | Write content to a file (**always requires `approve: true`**) |
| `list_directory` | `path`, `show_hidden?`, `approve?` | List directory entries |

`approve: true` is required whenever an operation needs explicit user confirmation (see [Security](#security) below).

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
| `DEFAULT_CWD` | _(launch directory)_ | Default working directory for command execution |
| `COMMAND_TIMEOUT_SECS` | `30` | Max execution time per command (seconds) |
| `MAX_OUTPUT_BYTES` | `1048576` | Output truncation threshold (bytes, default 1 MB) |
| `AUDIT_LOG_FILE` | _(empty — stderr)_ | Audit log file path |

---

## Security

Mario enforces three independent security layers:

### 1. Hardcoded block (permanent, not configurable)

The following commands are **always refused**, regardless of `ALLOWED_COMMANDS`:

- Disk formatting: `mkfs` and variants (`mkfs.ext4`, `mkfs.xfs`, …), `wipefs`, `shred`
- Partition tools: `fdisk`, `parted`, `gdisk`, `sgdisk`, `sfdisk`, `cfdisk`
- System power: `shutdown`, `reboot`, `poweroff`, `halt`
- LVM management: `lvremove`, `vgremove`, `pvremove`

Dangerous argument patterns are also blocked regardless of command source:
`rm -rf /`, `rm -rf /*`, `dd of=/dev/…`, fork bombs, `kill -9 -1`, overwriting `/etc/passwd`, etc.

### 2. Write approval gate

`write_file` **always** returns an approval-required error unless the caller passes `"approve": true`. File reads and directory listings outside `server_cwd` also require `approve: true`.

`execute_command` also requires `approve: true` when the base command is a known write/modify/delete operation: `rm`, `mv`, `cp`, `chmod`, `chown`, `tar`, `rsync`, `wget`, `curl`, etc. Shell redirections (`echo > file`) are a known gap — they are not detected by basename checking.

When approval is needed, the server responds with:
```
⚠️  Approval required: <reason>

To proceed, re-call this tool with "approve": true
```

> **Note:** `approve: true` is a UX friction mechanism. It surfaces a review checkpoint in human-in-the-loop agent setups (e.g. Claude Desktop shows the re-call to the user). It does not provide cryptographic enforcement.

### 3. Policy-based allow/deny

```bash
# Example: lock down to specific commands and paths
ALLOWED_COMMANDS=systemctl,journalctl,df,free,ps \
BLOCKED_COMMANDS=rm,dd \
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
