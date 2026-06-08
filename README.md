# 🍄 mario

**Reach your server from any AI agent.**

A zero-dependency MCP server in a single Python file. No packages to install — just copy `server.py` to any server and AI agents can remotely execute commands, read/write files, and manage processes.

> 中文文档：[README.zh.md](README.zh.md)

---

## Features

- 📦 **Zero dependencies** — pure Python 3.6+ stdlib, upload and run instantly
- 🌐 **Streamable HTTP transport** — implements the MCP 2025-03-26 transport (replaces the deprecated SSE transport). Single `/mcp` endpoint over HTTP/1.1; listens on `localhost:8000` by default; opt-in to non-loopback exposure
- 🔑 **Key auth** — `API_KEY` Bearer token; constant-time comparison; **required when binding to a non-loopback host**
- 🔒 **Security policy** — command allow/blocklist, path restrictions, execution timeout
- 🛡 **Hardcoded safety block** — destructive commands (`mkfs`, `fdisk`, `shutdown`, `reboot`, `mount`, `kexec`, `crontab`, …) are permanently blocked, even when wrapped with `sudo`/`bash -c`/`env`/`nohup`/`timeout`/`xargs`
- 🚧 **Shell-aware approval gate** — write redirects (`>`/`>>`) and write commands inside pipelines (`ls && cp …`) all surface a user-confirmation prompt via MCP elicitation
- 🧼 **Env scrubbing** — children never see `API_KEY` / `*_TOKEN` / `*_SECRET` / `AWS_*` / etc.
- 🪪 **Process-group isolation** — timeout cleanly kills grandchildren spawned via `&`/`nohup`
- ✋ **Write approval gate** — `write_file` and out-of-cwd access always ask the **user** for confirmation via MCP `elicitation/create` (routes through the client UI, bypassing the LLM)
- 📋 **Audit log** — every tool call is logged as NDJSON
- 🛠 **5 tools** — `execute_command` / `read_file` / `write_file` / `list_directory` / `search_files`

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
  transport : http
  cwd       : /home/user
  listen    : http://localhost:8000/mcp
  auth      : ENABLED (Bearer)
  timeout   : 30s
  allowlist : *
  blocklist : (none)
  body cap  : 1048576 bytes
```

`cwd` is the server's launch directory and acts as the **approval boundary** — file access outside it requires the agent to pass `approve: true`.

---

## Connecting

mario speaks the **MCP Streamable HTTP** transport (spec 2025-03-26). Configure your MCP client with `type: "http"` (sometimes labelled `streamable-http`) and point it at `/mcp`.

### Kiro / OpenCode / generic Streamable HTTP client

Add to your project `opencode.json` or `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mario": {
      "type": "http",
      "url": "http://your-server:8000/mcp",
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
      "type": "http",
      "url": "http://your-server:8000/mcp",
      "headers": {
        "Authorization": "Bearer your-secret"
      }
    }
  }
}
```

### Any MCP client

HTTP endpoint: `http://your-server:8000/mcp`

Methods:
- `POST /mcp`  — send a JSON-RPC request; returns `200 application/json` (or `202` for notifications)
- `GET /mcp`   — returns `405` (no server-initiated streams)
- `DELETE /mcp` — terminate session

Required header when `API_KEY` is set:
```
Authorization: Bearer your-secret
```

After `initialize`, the server returns an `Mcp-Session-Id` response header which the client SHOULD echo on subsequent requests.

---

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `execute_command` | `command`, `cwd?`, `shell?`, `timeout_secs?`, `approve?` | Run a shell command, returns stdout / stderr / exit_code |
| `read_file` | `path`, `encoding?`, `max_bytes?`, `approve?` | Read file content (supports base64) |
| `write_file` | `path`, `content`, `encoding?`, `create_dirs?`, `approve?` | Write content to a file (**always requires `approve: true`**) |
| `list_directory` | `path?`, `show_hidden?`, `approve?` | List directory entries (defaults to server cwd) |
| `search_files` | `path?`, `name?`, `content?`, `case_sensitive?`, `max_depth?`, `max_results?`, `show_hidden?`, `approve?` | Find files by name/content (find+grep in one call) |

`approve: true` is required whenever an operation needs explicit user confirmation (see [Security](#security) below).

The `initialize` response carries an `instructions` payload that summarises this table for the agent so it picks the right tool on the first call (e.g. `read_file` over `execute_command("cat …")`, `search_files` over `find … | xargs grep …`).

> **Elicitation support**: when an operation requires approval (write, out-of-cwd access), the server sends an MCP `elicitation/create` request so the **user** confirms via the client UI directly — the LLM never auto-approves. Clients must declare `{"capabilities": {"elicitation": {}}}` during `initialize`; clients without this capability are denied immediately. The stdio transport also denies immediately (bidirectional mid-call messaging is not supported on stdio).

---

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRANSPORT` | `http` | Transport mode: `http` (Streamable HTTP, network) or `stdio` (local) |
| `HTTP_HOST` | `localhost` | Bind address. **Non-loopback values require `API_KEY`** (server refuses to start otherwise) |
| `HTTP_PORT` | `8000` | Bind port |
| `API_KEY` | _(empty — no auth)_ | Bearer token; required on all HTTP requests when set; **mandatory when HTTP_HOST is non-loopback** |
| `ALLOWED_COMMANDS` | `*` | Command allowlist, comma-separated; `*` = all allowed |
| `BLOCKED_COMMANDS` | _(empty)_ | Command blocklist, comma-separated; always enforced |
| `ALLOWED_PATHS` | `/` | Filesystem path prefixes accessible to file tools |
| `DEFAULT_CWD` | _(launch directory)_ | Default working directory for command execution |
| `COMMAND_TIMEOUT_SECS` | `30` | Max execution time per command (seconds) |
| `MAX_OUTPUT_BYTES` | `1048576` | Output truncation threshold (bytes, default 1 MB) |
| `MAX_REQUEST_BYTES` | `1048576` | POST body cap on the HTTP transport (bytes) |
| `EXTRA_ENV_PASSTHROUGH` | _(empty)_ | Additional env names to forward to children (`KEY`/`TOKEN`/`SECRET`/`PASS`/`CRED` names are still dropped) |
| `AUDIT_LOG_FILE` | _(empty — stderr)_ | Audit log file path |

---

## Security

Mario enforces three independent security layers, plus transport-level hardening on the HTTP endpoint.

### 1. Hardcoded block (permanent, not configurable)

The following commands are **always refused**, regardless of `ALLOWED_COMMANDS`:

- Disk formatting: `mkfs` and variants (`mkfs.ext4`, `mkfs.xfs`, …), `wipefs`, `shred`
- Partition tools: `fdisk`, `parted`, `gdisk`, `sgdisk`, `sfdisk`, `cfdisk`
- Power / init / kernel-swap: `shutdown`, `reboot`, `poweroff`, `halt`, `kexec`, `init`, `telinit`
- Kernel modules: `insmod`, `rmmod`, `modprobe`
- Mount / chroot / namespace / swap: `mount`, `umount`, `pivot_root`, `chroot`, `nsenter`, `unshare`, `losetup`, `swapoff`
- LSM disable: `setenforce`, `aa-disable`, `apparmor_parser`
- LVM: `lvremove`, `vgremove`, `pvremove`
- User / authentication: `userdel`, `groupdel`, `passwd`, `chpasswd`, `usermod`, `gpasswd`, `vipw`, `vigr`
- Cron / scheduled tasks: `crontab`, `at`, `batch`

These blocks are **bypass-resistant** — wrappers like `sudo`, `doas`, `pkexec`, `bash -c "…"`, `sh -c "…"`, `env A=1`, `nohup`, `setsid`, `timeout 5 …`, `xargs` are unwrapped before the inner command is checked, so `sudo bash -c 'shutdown -h now'` is rejected just like plain `shutdown`.

Dangerous **argument patterns** are also blocked (defense-in-depth, not bypass-proof):
`rm -rf /`, `rm -rf /*`, `dd of=/dev/…`, fork bombs, `kill -9 -1`, overwriting `/etc/passwd`, `iptables -F`, `nft flush ruleset`, `history -c`, `truncate -s 0 /var/log/*`, `docker run --privileged`, `git push --force`, `git reset --hard`, `curl … | sh`.

### 2. Write approval gate (shell-aware, elicitation-based)

`write_file` **always** requires user confirmation. File reads and directory listings outside `server_cwd` also require user confirmation.

`execute_command` triggers confirmation when **any** of these is true:

- The base command (after unwrapping `sudo`, `bash -c`, `xargs`, `env`, `nohup`, `timeout`, …) is a known write/modify/delete operation: `rm`, `mv`, `cp`, `chmod`, `chown`, `tar`, `wget`, `curl`, etc.
- **Shell pipelines** (`shell=true`) where any segment matches a write command, e.g. `ls && cp a b`.
- **Shell redirects** (`shell=true`) that write to a real file, e.g. `echo evil > /tmp/x` or `cmd 2>> /var/log/foo`. Redirects to `/dev/null`, `/dev/stdout`, `/dev/stderr`, or fd-dup like `2>&1` do **not** require approval.

When approval is needed, the server uses the MCP **`elicitation/create`** protocol (spec 2025-06-18) to ask the **user** — not the LLM — for confirmation:

1. The server switches the HTTP response to SSE streaming and sends an `elicitation/create` request to the client.
2. The client presents a yes/no prompt to the **user** via its own UI.
3. If the user accepts, the server re-runs the tool with `approve=True` injected.
4. If the user declines or the 120-second timeout expires, the operation is denied with `isError: true`.

**Requirements:** the client must declare `{"capabilities": {"elicitation": {}}}` during `initialize`. Clients that do not declare this capability are denied immediately. The stdio transport also denies immediately (no bidirectional mid-call messaging).

> **Why elicitation instead of `approve: true`?** The previous `approve: true` approach told the LLM to re-call with the flag, which the LLM would do automatically — no human ever reviewed it. Elicitation routes the confirmation through the client UI directly to the user, bypassing the LLM entirely.

### 3. Defense-in-depth at the runtime boundary

- **Subprocess env scrubbing** — children inherit only `PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `PWD` plus anything explicitly listed in `EXTRA_ENV_PASSTHROUGH`. `API_KEY` and any name matching `(KEY|TOKEN|SECRET|PASS|CRED)` are unconditionally dropped, even if listed in passthrough.
- **Process-group isolation** — the server starts each command in its own POSIX process group (`start_new_session=True`). On timeout, the **whole group is SIGKILL'd**, so grandchildren spawned via `&` / `nohup` are reaped instead of becoming orphans.
- **Constant-time auth** — `Authorization: Bearer …` is compared with `hmac.compare_digest` to avoid timing leaks.
- **Request-size cap** — POST bodies on the HTTP transport are bounded by `MAX_REQUEST_BYTES` (default 1 MB); a hostile `Content-Length: 999999999999` is rejected with HTTP 413 *before* any bytes are read.
- **Chunked TE rejected** — `Transfer-Encoding: chunked` is refused with HTTP 400. The stdlib HTTP server doesn't decode chunked bodies, and silently treating an unsupported TE as 0-length would be a request-smuggling foothold behind a future reverse proxy.
- **Method allowlist** — only `POST`, `GET`, `DELETE`, `OPTIONS` on `/mcp` are recognised; other paths and methods return `404`.
- **Session lifecycle** — after `initialize`, the server issues an `Mcp-Session-Id`. When a client echoes it back, the server validates it against an in-memory set (capped at 256, oldest-evicted FIFO). Unknown session IDs return `404`.
- **Fail-closed startup** — if `HTTP_HOST` is not loopback (`localhost`/`127.0.0.1`/`::1`) and `API_KEY` is empty, the server refuses to start.

### 4. Policy-based allow/deny

```bash
# Example: lock down to specific commands and paths
ALLOWED_COMMANDS=systemctl,journalctl,df,free,ps \
BLOCKED_COMMANDS=rm,dd \
ALLOWED_PATHS=/var/log,/tmp \
API_KEY=$(openssl rand -hex 16) \
HTTP_HOST=0.0.0.0 \
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
