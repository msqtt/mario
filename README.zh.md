# 🍄 mario

**把 AI agent 的手伸进你的服务器。**

零依赖 MCP server，单个 Python 文件。无需安装任何包，`scp` 上传即用，AI agent 远程执行命令、读写文件、管理进程。

> English docs: [README.md](README.md)

---

## 特性

- 📦 **零依赖** — 纯 Python 3.6+ 标准库，上传即运行
- 🌐 **Streamable HTTP 传输** — 实现 MCP 2025-03-26 规范（替代已废弃的 SSE 传输），单一 `/mcp` 端点；默认监听 `localhost:8000`，对外暴露需显式开启
- 🔑 **Bearer 鉴权** — `API_KEY` 常量时间比较；**绑定非 loopback host 时强制要求**
- 🔒 **安全策略** — 命令白/黑名单、路径限制、执行超时
- 🛡 **硬编码安全封锁** — 破坏性命令（`mkfs`/`fdisk`/`shutdown`/`reboot`/`mount`/`kexec`/`crontab` 等）永久禁用，即便被 `sudo`/`bash -c`/`env`/`nohup`/`timeout`/`xargs` 包裹也会被拆穿后拒绝
- 🚧 **Shell 感知审批门** — 写重定向（`>`/`>>`）和管道中的写命令（`ls && cp …`）都会通过 MCP elicitation 向用户发出确认请求
- 🧼 **环境变量净化** — 子进程绝不会看到 `API_KEY` / `*_TOKEN` / `*_SECRET` / `AWS_*` 等
- 🪪 **进程组隔离** — 超时清理时连 `&`/`nohup` 派生的孙子进程一起 SIGKILL
- ✋ **写操作审批门** — `write_file` 及访问 server 工作目录以外路径时，通过 MCP `elicitation/create` 直接向**用户**请求确认（走客户端 UI，绕过 LLM）
- 📋 **审计日志** — 每次工具调用均记录 NDJSON
- 🛠 **5 个工具** — `execute_command` / `read_file` / `write_file` / `list_directory` / `search_files`

---

## 快速部署

```bash
# 1. 把 server.py 上传到服务器
scp server.py user@your-server:~/mario.py

# 2. SSH 进入服务器，启动
ssh user@your-server
API_KEY=your-secret python3 mario.py
```

启动后输出：

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

`cwd` 是 server 的启动目录，同时也是**审批边界** —— agent 访问该目录以外的路径时需要传入 `approve: true`。

---

## 连接方式

mario 使用 **MCP Streamable HTTP** 传输（规范 2025-03-26）。MCP 客户端配置 `type: "http"`（部分客户端写作 `streamable-http`），URL 指向 `/mcp`。

### Kiro / OpenCode / 其他 Streamable HTTP 客户端

在项目目录或 `~/.config/opencode/opencode.json` 中添加：

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

未设置 `API_KEY` 时去掉 `headers` 字段即可。

### Claude Desktop

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）：

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

### 其他 MCP 客户端

HTTP 端点：`http://your-server:8000/mcp`

请求方法：
- `POST /mcp`  — 发送 JSON-RPC 请求；返回 `200 application/json`（通知则返回 `202`）
- `GET /mcp`   — 返回 `405`（本服务不主动推流）
- `DELETE /mcp` — 终止会话

设置 `API_KEY` 后请求需携带：
```
Authorization: Bearer your-secret
```

`initialize` 返回时会带上 `Mcp-Session-Id` 响应头，客户端在后续请求中应当回传同一 session id。

---

## 工具说明

| 工具 | 参数 | 说明 |
|------|------|------|
| `execute_command` | `command`, `cwd?`, `shell?`, `timeout_secs?`, `approve?` | 执行 shell 命令，返回 stdout / stderr / exit_code |
| `read_file` | `path`, `encoding?`, `max_bytes?`, `approve?` | 读取文件内容（支持 base64） |
| `write_file` | `path`, `content`, `encoding?`, `create_dirs?`, `approve?` | 写入文件（**必须传 `approve: true`**） |
| `list_directory` | `path?`, `show_hidden?`, `approve?` | 列出目录内容（无参时列 server 工作目录） |
| `search_files` | `path?`, `name?`, `content?`, `case_sensitive?`, `max_depth?`, `max_results?`, `show_hidden?`, `approve?` | 文件名/内容搜索（find + grep 一次完成） |

需要审批的操作若未通过 elicitation 确认，server 会拒绝并返回 `isError: true`。

`initialize` 响应里的 `instructions` 字段会把上面这张表的要点传给 agent，让它一次就选对工具（比如 `read_file` 优于 `cat`，`search_files` 优于 `find … | xargs grep …`）。

> **Elicitation 支持**：需要审批时，server 通过 MCP `elicitation/create` 向**用户**（而非 LLM）发出确认请求，由客户端 UI 呈现。客户端须在 `initialize` 时声明 `{"capabilities": {"elicitation": {}}}`，否则操作立即被拒绝。stdio 传输也会立即拒绝（不支持通话中双向通信）。

---

## 配置项

通过环境变量控制所有行为：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TRANSPORT` | `http` | 传输模式：`http`（Streamable HTTP，网络）或 `stdio`（本地） |
| `HTTP_HOST` | `localhost` | 监听地址。**非 loopback 值要求设置 `API_KEY`**，否则启动时直接报错退出 |
| `HTTP_PORT` | `8000` | 监听端口 |
| `API_KEY` | _(空，不鉴权)_ | Bearer Token；设置后所有 HTTP 请求必须携带；**非 loopback 时强制必填** |
| `ALLOWED_COMMANDS` | `*` | 命令白名单，逗号分隔；`*` 表示全部允许 |
| `BLOCKED_COMMANDS` | _(空)_ | 命令黑名单，逗号分隔，优先级高于白名单 |
| `ALLOWED_PATHS` | `/` | 文件系统访问路径前缀，逗号分隔 |
| `DEFAULT_CWD` | _(启动目录)_ | 命令默认工作目录 |
| `COMMAND_TIMEOUT_SECS` | `30` | 单条命令最长执行时间（秒） |
| `MAX_OUTPUT_BYTES` | `1048576` | 输出截断阈值（字节，默认 1 MB） |
| `MAX_REQUEST_BYTES` | `1048576` | HTTP POST body 上限（字节） |
| `EXTRA_ENV_PASSTHROUGH` | _(空)_ | 额外透传给子进程的环境变量名（命中 `KEY`/`TOKEN`/`SECRET`/`PASS`/`CRED` 仍会被丢弃） |
| `AUDIT_LOG_FILE` | _(空，输出到 stderr)_ | 审计日志文件路径 |

---

## 安全机制

mario 执行三层独立的安全策略，外加 HTTP 传输层的额外加固。

### 第一层：硬编码封锁（永久，不可配置）

以下命令**无论白名单如何设置，始终拒绝执行**：

- 磁盘格式化：`mkfs` 及变体（`mkfs.ext4`、`mkfs.xfs`……）、`wipefs`、`shred`
- 分区工具：`fdisk`、`parted`、`gdisk`、`sgdisk`、`sfdisk`、`cfdisk`
- 系统电源 / init / kexec：`shutdown`、`reboot`、`poweroff`、`halt`、`kexec`、`init`、`telinit`
- 内核模块：`insmod`、`rmmod`、`modprobe`
- 挂载 / chroot / 命名空间 / swap：`mount`、`umount`、`pivot_root`、`chroot`、`nsenter`、`unshare`、`losetup`、`swapoff`
- LSM 关闭：`setenforce`、`aa-disable`、`apparmor_parser`
- LVM：`lvremove`、`vgremove`、`pvremove`
- 用户/认证：`userdel`、`groupdel`、`passwd`、`chpasswd`、`usermod`、`gpasswd`、`vipw`、`vigr`
- 计划任务：`crontab`、`at`、`batch`

这些封锁是**抗包装的**：`sudo`、`doas`、`pkexec`、`bash -c "…"`、`sh -c "…"`、`env A=1`、`nohup`、`setsid`、`timeout 5 …`、`xargs` 这些前缀会先被拆掉再校验，所以 `sudo bash -c 'shutdown -h now'` 也会被拒绝。

参数模式同样会被拦截（防御性匹配，并非 100% 覆盖）：`rm -rf /`、`rm -rf /*`、`dd of=/dev/…`、fork bomb、`kill -9 -1`、覆盖 `/etc/passwd`、`iptables -F`、`nft flush ruleset`、`history -c`、`truncate -s 0 /var/log/*`、`docker run --privileged`、`git push --force`、`git reset --hard`、`curl … | sh`。

### 第二层：写操作审批门（shell 感知，基于 elicitation）

`write_file` **始终**需要用户确认。对 `server_cwd` 以外路径的读取和目录列举同样需要用户确认。

`execute_command` 在以下情形也触发确认：

- 拆掉 `sudo`/`bash -c`/`xargs`/`env`/`nohup`/`timeout` 等包装后，base 命令是写/修改/删除类（`rm`/`mv`/`cp`/`chmod`/`chown`/`tar`/`wget`/`curl` 等）
- **shell 管道**中的任意一段是写命令，如 `ls && cp a b`
- **shell 写重定向**（`>`/`>>`）写入真实文件，如 `echo evil > /tmp/x` 或 `cmd 2>> /var/log/foo`。重定向到 `/dev/null`/`/dev/stdout`/`/dev/stderr` 或 fd-dup（如 `2>&1`）**不**需要确认

需要审批时，server 使用 MCP **`elicitation/create`** 协议（规范 2025-06-18）直接向**用户**（而非 LLM）请求确认：

1. server 将 HTTP 响应切换为 SSE 流，并向客户端发送 `elicitation/create` 请求。
2. 客户端通过其 UI 向**用户**展示确认提示。
3. 用户同意后，server 注入 `approve=True` 重新执行工具。
4. 用户拒绝或 120 秒超时后，操作以 `isError: true` 被拒绝。

**要求**：客户端须在 `initialize` 时声明 `{"capabilities": {"elicitation": {}}}`，未声明的客户端立即被拒绝。stdio 传输也会立即拒绝（不支持通话中双向通信）。

> **为何用 elicitation 而非 `approve: true`？** 旧机制是告诉 LLM 重新调用并带上 flag，LLM 会自动执行——用户根本没有审查机会。Elicitation 把确认请求直接送到客户端 UI，由用户决定，完全绕开 LLM。

### 第三层：运行时边界纵深防御

- **子进程环境变量净化** — 子进程仅继承 `PATH`/`HOME`/`LANG`/`LC_ALL`/`LC_CTYPE`/`TZ`/`USER`/`LOGNAME`/`SHELL`/`TERM`/`PWD` 以及 `EXTRA_ENV_PASSTHROUGH` 显式声明的变量；`API_KEY` 与匹配 `(KEY|TOKEN|SECRET|PASS|CRED)` 的变量无条件丢弃
- **进程组隔离** — `start_new_session=True` 给每条命令独立进程组；超时后整组 `SIGTERM`+`SIGKILL`，连 `&`/`nohup` 派生的孙子进程都一并清理
- **常量时间鉴权** — `Authorization: Bearer …` 使用 `hmac.compare_digest`，避免时序泄露
- **请求体上限** — POST 体大小受 `MAX_REQUEST_BYTES`（默认 1 MB）约束；`Content-Length: 999999999999` 这种诱骗值会**在读 body 之前**返回 HTTP 413
- **拒绝 chunked TE** — `Transfer-Encoding: chunked` 直接返回 HTTP 400。stdlib 的 HTTP server 不解码分块编码，把未知 TE 当作 0 长度对待会成为反向代理后的请求走私入口
- **方法白名单** — 仅识别 `/mcp` 路径上的 `POST`/`GET`/`DELETE`/`OPTIONS`，其他都返回 `404`
- **会话生命周期** — `initialize` 后服务端签发 `Mcp-Session-Id`，客户端回传时校验内存中的 session 集合（容量上限 256，溢出时 FIFO 淘汰），未知 session 返回 `404`
- **fail-closed 启动** — 若 `HTTP_HOST` 非 loopback（`localhost`/`127.0.0.1`/`::1`）且 `API_KEY` 为空，进程拒绝启动

### 第四层：策略白/黑名单

```bash
# 示例：限制只能读日志和执行少量命令
ALLOWED_COMMANDS=systemctl,journalctl,df,free,ps \
BLOCKED_COMMANDS=rm,dd \
ALLOWED_PATHS=/var/log,/tmp \
API_KEY=$(openssl rand -hex 16) \
HTTP_HOST=0.0.0.0 \
python3 mario.py
```

- **不要以 root 运行**，使用专用低权限用户
- 生产环境建议在 mario 前面放 nginx/caddy，加 HTTPS
- `API_KEY` 通过环境变量传入，不要写入代码或日志

---

## 本地开发

```bash
# 安装开发依赖（仅 pytest + mypy）
python3 -m venv .venv && .venv/bin/pip install pytest mypy

# 运行测试
.venv/bin/pytest

# 类型检查
.venv/bin/mypy server.py

# 本地启动（stdio 模式，方便调试）
TRANSPORT=stdio python3 server.py
```

---

## 协议

MIT
