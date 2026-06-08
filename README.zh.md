# 🍄 mario

**把 AI agent 的手伸进你的服务器。**

零依赖 MCP server，单个 Python 文件。无需安装任何包，`scp` 上传即用，AI agent 远程执行命令、读写文件、管理进程。

> English docs: [README.md](README.md)

---

## 特性

- 📦 **零依赖** — 纯 Python 3.6+ 标准库，上传即运行
- 🌐 **SSE 网络传输** — 默认监听 `0.0.0.0:8000`，agent 远程连接
- 🔑 **Key 认证** — 通过 `API_KEY` 环境变量启用，防止未授权访问
- 🔒 **安全策略** — 命令白/黑名单、路径限制、执行超时
- 🛡 **硬编码安全封锁** — 破坏性命令（`mkfs`、`fdisk`、`shutdown`、`reboot` 等）永久禁用，不受配置影响
- ✋ **写操作审批门** — `write_file` 必须携带 `approve: true` 才能执行；访问 server 工作目录以外的文件也需要审批
- 📋 **审计日志** — 每次工具调用均记录 NDJSON 日志
- 🛠 **4 个工具** — `execute_command` / `read_file` / `write_file` / `list_directory`

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
  transport : sse
  cwd       : /home/user
  listen    : http://0.0.0.0:8000/sse
  timeout   : 30s
  allowlist : *
  blocklist : (none)
```

`cwd` 是 server 的启动目录，同时也是**审批边界** —— agent 访问该目录以外的路径时需要传入 `approve: true`。

---

## 连接方式

### OpenCode

在项目目录或 `~/.config/opencode/opencode.json` 中添加：

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

未设置 `API_KEY` 时去掉 `headers` 字段即可。

### Claude Desktop

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）：

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

### 其他 MCP 客户端

SSE 接入地址：`http://your-server:8000/sse`

设置了 `API_KEY` 时，请求头需携带：
```
Authorization: Bearer your-secret
```

---

## 工具说明

| 工具 | 参数 | 说明 |
|------|------|------|
| `execute_command` | `command`, `cwd?`, `shell?`, `timeout_secs?`, `approve?` | 执行 shell 命令，返回 stdout / stderr / exit_code |
| `read_file` | `path`, `encoding?`, `max_bytes?`, `approve?` | 读取文件内容（支持 base64）|
| `write_file` | `path`, `content`, `encoding?`, `create_dirs?`, `approve?` | 写入文件（**必须传 `approve: true`**）|
| `list_directory` | `path`, `show_hidden?`, `approve?` | 列出目录内容 |

需要审批的操作若未携带 `approve: true`，server 会返回如下提示，agent 须重新调用：

```
⚠️  Approval required: <reason>

To proceed, re-call this tool with "approve": true
```

---

## 配置项

通过环境变量控制所有行为：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TRANSPORT` | `sse` | 传输模式：`sse`（网络）或 `stdio`（本地） |
| `SSE_HOST` | `0.0.0.0` | 监听地址 |
| `SSE_PORT` | `8000` | 监听端口 |
| `API_KEY` | _(空，不鉴权)_ | Bearer Token，设置后所有连接必须携带 |
| `ALLOWED_COMMANDS` | `*` | 命令白名单，逗号分隔；`*` 表示全部允许 |
| `BLOCKED_COMMANDS` | _(空)_ | 命令黑名单，逗号分隔，优先级高于白名单 |
| `ALLOWED_PATHS` | `/` | 文件系统访问路径前缀，逗号分隔 |
| `DEFAULT_CWD` | `$HOME` | 命令默认工作目录 |
| `COMMAND_TIMEOUT_SECS` | `30` | 单条命令最长执行时间（秒） |
| `MAX_OUTPUT_BYTES` | `1048576` | 输出截断阈值（字节，默认 1MB） |
| `AUDIT_LOG_FILE` | _(空，输出到 stderr)_ | 审计日志文件路径 |

---

## 安全机制

mario 执行三层独立的安全策略：

### 第一层：硬编码封锁（永久，不可配置）

以下命令**无论白名单如何设置，始终拒绝执行**：

- 磁盘格式化：`mkfs` 及变体（`mkfs.ext4`、`mkfs.xfs`……）、`wipefs`、`shred`
- 分区工具：`fdisk`、`parted`、`gdisk`、`sgdisk`、`sfdisk`、`cfdisk`
- 系统电源：`shutdown`、`reboot`、`poweroff`、`halt`
- LVM 管理：`lvremove`、`vgremove`、`pvremove`

危险参数组合也会被模式匹配拦截：`rm -rf /`、`rm -rf /*`、`dd of=/dev/…`、fork bomb、`kill -9 -1`、覆盖 `/etc/passwd` 等。

### 第二层：写操作审批门

`write_file` **始终**需要 `"approve": true` 才能执行。
对 `server_cwd`（server 启动时的工作目录）以外路径的读取和目录列举同样需要 `approve: true`。

`execute_command` 中使用 `rm`、`mv`、`cp`、`chmod`、`chown`、`tar`、`rsync`、`wget`、`curl` 等写操作命令时同样需要 `approve: true`。已知局限：shell 重定向（`echo > file`）无法通过命令名检测，不在此保护范围内。

> **说明：** `approve: true` 是 UX 摩擦机制，而非密码学强制访问控制。在 human-in-the-loop 的 agent 环境（如 Claude Desktop）中，用户可以在 agent 重新调用前审查并决定是否放行。

### 第三层：策略白/黑名单

```bash
# 示例：限制只能读日志和执行少量命令
ALLOWED_COMMANDS=systemctl,journalctl,df,free,ps \
BLOCKED_COMMANDS=rm,dd \
ALLOWED_PATHS=/var/log,/tmp \
API_KEY=$(openssl rand -hex 16) \
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
