"""Tests for mario (server.py).

Import style: from server import <symbol>
All tests use monkeypatch to isolate environment variables.
"""

from __future__ import annotations

import base64
import io
import json
import os
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Section 1 — Config
# ---------------------------------------------------------------------------

from server import Config, ConfigError, load_config


class TestConfig:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """All env vars absent → valid Config with defaults."""
        for key in [
            "ALLOWED_COMMANDS", "BLOCKED_COMMANDS", "ALLOWED_PATHS",
            "DEFAULT_CWD", "COMMAND_TIMEOUT_SECS", "MAX_OUTPUT_BYTES",
            "AUDIT_LOG_FILE", "TRANSPORT", "SSE_PORT", "SSE_HOST",
        ]:
            monkeypatch.delenv(key, raising=False)
        cfg = load_config()
        assert cfg.allowed_commands == ["*"]
        assert cfg.blocked_commands == []
        assert cfg.allowed_paths == ["/"]
        assert cfg.command_timeout_secs == 30
        assert cfg.max_output_bytes == 1048576
        assert cfg.audit_log_file is None
        # server_cwd is set to os.getcwd() at startup
        assert isinstance(cfg.server_cwd, str)
        assert len(cfg.server_cwd) > 0

    def test_allowed_commands_star(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ALLOWED_COMMANDS", "*")
        assert load_config().allowed_commands == ["*"]

    def test_allowed_commands_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ALLOWED_COMMANDS", "ls, df, ps")
        assert load_config().allowed_commands == ["ls", "df", "ps"]

    def test_allowed_commands_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ALLOWED_COMMANDS", "")
        assert load_config().allowed_commands == ["*"]

    def test_blocked_commands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLOCKED_COMMANDS", "rm, dd")
        assert load_config().blocked_commands == ["rm", "dd"]

    def test_allowed_paths(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ALLOWED_PATHS", "/var/log,/tmp")
        assert load_config().allowed_paths == ["/var/log", "/tmp"]

    def test_default_cwd_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DEFAULT_CWD", "/srv")
        assert load_config().default_cwd == "/srv"

    def test_timeout_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMAND_TIMEOUT_SECS", "60")
        assert load_config().command_timeout_secs == 60

    def test_timeout_zero_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMAND_TIMEOUT_SECS", "0")
        with pytest.raises(ConfigError):
            load_config()

    def test_timeout_negative_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMAND_TIMEOUT_SECS", "-1")
        with pytest.raises(ConfigError):
            load_config()

    def test_timeout_non_integer_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMAND_TIMEOUT_SECS", "abc")
        with pytest.raises(ConfigError):
            load_config()

    def test_timeout_too_large_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMMAND_TIMEOUT_SECS", "3601")
        with pytest.raises(ConfigError):
            load_config()

    def test_max_output_bytes_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_OUTPUT_BYTES", "512")
        assert load_config().max_output_bytes == 512

    def test_max_output_bytes_zero_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_OUTPUT_BYTES", "0")
        with pytest.raises(ConfigError):
            load_config()

    def test_frozen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["ALLOWED_COMMANDS", "BLOCKED_COMMANDS", "ALLOWED_PATHS",
                    "DEFAULT_CWD", "COMMAND_TIMEOUT_SECS", "MAX_OUTPUT_BYTES",
                    "AUDIT_LOG_FILE"]:
            monkeypatch.delenv(key, raising=False)
        cfg = load_config()
        with pytest.raises((AttributeError, TypeError)):
            cfg.allowed_commands = []  # type: ignore[misc]

    def test_audit_log_file_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_LOG_FILE", "")
        assert load_config().audit_log_file is None

    def test_audit_log_file_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_LOG_FILE", "/tmp/audit.log")
        assert load_config().audit_log_file == "/tmp/audit.log"


# ---------------------------------------------------------------------------
# Section 2 — Security
# ---------------------------------------------------------------------------

from server import PolicyDenied, check_command, check_path
from server import HARDCODED_BLOCKED_COMMANDS, DESTRUCTIVE_PATTERNS, WRITE_COMMANDS, _is_outside_cwd


def _cfg(**kwargs: Any) -> Config:
    """Build a minimal Config for security tests."""
    defaults: dict[str, Any] = dict(
        allowed_commands=["*"],
        blocked_commands=[],
        allowed_paths=["/"],
        default_cwd="/tmp",
        command_timeout_secs=30,
        max_output_bytes=1048576,
        audit_log_file=None,
        server_cwd="/",
    )
    defaults.update(kwargs)
    return Config(**defaults)


class TestCheckCommand:
    def test_allowed_star(self) -> None:
        check_command("ls -la", _cfg(allowed_commands=["*"]))

    def test_allowlist_hit(self) -> None:
        check_command("ls -la", _cfg(allowed_commands=["ls"]))

    def test_allowlist_miss(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("df -h", _cfg(allowed_commands=["ls"]))

    def test_denylist_blocks_star(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("rm -rf /", _cfg(allowed_commands=["*"], blocked_commands=["rm"]))

    def test_denylist_exact_match(self) -> None:
        # 'rm' in denylist should NOT block 'rmdir'
        check_command("rmdir /tmp/x", _cfg(allowed_commands=["*"], blocked_commands=["rm"]))

    def test_absolute_path_denylist(self) -> None:
        # basename match: denylist 'rm' blocks '/usr/bin/rm'
        with pytest.raises(PolicyDenied):
            check_command("/usr/bin/rm file", _cfg(allowed_commands=["*"], blocked_commands=["rm"]))

    def test_empty_command(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("", _cfg())

    def test_whitespace_only(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("   ", _cfg())


class TestCheckPath:
    def test_allowed(self) -> None:
        check_path("/var/log/app.log", _cfg(allowed_paths=["/var/log"]))

    def test_denied(self) -> None:
        with pytest.raises(PolicyDenied):
            check_path("/etc/passwd", _cfg(allowed_paths=["/var/log"]))

    def test_traversal_blocked(self, tmp_path: Path) -> None:
        # Create a real path that traverses outside allowed prefix
        with pytest.raises(PolicyDenied):
            check_path("/var/log/../../etc/passwd", _cfg(allowed_paths=["/var/log"]))

    def test_unrestricted(self) -> None:
        check_path("/etc/passwd", _cfg(allowed_paths=["/"]))

    def test_relative_path(self, tmp_path: Path) -> None:
        # Relative path resolved; should be denied if outside allowed_paths
        with pytest.raises(PolicyDenied):
            check_path("relative/path", _cfg(allowed_paths=["/var/log"]))


class TestHardcodedBlockedCommands:
    """HARDCODED_BLOCKED_COMMANDS cannot be overridden by config."""

    def test_mkfs_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("mkfs /dev/sda1", _cfg(allowed_commands=["*"]))

    def test_mkfs_ext4_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("mkfs.ext4 /dev/sda1", _cfg(allowed_commands=["*"]))

    def test_fdisk_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("fdisk /dev/sda", _cfg(allowed_commands=["*"]))

    def test_wipefs_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("wipefs /dev/sda", _cfg(allowed_commands=["*"]))

    def test_shred_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("shred /dev/sda", _cfg(allowed_commands=["*"]))

    def test_shutdown_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("shutdown -h now", _cfg(allowed_commands=["*"]))

    def test_reboot_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("reboot", _cfg(allowed_commands=["*"]))

    def test_poweroff_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("poweroff", _cfg(allowed_commands=["*"]))

    def test_lvremove_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("lvremove /dev/vg0/lv0", _cfg(allowed_commands=["*"]))

    def test_absolute_path_mkfs_blocked(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("/sbin/mkfs.ext4 /dev/sda1", _cfg(allowed_commands=["*"]))

    def test_hardcoded_not_in_frozenset(self) -> None:
        # 'ls' is not in the hardcoded list
        assert "ls" not in HARDCODED_BLOCKED_COMMANDS

    def test_mkfs_in_frozenset(self) -> None:
        assert "mkfs" in HARDCODED_BLOCKED_COMMANDS

    def test_shutdown_in_frozenset(self) -> None:
        assert "shutdown" in HARDCODED_BLOCKED_COMMANDS


class TestDestructivePatterns:
    """DESTRUCTIVE_PATTERNS block dangerous full-command strings."""

    def test_rm_rf_root(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("rm -rf /", _cfg(allowed_commands=["*"], blocked_commands=[]))

    def test_rm_rf_root_glob(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("rm -rf /*", _cfg(allowed_commands=["*"], blocked_commands=[]))

    def test_rm_rf_home(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("rm -rf ~/", _cfg(allowed_commands=["*"], blocked_commands=[]))

    def test_dd_to_raw_device(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("dd if=/dev/zero of=/dev/sda", _cfg(allowed_commands=["*"]))

    def test_fork_bomb(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command(":(){ :|:& };:", _cfg(allowed_commands=["*"]))

    def test_kill_all(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("kill -9 -1", _cfg(allowed_commands=["*"]))

    def test_overwrite_passwd(self) -> None:
        with pytest.raises(PolicyDenied):
            check_command("cat /dev/null > /etc/passwd", _cfg(allowed_commands=["*"]))

    def test_patterns_list_nonempty(self) -> None:
        assert len(DESTRUCTIVE_PATTERNS) > 0

    def test_rm_safe_subdir_not_blocked(self) -> None:
        # rm on a regular subdir should NOT be blocked by patterns
        check_command("rm -rf /tmp/myproject", _cfg(allowed_commands=["*"], blocked_commands=[]))

    def test_rm_no_r_root_not_blocked_by_pattern(self) -> None:
        # rm without -r on a file — not caught by the recursive pattern
        # (may still be blocked if rm is in blocked_commands, but not by DESTRUCTIVE_PATTERNS)
        check_command("rm /tmp/foo.txt", _cfg(allowed_commands=["*"], blocked_commands=[]))


class TestIsOutsideCwd:
    def test_inside_cwd(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub" / "file.txt"
        assert not _is_outside_cwd(str(sub), str(tmp_path))

    def test_exactly_cwd(self, tmp_path: Path) -> None:
        assert not _is_outside_cwd(str(tmp_path), str(tmp_path))

    def test_outside_cwd(self, tmp_path: Path) -> None:
        assert _is_outside_cwd("/etc/passwd", str(tmp_path))

    def test_slash_sentinel_never_outside(self) -> None:
        assert not _is_outside_cwd("/etc/passwd", "/")
        assert not _is_outside_cwd("/tmp/foo", "/")


class TestWriteCommands:
    """WRITE_COMMANDS triggers approval in execute_command."""

    def test_rm_in_write_commands(self) -> None:
        assert "rm" in WRITE_COMMANDS

    def test_cp_in_write_commands(self) -> None:
        assert "cp" in WRITE_COMMANDS

    def test_mv_in_write_commands(self) -> None:
        assert "mv" in WRITE_COMMANDS

    def test_chmod_in_write_commands(self) -> None:
        assert "chmod" in WRITE_COMMANDS

    def test_ls_not_in_write_commands(self) -> None:
        assert "ls" not in WRITE_COMMANDS

    def test_cat_not_in_write_commands(self) -> None:
        assert "cat" not in WRITE_COMMANDS


# ---------------------------------------------------------------------------
# Section 3 — Executor
# ---------------------------------------------------------------------------

from server import ExecutionResult, execute


def _exec_cfg(**kwargs: Any) -> Config:
    defaults: dict[str, Any] = dict(
        allowed_commands=["*"],
        blocked_commands=[],
        allowed_paths=["/"],
        default_cwd="/tmp",
        command_timeout_secs=10,
        max_output_bytes=1048576,
        audit_log_file=None,
        server_cwd="/",
    )
    defaults.update(kwargs)
    return Config(**defaults)


class TestExecute:
    def test_echo(self) -> None:
        result = execute("echo hello", "/tmp", False, _exec_cfg())
        assert result.stdout == "hello\n"
        assert result.exit_code == 0
        assert not result.timed_out
        assert not result.truncated

    def test_exit_nonzero(self) -> None:
        result = execute("exit 42", "/tmp", True, _exec_cfg())
        assert result.exit_code == 42

    def test_timeout(self) -> None:
        result = execute("sleep 10", "/tmp", False, _exec_cfg(command_timeout_secs=1))
        assert result.timed_out
        assert result.exit_code == -1

    def test_truncate(self) -> None:
        # Generate output larger than max_output_bytes
        result = execute("python3 -c \"print('x'*200)\"", "/tmp", False, _exec_cfg(max_output_bytes=50))
        assert result.truncated

    def test_command_not_found(self) -> None:
        result = execute("nonexistent_cmd_xyz", "/tmp", False, _exec_cfg())
        assert result.exit_code == 127
        assert not result.timed_out

    def test_bad_cwd(self) -> None:
        result = execute("echo hi", "/nonexistent_path_xyz", False, _exec_cfg())
        assert result.exit_code == -1

    def test_duration(self) -> None:
        result = execute("echo hi", "/tmp", False, _exec_cfg())
        assert result.duration_secs >= 0

    def test_stderr_captured(self) -> None:
        result = execute("python3 -c \"import sys; sys.stderr.write('err')\"", "/tmp", False, _exec_cfg())
        assert "err" in result.stderr

    def test_shell_true(self) -> None:
        result = execute("echo $HOME", "/tmp", True, _exec_cfg())
        assert result.exit_code == 0
        assert result.stdout.strip() != ""


# ---------------------------------------------------------------------------
# Section 4 — Audit
# ---------------------------------------------------------------------------

from server import AuditLogger, create_audit_logger


def _audit_cfg(**kwargs: Any) -> Config:
    defaults: dict[str, Any] = dict(
        allowed_commands=["*"],
        blocked_commands=[],
        allowed_paths=["/"],
        default_cwd="/tmp",
        command_timeout_secs=30,
        max_output_bytes=1048576,
        audit_log_file=None,
        server_cwd="/",
    )
    defaults.update(kwargs)
    return Config(**defaults)


class TestAuditLogger:
    def _make_logger(self) -> tuple[AuditLogger, io.StringIO]:
        buf = io.StringIO()
        logger = AuditLogger(dest=buf)
        return logger, buf

    def test_writes_ndjson(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "execute_command", "input": {}, "outcome": "success"})
        line = buf.getvalue().strip()
        data = json.loads(line)
        assert isinstance(data, dict)

    def test_required_fields(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "execute_command", "input": {"command": "ls"}, "outcome": "success"})
        data = json.loads(buf.getvalue().strip())
        assert "timestamp" in data
        assert "tool" in data
        assert "input" in data
        assert "outcome" in data

    def test_timestamp_format(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "t", "input": {}, "outcome": "success"})
        data = json.loads(buf.getvalue().strip())
        assert data["timestamp"].endswith("Z")

    def test_redacts_password(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "t", "input": {"password": "secret123"}, "outcome": "success"})
        data = json.loads(buf.getvalue().strip())
        assert data["input"]["password"] == "[REDACTED]"

    def test_redacts_token(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "t", "input": {"api_token": "abc"}, "outcome": "success"})
        data = json.loads(buf.getvalue().strip())
        assert data["input"]["api_token"] == "[REDACTED]"

    def test_redacts_secret(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "t", "input": {"secret_key": "abc"}, "outcome": "success"})
        data = json.loads(buf.getvalue().strip())
        assert data["input"]["secret_key"] == "[REDACTED]"

    def test_safe_key_not_redacted(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "t", "input": {"command": "ls"}, "outcome": "success"})
        data = json.loads(buf.getvalue().strip())
        assert data["input"]["command"] == "ls"

    def test_no_interleave(self) -> None:
        logger, buf = self._make_logger()
        barrier = threading.Barrier(2)

        def _log(outcome: str) -> None:
            barrier.wait()
            logger.log({"tool": "t", "input": {}, "outcome": outcome})

        t1 = threading.Thread(target=_log, args=("success",))
        t2 = threading.Thread(target=_log, args=("error",))
        t1.start(); t2.start()
        t1.join(); t2.join()

        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # each line must be valid JSON

    def test_write_failure_no_raise(self) -> None:
        buf = io.StringIO()
        buf.close()
        logger = AuditLogger(dest=buf)
        logger.log({"tool": "t", "input": {}, "outcome": "success"})  # must not raise

    def test_close_flushes(self) -> None:
        logger, buf = self._make_logger()
        logger.log({"tool": "t", "input": {}, "outcome": "success"})
        logger.close()
        assert buf.closed or len(buf.getvalue()) > 0

    def test_stderr_when_no_file(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        cfg = _audit_cfg(audit_log_file=None)
        logger = create_audit_logger(cfg)
        logger.log({"tool": "t", "input": {}, "outcome": "success"})
        captured = capsys.readouterr()
        assert "outcome" in captured.err


# ---------------------------------------------------------------------------
# Section 5 — Tool Handler: execute_command
# ---------------------------------------------------------------------------

from server import handle_execute_command


class TestHandleExecuteCommand:
    def _cfg(self, **kwargs: Any) -> Config:
        defaults: dict[str, Any] = dict(
            allowed_commands=["*"],
            blocked_commands=[],
            allowed_paths=["/"],
            default_cwd="/tmp",
            command_timeout_secs=10,
            max_output_bytes=1048576,
            audit_log_file=None,
            server_cwd="/",
        )
        defaults.update(kwargs)
        return Config(**defaults)

    def _audit(self) -> tuple[AuditLogger, io.StringIO]:
        buf = io.StringIO()
        return AuditLogger(dest=buf), buf

    def test_success(self) -> None:
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_execute_command({"command": "echo hi"}, cfg, audit)
        assert result.get("isError") is not True
        text = result["content"][0]["text"]
        assert "Exit code: 0" in text
        assert "hi" in text

    def test_denied(self) -> None:
        cfg = self._cfg(allowed_commands=["*"], blocked_commands=["rm"])
        audit, buf = self._audit()
        result = handle_execute_command({"command": "rm -rf /"}, cfg, audit)
        assert result.get("isError") is True
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "denied"

    def test_timeout(self) -> None:
        cfg = self._cfg(command_timeout_secs=1)
        audit, buf = self._audit()
        result = handle_execute_command({"command": "sleep 10"}, cfg, audit)
        assert result.get("isError") is True
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "timeout"

    def test_bad_cwd(self) -> None:
        cfg = self._cfg(allowed_paths=["/tmp"])
        audit, _ = self._audit()
        result = handle_execute_command({"command": "ls", "cwd": "/etc"}, cfg, audit)
        assert result.get("isError") is True

    def test_timeout_clamped(self) -> None:
        cfg = self._cfg(command_timeout_secs=5)
        audit, _ = self._audit()
        # Passing a timeout larger than server max should be clamped, not error
        result = handle_execute_command({"command": "echo hi", "timeout_secs": 9999}, cfg, audit)
        assert result.get("isError") is not True

    def test_truncated_notice(self) -> None:
        cfg = self._cfg(max_output_bytes=5)
        audit, _ = self._audit()
        result = handle_execute_command({"command": "python3 -c \"print('x'*100)\""}, cfg, audit)
        text = result["content"][0]["text"]
        assert "truncated" in text.lower()

    def test_one_audit_entry(self) -> None:
        cfg = self._cfg()
        audit, buf = self._audit()
        handle_execute_command({"command": "echo hi"}, cfg, audit)
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_approval_required_outside_cwd(self, tmp_path: Path) -> None:
        """execute_command with cwd outside server_cwd requires approval."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc")
        audit, buf = self._audit()
        result = handle_execute_command({"command": "echo hi", "cwd": str(outside_dir)}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "approval_required"

    def test_approval_with_approve_true(self, tmp_path: Path) -> None:
        """execute_command proceeds with approve=True even if cwd is outside server_cwd."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc", allowed_paths=["/"])
        audit, _ = self._audit()
        result = handle_execute_command(
            {"command": "echo hi", "cwd": str(outside_dir), "approve": True}, cfg, audit
        )
        assert result.get("isError") is not True

    def test_default_cwd_outside_server_cwd_requires_approval(self) -> None:
        """Effective cwd uses default_cwd when no explicit cwd param; outside server_cwd needs approval."""
        cfg = self._cfg(default_cwd="/tmp", server_cwd="/nonexistent_cwd_xyz_abc")
        audit, buf = self._audit()
        # No cwd param; effective cwd = default_cwd = /tmp, which is outside server_cwd
        result = handle_execute_command({"command": "echo hi"}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()

    def test_hardcoded_blocked_in_execute(self) -> None:
        """Commands in HARDCODED_BLOCKED_COMMANDS are blocked even via execute_command."""
        cfg = self._cfg(allowed_commands=["*"])
        audit, buf = self._audit()
        result = handle_execute_command({"command": "mkfs /dev/sda1"}, cfg, audit)
        assert result.get("isError") is True
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "denied"

    def test_destructive_pattern_blocked_in_execute(self) -> None:
        """Destructive patterns are blocked even via execute_command."""
        cfg = self._cfg(allowed_commands=["*"])
        audit, buf = self._audit()
        result = handle_execute_command({"command": "rm -rf /"}, cfg, audit)
        assert result.get("isError") is True
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "denied"

    def test_write_command_requires_approval(self, tmp_path: Path) -> None:
        """rm on a local file requires approval (write command detection)."""
        cfg = self._cfg(server_cwd=str(tmp_path))
        audit, buf = self._audit()
        result = handle_execute_command({"command": "rm somefile.txt"}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "approval_required"

    def test_write_command_proceeds_with_approve(self, tmp_path: Path) -> None:
        """rm with approve=True proceeds (even if it then fails — file not found is fine)."""
        cfg = self._cfg(server_cwd=str(tmp_path), allowed_paths=["/"])
        audit, _ = self._audit()
        result = handle_execute_command(
            {"command": "rm nonexistent_xyz.txt", "approve": True}, cfg, audit
        )
        # The command runs (even if exit code != 0) — approval was satisfied
        text = result["content"][0]["text"]
        assert "approval" not in text.lower()

    def test_cp_requires_approval(self, tmp_path: Path) -> None:
        """cp is a write command and requires approval."""
        cfg = self._cfg(server_cwd=str(tmp_path))
        audit, buf = self._audit()
        result = handle_execute_command({"command": "cp src.txt dst.txt"}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()

    def test_mv_requires_approval(self, tmp_path: Path) -> None:
        """mv is a write command and requires approval."""
        cfg = self._cfg(server_cwd=str(tmp_path))
        audit, buf = self._audit()
        result = handle_execute_command({"command": "mv old.txt new.txt"}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()

    def test_read_only_command_no_approval_needed(self, tmp_path: Path) -> None:
        """echo/ls inside server_cwd does NOT require approval."""
        cfg = self._cfg(server_cwd=str(tmp_path), default_cwd=str(tmp_path))
        audit, _ = self._audit()
        result = handle_execute_command({"command": "echo hello"}, cfg, audit)
        assert result.get("isError") is not True


# ---------------------------------------------------------------------------
# Section 6 — Tool Handlers: Filesystem
# ---------------------------------------------------------------------------

from server import TOOLS, handle_list_directory, handle_read_file, handle_write_file


class TestToolsList:
    def test_all_four_tools(self) -> None:
        names = {t["name"] for t in TOOLS}
        assert names == {"execute_command", "read_file", "write_file", "list_directory"}


class TestHandleReadFile:
    def _cfg(self, **kwargs: Any) -> Config:
        defaults: dict[str, Any] = dict(
            allowed_commands=["*"], blocked_commands=[],
            allowed_paths=["/"], default_cwd="/tmp",
            command_timeout_secs=30, max_output_bytes=1048576, audit_log_file=None,
            server_cwd="/",
        )
        defaults.update(kwargs)
        return Config(**defaults)

    def _audit(self) -> tuple[AuditLogger, io.StringIO]:
        buf = io.StringIO()
        return AuditLogger(dest=buf), buf

    def test_success(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert result.get("isError") is not True
        assert "hello world" in result["content"][0]["text"]

    def test_truncate(self, tmp_path: Path) -> None:
        f = tmp_path / "big.txt"
        f.write_text("x" * 200)
        cfg = self._cfg(max_output_bytes=50)
        audit, _ = self._audit()
        result = handle_read_file({"path": str(f), "max_bytes": 10}, cfg, audit)
        text = result["content"][0]["text"]
        assert "Truncated" in text or "truncated" in text

    def test_directory_error(self, tmp_path: Path) -> None:
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_read_file({"path": str(tmp_path)}, cfg, audit)
        assert result.get("isError") is True

    def test_denied(self) -> None:
        cfg = self._cfg(allowed_paths=["/tmp"])
        audit, _ = self._audit()
        result = handle_read_file({"path": "/etc/passwd"}, cfg, audit)
        assert result.get("isError") is True

    def test_base64(self, tmp_path: Path) -> None:
        f = tmp_path / "bin.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_read_file({"path": str(f), "encoding": "base64"}, cfg, audit)
        assert result.get("isError") is not True
        decoded = base64.b64decode(result["content"][0]["text"])
        assert decoded == b"\x00\x01\x02\x03"

    def test_one_audit_entry(self, tmp_path: Path) -> None:
        f = tmp_path / "t.txt"
        f.write_text("hi")
        cfg = self._cfg()
        audit, buf = self._audit()
        handle_read_file({"path": str(f)}, cfg, audit)
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_approval_required_outside_cwd(self, tmp_path: Path) -> None:
        """read_file on path outside server_cwd requires approval."""
        f = tmp_path / "secret.txt"
        f.write_text("secret")
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc")
        audit, buf = self._audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "approval_required"

    def test_approval_with_approve_true(self, tmp_path: Path) -> None:
        """read_file proceeds with approve=True even if outside server_cwd."""
        f = tmp_path / "secret.txt"
        f.write_text("secret content")
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc")
        audit, _ = self._audit()
        result = handle_read_file({"path": str(f), "approve": True}, cfg, audit)
        assert result.get("isError") is not True
        assert "secret content" in result["content"][0]["text"]


class TestHandleWriteFile:
    def _cfg(self, **kwargs: Any) -> Config:
        defaults: dict[str, Any] = dict(
            allowed_commands=["*"], blocked_commands=[],
            allowed_paths=["/"], default_cwd="/tmp",
            command_timeout_secs=30, max_output_bytes=1048576, audit_log_file=None,
            server_cwd="/",
        )
        defaults.update(kwargs)
        return Config(**defaults)

    def _audit(self) -> tuple[AuditLogger, io.StringIO]:
        buf = io.StringIO()
        return AuditLogger(dest=buf), buf

    def test_create(self, tmp_path: Path) -> None:
        f = tmp_path / "new.txt"
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_write_file({"path": str(f), "content": "hello", "approve": True}, cfg, audit)
        assert result.get("isError") is not True
        assert f.read_text() == "hello"

    def test_overwrite(self, tmp_path: Path) -> None:
        f = tmp_path / "existing.txt"
        f.write_text("old")
        cfg = self._cfg()
        audit, _ = self._audit()
        handle_write_file({"path": str(f), "content": "new", "approve": True}, cfg, audit)
        assert f.read_text() == "new"

    def test_create_dirs(self, tmp_path: Path) -> None:
        f = tmp_path / "a" / "b" / "c.txt"
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_write_file({"path": str(f), "content": "x", "create_dirs": True, "approve": True}, cfg, audit)
        assert result.get("isError") is not True
        assert f.read_text() == "x"

    def test_no_create_dirs_missing_parent(self, tmp_path: Path) -> None:
        f = tmp_path / "missing" / "file.txt"
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_write_file({"path": str(f), "content": "x", "approve": True}, cfg, audit)
        assert result.get("isError") is True

    def test_base64(self, tmp_path: Path) -> None:
        f = tmp_path / "out.bin"
        encoded = base64.b64encode(b"\xde\xad\xbe\xef").decode()
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_write_file({"path": str(f), "content": encoded, "encoding": "base64", "approve": True}, cfg, audit)
        assert result.get("isError") is not True
        assert f.read_bytes() == b"\xde\xad\xbe\xef"

    def test_denied(self) -> None:
        cfg = self._cfg(allowed_paths=["/tmp"])
        audit, _ = self._audit()
        result = handle_write_file({"path": "/etc/test.txt", "content": "x", "approve": True}, cfg, audit)
        assert result.get("isError") is True

    def test_one_audit_entry(self, tmp_path: Path) -> None:
        f = tmp_path / "t.txt"
        cfg = self._cfg()
        audit, buf = self._audit()
        handle_write_file({"path": str(f), "content": "hi", "approve": True}, cfg, audit)
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_approval_required_without_approve(self, tmp_path: Path) -> None:
        """write_file always requires approval regardless of path."""
        f = tmp_path / "file.txt"
        cfg = self._cfg()
        audit, buf = self._audit()
        result = handle_write_file({"path": str(f), "content": "x"}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "approval_required"

    def test_approval_required_false_explicit(self, tmp_path: Path) -> None:
        """write_file with approve=False still requires approval."""
        f = tmp_path / "file.txt"
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_write_file({"path": str(f), "content": "x", "approve": False}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()

    def test_approval_outside_cwd_with_approve(self, tmp_path: Path) -> None:
        """write_file outside server_cwd proceeds when approve=True."""
        f = tmp_path / "file.txt"
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc")
        audit, _ = self._audit()
        result = handle_write_file({"path": str(f), "content": "hi", "approve": True}, cfg, audit)
        assert result.get("isError") is not True


class TestHandleListDirectory:
    def _cfg(self, **kwargs: Any) -> Config:
        defaults: dict[str, Any] = dict(
            allowed_commands=["*"], blocked_commands=[],
            allowed_paths=["/"], default_cwd="/tmp",
            command_timeout_secs=30, max_output_bytes=1048576, audit_log_file=None,
            server_cwd="/",
        )
        defaults.update(kwargs)
        return Config(**defaults)

    def _audit(self) -> tuple[AuditLogger, io.StringIO]:
        buf = io.StringIO()
        return AuditLogger(dest=buf), buf

    def test_success(self, tmp_path: Path) -> None:
        (tmp_path / "file.txt").write_text("hi")
        (tmp_path / "subdir").mkdir()
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_list_directory({"path": str(tmp_path)}, cfg, audit)
        assert result.get("isError") is not True
        text = result["content"][0]["text"]
        assert "file.txt" in text
        assert "subdir" in text

    def test_hidden_excluded(self, tmp_path: Path) -> None:
        (tmp_path / ".hidden").write_text("h")
        (tmp_path / "visible.txt").write_text("v")
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_list_directory({"path": str(tmp_path), "show_hidden": False}, cfg, audit)
        text = result["content"][0]["text"]
        assert ".hidden" not in text
        assert "visible.txt" in text

    def test_empty_dir(self, tmp_path: Path) -> None:
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_list_directory({"path": str(tmp_path)}, cfg, audit)
        assert result.get("isError") is not True

    def test_file_error(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("x")
        cfg = self._cfg()
        audit, _ = self._audit()
        result = handle_list_directory({"path": str(f)}, cfg, audit)
        assert result.get("isError") is True

    def test_denied(self) -> None:
        cfg = self._cfg(allowed_paths=["/tmp"])
        audit, _ = self._audit()
        result = handle_list_directory({"path": "/etc"}, cfg, audit)
        assert result.get("isError") is True

    def test_one_audit_entry(self, tmp_path: Path) -> None:
        cfg = self._cfg()
        audit, buf = self._audit()
        handle_list_directory({"path": str(tmp_path)}, cfg, audit)
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_approval_required_outside_cwd(self, tmp_path: Path) -> None:
        """list_directory on path outside server_cwd requires approval."""
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc")
        audit, buf = self._audit()
        result = handle_list_directory({"path": str(tmp_path)}, cfg, audit)
        assert result.get("isError") is True
        assert "approval" in result["content"][0]["text"].lower()
        data = json.loads(buf.getvalue().strip())
        assert data["outcome"] == "approval_required"

    def test_approval_with_approve_true(self, tmp_path: Path) -> None:
        """list_directory proceeds with approve=True even if outside server_cwd."""
        (tmp_path / "file.txt").write_text("hi")
        cfg = self._cfg(server_cwd="/nonexistent_cwd_xyz_abc")
        audit, _ = self._audit()
        result = handle_list_directory({"path": str(tmp_path), "approve": True}, cfg, audit)
        assert result.get("isError") is not True
        assert "file.txt" in result["content"][0]["text"]


# ---------------------------------------------------------------------------
# Section 7 — MCP Protocol
# ---------------------------------------------------------------------------

from server import read_message, write_message


def _make_message(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    return header + body


class TestReadWriteMessage:
    def test_roundtrip(self) -> None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        raw = io.BytesIO(_make_message(payload))
        result = read_message(raw)
        assert result == payload

    def test_exact_bytes(self) -> None:
        payload = {"method": "test"}
        body = json.dumps(payload).encode()
        # Append extra garbage after the message
        raw = io.BytesIO(f"Content-Length: {len(body)}\r\n\r\n".encode() + body + b"GARBAGE")
        result = read_message(raw)
        assert result == payload

    def test_write_produces_valid_frame(self) -> None:
        buf = io.BytesIO()
        msg = {"result": "ok"}
        write_message(buf, msg)
        buf.seek(0)
        parsed = read_message(buf)
        assert parsed == msg


class TestServerDispatch:
    """Integration tests for the JSON-RPC dispatch loop via run_server."""

    def _run_exchange(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Feed a sequence of requests into run_server and collect responses."""
        from server import run_server

        input_buf = io.BytesIO()
        for req in requests:
            input_buf.write(_make_message(req))
        input_buf.seek(0)

        output_buf = io.BytesIO()
        audit_buf = io.StringIO()
        cfg = Config(
            allowed_commands=["*"], blocked_commands=[],
            allowed_paths=["/"], default_cwd="/tmp",
            command_timeout_secs=10, max_output_bytes=1048576, audit_log_file=None,
            server_cwd="/",
        )
        audit = AuditLogger(dest=audit_buf)
        run_server(cfg, audit, stdin=input_buf, stdout=output_buf)

        output_buf.seek(0)
        responses: list[dict[str, Any]] = []
        while True:
            try:
                responses.append(read_message(output_buf))
            except Exception:
                break
        return responses

    def test_initialize(self) -> None:
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {}
        }}
        responses = self._run_exchange([req])
        assert len(responses) >= 1
        r = responses[0]
        assert r["result"]["protocolVersion"] == "2024-11-05"
        assert r["result"]["serverInfo"]["name"] == "mario"

    def test_tools_list(self) -> None:
        req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        responses = self._run_exchange([req])
        names = {t["name"] for t in responses[0]["result"]["tools"]}
        assert names == {"execute_command", "read_file", "write_file", "list_directory"}

    def test_tools_call_execute(self) -> None:
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "execute_command", "arguments": {"command": "echo hello"}}}
        responses = self._run_exchange([req])
        text = responses[0]["result"]["content"][0]["text"]
        assert "hello" in text

    def test_ping(self) -> None:
        req = {"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {}}
        responses = self._run_exchange([req])
        assert responses[0]["result"] == {}

    def test_unknown_method(self) -> None:
        req = {"jsonrpc": "2.0", "id": 5, "method": "no_such_method", "params": {}}
        responses = self._run_exchange([req])
        assert responses[0]["error"]["code"] == -32601

    def test_malformed_json(self) -> None:
        # Send a valid frame but with broken JSON body
        garbage_body = b"not json at all"
        raw_frame = f"Content-Length: {len(garbage_body)}\r\n\r\n".encode() + garbage_body
        # Follow with a valid ping so the server processes both
        ping = _make_message({"jsonrpc": "2.0", "id": 6, "method": "ping", "params": {}})
        input_buf = io.BytesIO(raw_frame + ping)
        output_buf = io.BytesIO()
        from server import run_server
        cfg = Config(
            allowed_commands=["*"], blocked_commands=[],
            allowed_paths=["/"], default_cwd="/tmp",
            command_timeout_secs=10, max_output_bytes=1048576, audit_log_file=None,
        )
        audit = AuditLogger(dest=io.StringIO())
        run_server(cfg, audit, stdin=input_buf, stdout=output_buf)
        output_buf.seek(0)
        responses: list[dict[str, Any]] = []
        while True:
            try:
                responses.append(read_message(output_buf))
            except Exception:
                break
        codes = [r.get("error", {}).get("code") for r in responses]
        assert -32700 in codes

    def test_unknown_tool(self) -> None:
        req = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": "no_such_tool", "arguments": {}}}
        responses = self._run_exchange([req])
        result = responses[0]["result"]
        assert result.get("isError") is True

    def test_eof_exits_cleanly(self) -> None:
        from server import run_server
        empty = io.BytesIO(b"")
        out = io.BytesIO()
        cfg = Config(
            allowed_commands=["*"], blocked_commands=[],
            allowed_paths=["/"], default_cwd="/tmp",
            command_timeout_secs=10, max_output_bytes=1048576, audit_log_file=None,
        )
        # Should return without raising
        run_server(cfg, AuditLogger(dest=io.StringIO()), stdin=empty, stdout=out)


# ---------------------------------------------------------------------------
# Section 1 (extended) — Config: transport fields
# ---------------------------------------------------------------------------


class TestConfigTransport:
    def test_transport_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRANSPORT", raising=False)
        assert load_config().transport == "sse"

    def test_transport_sse(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRANSPORT", "sse")
        assert load_config().transport == "sse"

    def test_transport_invalid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRANSPORT", "websocket")
        with pytest.raises(ConfigError):
            load_config()

    def test_sse_port_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSE_PORT", raising=False)
        assert load_config().sse_port == 8000

    def test_sse_port_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSE_PORT", "9090")
        assert load_config().sse_port == 9090

    def test_sse_port_invalid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSE_PORT", "99999")
        with pytest.raises(ConfigError):
            load_config()

    def test_sse_host_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSE_HOST", raising=False)
        assert load_config().sse_host == "0.0.0.0"

    def test_sse_host_custom(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSE_HOST", "0.0.0.0")
        assert load_config().sse_host == "0.0.0.0"


# ---------------------------------------------------------------------------
# Section 7 (extended) — SSE Transport
# ---------------------------------------------------------------------------

import socket
import urllib.error
import urllib.request

from server import run_sse_server


def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _sse_cfg(port: int) -> Config:
    return Config(
        allowed_commands=["*"], blocked_commands=[],
        allowed_paths=["/"], default_cwd="/tmp",
        command_timeout_secs=10, max_output_bytes=1048576,
        audit_log_file=None, transport="sse",
        sse_port=port, sse_host="127.0.0.1",
    )


class TestSseServer:
    """Integration tests for the SSE HTTP transport."""

    def _start_server(self, port: int) -> threading.Thread:
        cfg = _sse_cfg(port)
        audit = AuditLogger(dest=io.StringIO())
        t = threading.Thread(target=run_sse_server, args=(cfg, audit), daemon=True)
        t.start()
        # Wait until the port is accepting connections
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        return t

    def test_sse_endpoint_returns_event_stream(self) -> None:
        port = _free_port()
        self._start_server(port)

        # Use raw socket to read SSE stream without buffering issues
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.sendall(b"GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            response = b""
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    sock.settimeout(0.5)
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    if b"event: endpoint" in response:
                        break
                except socket.timeout:
                    if b"event: endpoint" in response:
                        break

        text = response.decode("utf-8", errors="replace")
        assert "text/event-stream" in text
        assert "event: endpoint" in text
        assert "sessionId=" in text

    def test_sse_message_exchange(self) -> None:
        port = _free_port()
        self._start_server(port)

        # Step 1: open SSE connection and read the endpoint event
        sse_sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sse_sock.sendall(b"GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")

        def _read_until_pattern(sock: socket.socket, pattern: bytes, timeout: float = 3.0) -> bytes:
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    sock.settimeout(0.3)
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    buf += chunk
                    if pattern in buf:
                        return buf
                except socket.timeout:
                    pass
            return buf

        raw = _read_until_pattern(sse_sock, b"event: endpoint")
        assert b"event: endpoint" in raw, "endpoint event not received"

        # Parse sessionId from the event data line
        text = raw.decode("utf-8", errors="replace")
        session_id = ""
        for line in text.splitlines():
            if "data:" in line and "sessionId=" in line:
                session_id = line.split("sessionId=")[-1].strip()
                break
        assert session_id, f"Could not parse sessionId from:\n{text}"

        # Step 2: POST a tools/list request
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/list", "params": {},
        }).encode("utf-8")
        post_req = (
            f"POST /message?sessionId={session_id} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body

        with socket.create_connection(("127.0.0.1", port), timeout=3) as post_sock:
            post_sock.sendall(post_req)
            post_resp = _read_until_pattern(post_sock, b"202", timeout=2.0)
            assert b"202" in post_resp

        # Step 3: wait for the SSE message response on the SSE connection
        raw2 = _read_until_pattern(sse_sock, b"event: message")
        sse_sock.close()

        assert b"event: message" in raw2, "No message event received"
        full = (raw + raw2).decode("utf-8", errors="replace")
        # Find the data line after "event: message"
        idx = full.find("event: message")
        snippet = full[idx:]
        data_line = next((l for l in snippet.splitlines() if l.startswith("data:")), None)
        assert data_line is not None
        payload = json.loads(data_line[len("data:"):].strip())
        names = {t["name"] for t in payload["result"]["tools"]}
        assert names == {"execute_command", "read_file", "write_file", "list_directory"}

    def test_post_unknown_session_returns_404(self) -> None:
        port = _free_port()
        self._start_server(port)

        msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/message?sessionId=nonexistent-session",
            data=msg,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=2)
        assert exc_info.value.code == 404


# ---------------------------------------------------------------------------
# Section 1 (extended) — Config: api_key
# ---------------------------------------------------------------------------


class TestConfigApiKey:
    def test_api_key_default_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("API_KEY", raising=False)
        assert load_config().api_key is None

    def test_api_key_empty_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY", "")
        assert load_config().api_key is None

    def test_api_key_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY", "secret123")
        assert load_config().api_key == "secret123"


# ---------------------------------------------------------------------------
# SSE Auth tests
# ---------------------------------------------------------------------------


def _auth_sse_cfg(port: int, api_key: Optional[str] = "test-key") -> Config:
    return Config(
        allowed_commands=["*"], blocked_commands=[],
        allowed_paths=["/"], default_cwd="/tmp",
        command_timeout_secs=10, max_output_bytes=1048576,
        audit_log_file=None, transport="sse",
        sse_port=port, sse_host="127.0.0.1",
        api_key=api_key,
    )


class TestSseAuth:
    def _start_server(self, port: int, api_key: Optional[str] = "test-key") -> None:
        cfg = _auth_sse_cfg(port, api_key=api_key)
        audit = AuditLogger(dest=io.StringIO())
        t = threading.Thread(target=run_sse_server, args=(cfg, audit), daemon=True)
        t.start()
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)

    def _raw_get_sse(self, port: int, auth_header: Optional[str] = None) -> bytes:
        """Send GET /sse and return the raw HTTP response bytes."""
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            req = "GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            if auth_header:
                req += f"Authorization: {auth_header}\r\n"
            req += "\r\n"
            sock.sendall(req.encode())
            buf = b""
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    sock.settimeout(0.3)
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                    # Stop once we have the status line
                    if b"\r\n" in buf:
                        break
                except socket.timeout:
                    break
        return buf

    def test_no_auth_configured_allows_all(self) -> None:
        """When API_KEY is not set, all connections are accepted."""
        port = _free_port()
        self._start_server(port, api_key=None)
        raw = self._raw_get_sse(port)
        assert b"200" in raw

    def test_correct_key_allowed(self) -> None:
        port = _free_port()
        self._start_server(port, api_key="test-key")
        raw = self._raw_get_sse(port, auth_header="Bearer test-key")
        assert b"200" in raw

    def test_wrong_key_rejected(self) -> None:
        port = _free_port()
        self._start_server(port, api_key="test-key")
        raw = self._raw_get_sse(port, auth_header="Bearer wrong-key")
        assert b"401" in raw

    def test_missing_key_rejected(self) -> None:
        port = _free_port()
        self._start_server(port, api_key="test-key")
        raw = self._raw_get_sse(port)  # no Authorization header
        assert b"401" in raw

    def test_post_without_key_rejected(self) -> None:
        """POST /message without auth should also return 401."""
        port = _free_port()
        self._start_server(port, api_key="test-key")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}).encode()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            req = (
                f"POST /message?sessionId=fake HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode() + body
            sock.sendall(req)
            buf = b""
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    sock.settimeout(0.3)
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\r\n" in buf:
                        break
                except socket.timeout:
                    break
        assert b"401" in buf

