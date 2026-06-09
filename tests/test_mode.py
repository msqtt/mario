"""Tests for MODE environment variable controlling approval behavior.

Three modes:
- read (default): cwd-internal read free, all writes need approval, outside-cwd needs approval
- write: cwd-internal read+write free, outside-cwd needs approval
- yolo: all operations free (hardcoded safety blocks still enforced)
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from server import (
    AuditLogger,
    Config,
    ConfigError,
    _ElicitationNeeded,
    _build_instructions,
    handle_execute_command,
    handle_list_directory,
    handle_read_file,
    handle_write_file,
    load_config,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg(server_cwd: str = "/home/user", mode: str = "read", **kwargs: Any) -> Config:
    defaults: dict[str, Any] = dict(
        allowed_commands=["*"], blocked_commands=[],
        allowed_paths=["/"], default_cwd=server_cwd,
        command_timeout_secs=30, max_output_bytes=1048576, audit_log_file=None,
        server_cwd=server_cwd, mode=mode,
    )
    defaults.update(kwargs)
    return Config(**defaults)


def _audit() -> tuple[AuditLogger, io.StringIO]:
    buf = io.StringIO()
    return AuditLogger(dest=buf), buf


# ── Section 1: Config parsing ─────────────────────────────────────────────────

class TestModeConfig:
    def test_default_mode_is_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MODE", raising=False)
        cfg = load_config()
        assert cfg.mode == "read"

    def test_mode_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODE", "read")
        cfg = load_config()
        assert cfg.mode == "read"

    def test_mode_write(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODE", "write")
        cfg = load_config()
        assert cfg.mode == "write"

    def test_mode_yolo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODE", "yolo")
        cfg = load_config()
        assert cfg.mode == "yolo"

    def test_invalid_mode_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODE", "invalid")
        with pytest.raises(ConfigError):
            load_config()

    def test_mode_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODE", "WRITE")
        cfg = load_config()
        assert cfg.mode == "write"


# ── Section 2: read mode (default) ───────────────────────────────────────────

class TestModeRead:
    """mode=read: cwd-internal read OK, writes need approval, outside-cwd needs approval."""

    def test_read_file_inside_cwd_free(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        cfg = _cfg(server_cwd=str(tmp_path), mode="read")
        audit, _ = _audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)
        assert "hello" in result["content"][0]["text"]

    def test_read_file_outside_cwd_needs_approval(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="read")
        audit, _ = _audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_write_file_inside_cwd_needs_approval(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        cfg = _cfg(server_cwd=str(tmp_path), mode="read")
        audit, _ = _audit()
        result = handle_write_file({"path": str(f), "content": "x"}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_write_file_outside_cwd_needs_approval(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="read")
        audit, _ = _audit()
        result = handle_write_file({"path": str(f), "content": "x"}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_list_directory_inside_cwd_free(self, tmp_path: Path) -> None:
        cfg = _cfg(server_cwd=str(tmp_path), mode="read")
        audit, _ = _audit()
        result = handle_list_directory({"path": str(tmp_path)}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)

    def test_list_directory_outside_cwd_needs_approval(self, tmp_path: Path) -> None:
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="read")
        audit, _ = _audit()
        result = handle_list_directory({"path": "/tmp"}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_execute_write_command_needs_approval(self, tmp_path: Path) -> None:
        cfg = _cfg(server_cwd=str(tmp_path), mode="read")
        audit, _ = _audit()
        result = handle_execute_command({"command": "rm foo.txt"}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)


# ── Section 3: write mode ─────────────────────────────────────────────────────

class TestModeWrite:
    """mode=write: cwd-internal read+write free, outside-cwd needs approval."""

    def test_read_file_inside_cwd_free(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        cfg = _cfg(server_cwd=str(tmp_path), mode="write")
        audit, _ = _audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)
        assert "hello" in result["content"][0]["text"]

    def test_write_file_inside_cwd_free(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        cfg = _cfg(server_cwd=str(tmp_path), mode="write")
        audit, _ = _audit()
        result = handle_write_file({"path": str(f), "content": "hello"}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)
        assert f.read_text() == "hello"

    def test_read_file_outside_cwd_needs_approval(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="write")
        audit, _ = _audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_write_file_outside_cwd_needs_approval(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="write")
        audit, _ = _audit()
        result = handle_write_file({"path": str(f), "content": "x"}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_execute_write_command_inside_cwd_free(self, tmp_path: Path) -> None:
        """write mode allows write commands inside cwd without approval."""
        f = tmp_path / "target.txt"
        f.write_text("delete me")
        cfg = _cfg(server_cwd=str(tmp_path), mode="write")
        audit, _ = _audit()
        result = handle_execute_command({"command": f"rm {f}"}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)

    def test_execute_write_command_outside_cwd_needs_approval(self, tmp_path: Path) -> None:
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="write")
        audit, _ = _audit()
        result = handle_execute_command({"command": "rm /tmp/foo", "cwd": "/tmp"}, cfg, audit)
        assert isinstance(result, _ElicitationNeeded)

    def test_list_directory_inside_cwd_free(self, tmp_path: Path) -> None:
        cfg = _cfg(server_cwd=str(tmp_path), mode="write")
        audit, _ = _audit()
        result = handle_list_directory({"path": str(tmp_path)}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)


# ── Section 4: yolo mode ──────────────────────────────────────────────────────

class TestModeYolo:
    """mode=yolo: all operations free, but hardcoded safety blocks still enforced."""

    def test_read_file_outside_cwd_free(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="yolo")
        audit, _ = _audit()
        result = handle_read_file({"path": str(f)}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)
        assert "hello" in result["content"][0]["text"]

    def test_write_file_outside_cwd_free(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="yolo")
        audit, _ = _audit()
        result = handle_write_file({"path": str(f), "content": "yolo"}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)
        assert f.read_text() == "yolo"

    def test_execute_write_command_free(self, tmp_path: Path) -> None:
        f = tmp_path / "target.txt"
        f.write_text("x")
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="yolo")
        audit, _ = _audit()
        result = handle_execute_command({"command": f"rm {f}"}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)

    def test_hardcoded_block_still_enforced(self, tmp_path: Path) -> None:
        """yolo mode does NOT bypass hardcoded safety blocks."""
        cfg = _cfg(server_cwd=str(tmp_path), mode="yolo")
        audit, _ = _audit()
        result = handle_execute_command({"command": "shutdown -h now"}, cfg, audit)
        # Should be denied (error response), not elicitation
        assert not isinstance(result, _ElicitationNeeded)
        assert result.get("isError") is True
        assert "denied" in result["content"][0]["text"].lower()

    def test_list_directory_outside_cwd_free(self, tmp_path: Path) -> None:
        cfg = _cfg(server_cwd="/nonexistent_xyz", mode="yolo")
        audit, _ = _audit()
        result = handle_list_directory({"path": "/tmp"}, cfg, audit)
        assert not isinstance(result, _ElicitationNeeded)

    def test_shell_redirect_free(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        cfg = _cfg(server_cwd=str(tmp_path), mode="yolo")
        audit, _ = _audit()
        result = handle_execute_command(
            {"command": f"echo hello > {f}", "shell": True}, cfg, audit
        )
        assert not isinstance(result, _ElicitationNeeded)


# ── Section 5: instructions include mode info ─────────────────────────────────

class TestModeInstructions:
    def test_instructions_mention_remote(self) -> None:
        cfg = _cfg(mode="read")
        instr = _build_instructions(cfg)
        # Must emphasize remote operations through MCP tools
        assert "remote" in instr.lower()
        assert "mcp" in instr.lower() or "mario" in instr.lower()

    def test_instructions_include_mode(self) -> None:
        for mode in ("read", "write", "yolo"):
            cfg = _cfg(mode=mode)
            instr = _build_instructions(cfg)
            assert mode in instr.lower()

    def test_instructions_emphasize_use_tools_not_local(self) -> None:
        cfg = _cfg(mode="read")
        instr = _build_instructions(cfg)
        # Should tell agent to use MCP tools, not local filesystem
        assert "read_file" in instr or "tool" in instr.lower()
