"""Tests for dynamic mode-aware tool descriptions and approve field documentation.

Validates:
1. Tool descriptions change based on config.mode
2. approve field has a description telling agents not to set it
3. instructions include mode-specific permission guidance
"""

from __future__ import annotations

import io
from typing import Any

import pytest

from server import (
    AuditLogger,
    Config,
    _build_instructions,
    dispatch,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg(mode: str = "read", **kwargs: Any) -> Config:
    defaults: dict[str, Any] = dict(
        allowed_commands=["*"], blocked_commands=[],
        allowed_paths=["/"], default_cwd="/home/user",
        command_timeout_secs=30, max_output_bytes=1048576, audit_log_file=None,
        server_cwd="/home/user", mode=mode,
    )
    defaults.update(kwargs)
    return Config(**defaults)


def _audit() -> AuditLogger:
    return AuditLogger(dest=io.StringIO())


def _tools_list(config: Config) -> list[dict[str, Any]]:
    """Call tools/list via dispatch and return the tools array."""
    audit = _audit()
    resp = dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        config, audit,
    )
    assert resp is not None
    return resp["result"]["tools"]


# ── Section 1: approve field has description in all tools ─────────────────────

class TestApproveFieldDescription:
    """Every tool schema's approve property must have a description."""

    @pytest.mark.parametrize("mode", ["read", "write", "yolo"])
    def test_all_tools_have_approve_description(self, mode: str) -> None:
        tools = _tools_list(_cfg(mode=mode))
        for tool in tools:
            props = tool["inputSchema"]["properties"]
            assert "approve" in props, f"{tool['name']} missing approve field"
            assert "description" in props["approve"], (
                f"{tool['name']} approve field has no description"
            )

    @pytest.mark.parametrize("mode", ["read", "write", "yolo"])
    def test_approve_description_warns_not_to_set(self, mode: str) -> None:
        """The approve description must tell the agent NOT to set it manually."""
        tools = _tools_list(_cfg(mode=mode))
        for tool in tools:
            desc = tool["inputSchema"]["properties"]["approve"]["description"]
            # Must contain some warning language
            assert "do not" in desc.lower() or "don't" in desc.lower(), (
                f"{tool['name']} approve description doesn't warn against manual use: {desc}"
            )


# ── Section 2: tool descriptions are mode-aware ──────────────────────────────

class TestDynamicToolDescriptions:
    """Tool descriptions must change based on mode to guide the agent."""

    def test_read_mode_mentions_approval(self) -> None:
        tools = _tools_list(_cfg(mode="read"))
        tool_map = {t["name"]: t for t in tools}

        # write_file in read mode should mention approval
        wf_desc = tool_map["write_file"]["description"]
        assert "approval" in wf_desc.lower() or "confirm" in wf_desc.lower()

        # execute_command in read mode should mention write commands need approval
        ec_desc = tool_map["execute_command"]["description"]
        assert "approval" in ec_desc.lower() or "confirm" in ec_desc.lower()

    def test_write_mode_mentions_cwd_free(self) -> None:
        tools = _tools_list(_cfg(mode="write"))
        tool_map = {t["name"]: t for t in tools}

        # write_file in write mode should mention cwd writes are free
        wf_desc = tool_map["write_file"]["description"]
        assert "free" in wf_desc.lower() or "without" in wf_desc.lower() or "no approval" in wf_desc.lower()

    def test_yolo_mode_mentions_no_approval(self) -> None:
        tools = _tools_list(_cfg(mode="yolo"))
        tool_map = {t["name"]: t for t in tools}

        # All tools in yolo mode should indicate no approval needed
        for name in ("execute_command", "write_file", "read_file", "list_directory", "search_files"):
            desc = tool_map[name]["description"]
            assert "no approval" in desc.lower() or "without approval" in desc.lower() or "freely" in desc.lower(), (
                f"{name} in yolo mode doesn't mention no approval: {desc}"
            )

    def test_descriptions_differ_between_modes(self) -> None:
        """The same tool should have different descriptions in different modes."""
        tools_read = {t["name"]: t for t in _tools_list(_cfg(mode="read"))}
        tools_yolo = {t["name"]: t for t in _tools_list(_cfg(mode="yolo"))}

        # write_file description must differ between read and yolo
        assert tools_read["write_file"]["description"] != tools_yolo["write_file"]["description"]

    def test_execute_command_description_mentions_mode(self) -> None:
        """execute_command description should include the current mode name."""
        for mode in ("read", "write", "yolo"):
            tools = _tools_list(_cfg(mode=mode))
            ec = next(t for t in tools if t["name"] == "execute_command")
            assert mode in ec["description"].lower()


# ── Section 3: instructions are mode-specific and actionable ──────────────────

class TestInstructionsOptimized:
    """Instructions must give the agent clear, actionable mode-specific guidance."""

    def test_read_mode_instructions_mention_read_free(self) -> None:
        instr = _build_instructions(_cfg(mode="read"))
        # Should tell agent reads in cwd are free
        assert "read" in instr.lower()
        assert "free" in instr.lower() or "without" in instr.lower()

    def test_write_mode_instructions_mention_write_free(self) -> None:
        instr = _build_instructions(_cfg(mode="write"))
        # Should tell agent writes in cwd are free
        assert "write" in instr.lower()
        assert "free" in instr.lower() or "without" in instr.lower()

    def test_yolo_mode_instructions_mention_full_access(self) -> None:
        instr = _build_instructions(_cfg(mode="yolo"))
        assert "full" in instr.lower() or "no approval" in instr.lower()

    def test_instructions_mention_server_cwd(self) -> None:
        instr = _build_instructions(_cfg(mode="read", server_cwd="/opt/app"))
        assert "/opt/app" in instr

    def test_instructions_emphasize_remote(self) -> None:
        instr = _build_instructions(_cfg(mode="read"))
        assert "remote" in instr.lower()
        assert "local" in instr.lower()  # Should tell agent NOT to use local

    def test_instructions_mention_tool_preference(self) -> None:
        instr = _build_instructions(_cfg(mode="read"))
        assert "read_file" in instr


# ── Section 4: instructions teach the agent how to handle "modify line N" ─────

class TestInstructionsAgentRouting:
    """The instructions block is the agent's onboarding doc — it must explicitly
    map common user intents to MCP tools and explain the read-modify-write
    pattern (since mario has no partial-edit primitive)."""

    def test_instructions_name_every_tool(self) -> None:
        """Every tool must be referenced by name so the agent knows it exists."""
        instr = _build_instructions(_cfg(mode="read"))
        for tool_name in (
            "read_file", "write_file",
            "list_directory", "search_files", "execute_command",
        ):
            assert tool_name in instr, f"{tool_name} not mentioned in instructions"

    def test_instructions_explain_line_edit_pattern(self) -> None:
        """Instructions must document the read-modify-write line-edit recipe so
        that 'modify line N of foo.py' is handled with read_file + write_file
        (not by hallucinating a partial edit)."""
        instr = _build_instructions(_cfg(mode="read")).lower()
        # Must mention line-based editing
        assert "line" in instr
        # Must reference both halves of the recipe
        assert "read_file" in instr
        assert "write_file" in instr
        # Must convey that write_file overwrites / there is no partial edit
        assert (
            "overwrite" in instr
            or "no partial" in instr
            or "full" in instr
            or "complete" in instr
        )

    def test_instructions_warn_against_setting_approve(self) -> None:
        """Tell the agent NOT to set approve=true manually."""
        instr = _build_instructions(_cfg(mode="read")).lower()
        assert "approve" in instr
        assert "do not" in instr or "don't" in instr or "never" in instr


# ── Section 5: tool descriptions are routing-friendly ────────────────────────

class TestToolDescriptionsRouting:
    """Tool descriptions must include the word 'remote' so the agent
    immediately understands the operation runs on a remote host, and
    write_file's description must teach the read-modify-write pattern."""

    @pytest.mark.parametrize("mode", ["read", "write", "yolo"])
    @pytest.mark.parametrize(
        "tool_name",
        ["execute_command", "read_file", "write_file", "list_directory", "search_files"],
    )
    def test_every_tool_mentions_remote(self, mode: str, tool_name: str) -> None:
        tools = _tools_list(_cfg(mode=mode))
        tool = next(t for t in tools if t["name"] == tool_name)
        assert "remote" in tool["description"].lower(), (
            f"{tool_name} ({mode} mode) description does not mention 'remote': "
            f"{tool['description']}"
        )

    @pytest.mark.parametrize("mode", ["read", "write", "yolo"])
    def test_write_file_description_explains_overwrite(self, mode: str) -> None:
        """write_file is the agent's only mutation primitive — its description
        must say it overwrites (no partial edit) and reference read_file as the
        first step of a line-edit workflow."""
        tools = _tools_list(_cfg(mode=mode))
        wf = next(t for t in tools if t["name"] == "write_file")
        desc = wf["description"].lower()
        # Mentions overwrite / no in-place
        assert "overwrite" in desc or "no partial" in desc or "no in-place" in desc, (
            f"write_file description must say it overwrites: {wf['description']}"
        )
        # References the read_file half of the recipe
        assert "read_file" in desc, (
            f"write_file description must reference read_file for line-edit workflow: "
            f"{wf['description']}"
        )

    @pytest.mark.parametrize("mode", ["read", "write", "yolo"])
    def test_read_file_description_supports_line_lookups(self, mode: str) -> None:
        """read_file is what the agent calls for 'show me line N of foo.py'."""
        tools = _tools_list(_cfg(mode=mode))
        rf = next(t for t in tools if t["name"] == "read_file")
        desc = rf["description"].lower()
        # Must invite usage for view/inspect/open scenarios
        assert (
            "view" in desc or "inspect" in desc or "open" in desc or "look" in desc
        ), f"read_file description should invite use for viewing: {rf['description']}"
