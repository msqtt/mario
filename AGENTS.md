# AGENTS.md — Shell MCP Server

## Project Overview

`shell-mcp-server` is an MCP (Model Context Protocol) server designed for DevOps and operations work. Once an AI agent connects to this server, it can execute shell commands directly on the server host to perform operations tasks (e.g., checking service status, restarting processes, querying logs, managing files).

## Tech Stack

- **Language**: Python 3.11+
- **Dependencies**: **stdlib only** — no third-party packages
- **Test framework**: pytest (dev-only dependency)
- **Type checker**: mypy (dev-only dependency)

## Repository Layout

```
shell-mcp-server/
├── AGENTS.md              # This file
├── specs/                 # Feature specifications (Phase 1)
├── tests/                 # Pytest test files (Phase 2)
│   └── test_server.py
├── server.py              # Single-file MCP server (Phase 3)
├── pyproject.toml
└── .env.example
```

> **Single-file rule**: All production code lives in `server.py`. Internal "modules" are organised as clearly separated classes and functions within that one file. No additional `.py` source files.

---

## Mandatory Rules

All agents MUST follow these rules. Violations are blockers.

### 1. Strict Development Order: SDD → TDD → Implementation

Every feature, enhancement, bug fix, or behavioral change MUST follow this exact order. **No exceptions.**

```
Phase 1: SPEC    — Write or update specs/<feature>.md first
Phase 2: TEST    — Write or update tests based on the spec
Phase 3: SOURCE  — Implement source code to pass the tests
```

**Phase 1 — Spec (gate: spec file committed/updated)**
- Before writing ANY code or test, read or create a Spec file under `specs/`.
- Spec files use Markdown format: `specs/<feature-name>.md`.
- A Spec must contain: goal, scope, API contract, data model, edge cases, and acceptance criteria.
- If no Spec exists, create one. If the change modifies existing behavior, update the existing Spec.
- Never skip Spec. No Spec = no work proceeds.

**Phase 2 — Tests (gate: failing tests exist that cover the spec)**
- Write test cases that cover every acceptance criterion in the Spec.
- Tests MUST fail initially (red) before implementation begins.
- Test files live in `tests/test_server.py` (pytest).- Minimum coverage target: core modules 90%, utilities 70%.

**Phase 3 — Implementation (gate: all tests green)**
- Implement source code only after failing tests exist.
- Run `pytest` — all tests must pass (green) before considering the task done.
- Run `mypy server.py` — no type errors.
- Do not add functionality beyond what the Spec defines.

**Anti-patterns (NEVER do these):**
- Writing source code first and adding tests/specs after the fact.
- Modifying source code without first updating the Spec if behavior changes.
- Skipping Spec for "small changes" — even bug fixes need a one-line Spec update.
- Writing tests that pass immediately without first verifying they would fail against unimplemented code.

### 2. Security Baseline

- NEVER hardcode API keys, passwords, or secrets in any file.
- All secrets come from environment variables or `.env` (which is gitignored).
- Shell command execution MUST enforce an allowlist or sandbox policy — never expose unrestricted root shell access without explicit configuration.
- Log all executed commands with timestamp, caller identity, and exit code for audit purposes.
- Sensitive output (e.g., environment variables, credential files) must be redacted or guarded by policy before being returned to the agent.

---

## Development Workflow (Step-by-Step)

1. **Pick a task** from the backlog or issue tracker.
2. **Write/update the Spec** in `specs/<feature>.md`. Include goal, API contract, edge cases, and acceptance criteria. Commit the spec.
3. **Write failing tests** in `tests/test_<module>.py` covering all acceptance criteria. Confirm tests fail (`pytest` shows red).
4. **Implement** the feature in `src/shell_mcp_server/`. Run `pytest` until green.
5. **Type-check**: run `mypy src/` — zero errors required.
6. **Commit** with a conventional commit message referencing the spec.

---

## Running Tests & Checks

```bash
# Install dev dependencies (pytest + mypy only)
pip install pytest mypy

# Run tests
pytest

# Type check
mypy server.py

# Run the server locally (stdio transport)
python server.py
```

---

## Key Design Principles

- **Least privilege**: commands run as a non-root user by default; privilege escalation requires explicit opt-in.
- **Auditability**: every tool call is logged with full context.
- **Determinism**: tool responses are structured JSON — never raw unformatted text blobs.
- **Fail-safe**: timeouts and resource limits are enforced on every command execution.
