"""Phase 4: Autonomous Agent Tool Dispatchers.

Provides `terminal_exec`, `read_file`, and `write_file` tools with two execution
backends:
  - unprotected: Spawns real OS subprocesses — demonstrates host compromise.
  - aegis:       Routes all execution through the Wasmer WASI sandbox + honeypot.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from aegis.core.honeypot import HoneypotManager
from aegis.core.policy import STRICT_SANDBOX_POLICY
from aegis.core.sandbox import ExecutionResult, WasmerSandbox
from aegis.core.telemetry import TelemetryDispatcher, get_dispatcher


class ToolResult(BaseModel):
    """Unified result object returned by every agent tool."""
    tool: str
    mode: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    trapped: bool = False
    canary_tripped: bool = False
    incident_id: Optional[str] = None
    duration_ms: float = 0.0


class AgentTools:
    """
    Dispatch table for autonomous agent tools.
    Instantiate once per agent session; the same sandbox instance is reused
    across calls so honeypot state is preserved.
    """

    def __init__(
        self,
        mode: str = "aegis",
        workspace: Optional[Path] = None,
        dispatcher: Optional[TelemetryDispatcher] = None,
    ):
        if mode not in ("aegis", "unprotected"):
            raise ValueError(f"Unknown mode '{mode}'. Must be 'aegis' or 'unprotected'.")
        self.mode = mode
        self.workspace = workspace or Path.cwd()
        self.dispatcher = dispatcher or get_dispatcher()
        self._sandbox: Optional[WasmerSandbox] = None
        self._honeypot: Optional[HoneypotManager] = None

        if mode == "aegis":
            self._init_aegis_sandbox()

    def _init_aegis_sandbox(self) -> None:
        """Spin up the Wasmer WASI sandbox and seed the VFS with honeytoken decoys."""
        self._honeypot = HoneypotManager()
        self._sandbox = WasmerSandbox(policy=STRICT_SANDBOX_POLICY)
        vfs = self._honeypot.seed_sandbox_vfs(self._sandbox.write_vfs_file)
        return vfs

    # ------------------------------------------------------------------
    # Tool: terminal_exec
    # ------------------------------------------------------------------

    def terminal_exec(self, command: str) -> ToolResult:
        """
        Execute a shell command.
        - unprotected: spawns a real OS subprocess — vulnerable to host compromise.
        - aegis:       routes through Wasmer sandbox with VFS jail + honeytoken detection.
        """
        if self.mode == "unprotected":
            return self._exec_unprotected(command)
        else:
            return self._exec_aegis(command)

    def _exec_unprotected(self, command: str) -> ToolResult:
        """Native subprocess execution — deliberately vulnerable baseline."""
        import time
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(self.workspace),
            )
            return ToolResult(
                tool="terminal_exec",
                mode="unprotected",
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                duration_ms=(time.perf_counter() - t0) * 1000,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool="terminal_exec",
                mode="unprotected",
                stderr="Command timed out after 10 seconds.",
                exit_code=124,
                duration_ms=(time.perf_counter() - t0) * 1000,
            )

    def _exec_aegis(self, command: str) -> ToolResult:
        """Wasmer-sandboxed execution with tripwire telemetry."""
        assert self._sandbox is not None
        result: ExecutionResult = self._sandbox.execute_command(command)

        incident = None
        if result.trapped or result.canary_tripped or result.violations:
            incident = self.dispatcher.incident_from_sandbox_result(result, original_command=command)
            self.dispatcher.emit(incident)

        return ToolResult(
            tool="terminal_exec",
            mode="aegis",
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            trapped=result.trapped,
            canary_tripped=result.canary_tripped,
            incident_id=incident.incident_id if incident else None,
            duration_ms=result.duration_ms,
        )

    # ------------------------------------------------------------------
    # Tool: read_file
    # ------------------------------------------------------------------

    def read_file(self, path: str) -> ToolResult:
        """Read a file from disk (unprotected) or from the sandboxed VFS (aegis)."""
        if self.mode == "unprotected":
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
                return ToolResult(tool="read_file", mode="unprotected", stdout=content)
            except Exception as e:
                return ToolResult(tool="read_file", mode="unprotected", stderr=str(e), exit_code=1)
        else:
            # Route read through sandbox so traversal attempts are caught
            return self._exec_aegis(f"cat {path}")

    # ------------------------------------------------------------------
    # Tool: write_file
    # ------------------------------------------------------------------

    def write_file(self, path: str, content: str) -> ToolResult:
        """Write a file (unprotected: host disk, aegis: sandboxed VFS)."""
        if self.mode == "unprotected":
            try:
                Path(path).write_text(content, encoding="utf-8")
                return ToolResult(tool="write_file", mode="unprotected", stdout=f"Written: {path}")
            except Exception as e:
                return ToolResult(tool="write_file", mode="unprotected", stderr=str(e), exit_code=1)
        else:
            try:
                assert self._sandbox is not None
                self._sandbox.write_vfs_file(path, content)
                return ToolResult(tool="write_file", mode="aegis", stdout=f"Written to VFS: {path}")
            except Exception as e:
                return ToolResult(tool="write_file", mode="aegis", stderr=str(e), exit_code=1)

    def close(self) -> None:
        """Tear down the Wasmer sandbox and clean up the ephemeral VFS."""
        if self._sandbox is not None:
            self._sandbox.destroy()
            self._sandbox = None

    def __enter__(self) -> "AgentTools":
        return self

    def __exit__(self, *_) -> None:
        self.close()
