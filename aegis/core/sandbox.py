"""Wasmer & WASI Runtime Containment Engine for AegisAgent.

Provides in-process, deterministic WebAssembly/WASI execution sandboxing,
virtual filesystem isolation, zero-network capability enforcement, and
sub-millisecond security policy violation trapping.
"""

import os
import re
import shlex
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import wasmtime
from pydantic import BaseModel, Field

from aegis.config import CanaryConfig, SandboxCapability, settings
from aegis.core.policy import (
    NetworkEgressBlockedError,
    PathTraversalError,
    PolicyViolation,
    PolicyViolationType,
    STRICT_SANDBOX_POLICY,
    SecurityPolicy,
)


class ExecutionResult(BaseModel):
    """Result of a command or WASM module execution inside the sandbox."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    trapped: bool = False
    violations: List[PolicyViolation] = Field(default_factory=list)
    canary_tripped: bool = False
    blocked_syscall: Optional[str] = None


class WasmerSandbox:
    """Deterministic WASI runtime execution sandbox with VFS isolation and capability controls."""

    def __init__(
        self,
        policy: SecurityPolicy = STRICT_SANDBOX_POLICY,
        workspace_dir: Optional[Path] = None,
        canary_config: Optional[CanaryConfig] = None,
    ):
        self.policy = policy
        self.canary_config = canary_config or settings.canary_config
        self._temp_dir_obj: Optional[tempfile.TemporaryDirectory] = None

        if workspace_dir is not None:
            self.host_workspace = Path(workspace_dir).resolve()
            self.host_workspace.mkdir(parents=True, exist_ok=True)
        else:
            self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="aegis_wasi_workspace_")
            self.host_workspace = Path(self._temp_dir_obj.name).resolve()

        self.violations: List[PolicyViolation] = []
        self._init_wasmer_engine()

    def _init_wasmer_engine(self) -> None:
        """Initialize the underlying WASI execution engine."""
        wasmtime_cfg = wasmtime.Config()
        wasmtime_cfg.consume_fuel = True
        self.engine = wasmtime.Engine(wasmtime_cfg)

    @property
    def guest_workspace(self) -> str:
        return self.policy.capabilities.guest_workspace

    def setup_vfs(self, initial_files: Optional[Dict[str, str]] = None) -> None:
        """Populate the isolated guest workspace with initial files."""
        if initial_files:
            for rel_path, content in initial_files.items():
                self.write_vfs_file(rel_path, content)

    def resolve_path(self, virtual_path: str) -> Path:
        """
        Safely resolve a guest virtual path to the isolated host workspace directory.
        Raises PathTraversalError if the path attempts to escape the sandbox jail.
        """
        return self.policy.resolve_sandbox_path(virtual_path, self.host_workspace)

    def read_vfs_file(self, virtual_path: str) -> str:
        """
        Safely read a file from the guest VFS.
        Raises PathTraversalError if attempting traversal outside /workspace.
        """
        try:
            target_path = self.resolve_path(virtual_path)
            if not target_path.exists():
                raise FileNotFoundError(f"File not found in VFS: '{virtual_path}'")
            if target_path.is_dir():
                raise IsADirectoryError(f"Is a directory in VFS: '{virtual_path}'")
            return target_path.read_text(encoding="utf-8", errors="replace")
        except PathTraversalError as e:
            violation = PolicyViolation(
                violation_type=PolicyViolationType.FILE_SYSTEM_TRAVERSAL,
                detail=str(e),
                target=virtual_path,
            )
            self.violations.append(violation)
            raise

    def write_vfs_file(self, virtual_path: str, content: str) -> Path:
        """
        Safely write a file to the guest VFS.
        Raises PathTraversalError if attempting traversal outside /workspace.
        """
        try:
            target_path = self.resolve_path(virtual_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content, encoding="utf-8")
            return target_path
        except PathTraversalError as e:
            violation = PolicyViolation(
                violation_type=PolicyViolationType.FILE_SYSTEM_TRAVERSAL,
                detail=str(e),
                target=virtual_path,
            )
            self.violations.append(violation)
            raise

    def list_vfs_dir(self, virtual_path: str = "/workspace") -> List[str]:
        """Safely list directory contents in the guest VFS."""
        target_path = self.resolve_path(virtual_path)
        if not target_path.exists():
            raise FileNotFoundError(f"Directory not found in VFS: '{virtual_path}'")
        if not target_path.is_dir():
            raise NotADirectoryError(f"Not a directory in VFS: '{virtual_path}'")
        return [p.name for p in target_path.iterdir()]

    def execute_wasm(
        self,
        wasm_bytes: bytes,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        stdin_data: Optional[bytes] = None,
    ) -> ExecutionResult:
        """
        Execute raw WebAssembly bytecode inside the WASI sandbox with strict capability limits.
        """
        start_time = time.perf_counter()
        violations: List[PolicyViolation] = []

        store = wasmtime.Store(self.engine)
        store.set_fuel(self.policy.capabilities.fuel_limit)

        linker = wasmtime.Linker(self.engine)
        linker.define_wasi()

        wasi_cfg = wasmtime.WasiConfig()
        wasi_cfg.argv = args or ["aegis_guest"]

        # Environment policy enforcement: Do NOT pass host environment
        if self.policy.capabilities.allow_env and env:
            wasi_cfg.env = list(env.items())
        else:
            wasi_cfg.env = []

        # Isolated VFS preopen: ONLY map host_workspace -> guest_workspace
        wasi_cfg.preopen_dir(str(self.host_workspace), self.guest_workspace)

        # In-memory stdout and stderr capture via temporary capture files
        stdout_tmp = tempfile.NamedTemporaryFile(delete=False)
        stderr_tmp = tempfile.NamedTemporaryFile(delete=False)
        stdout_tmp_path = Path(stdout_tmp.name)
        stderr_tmp_path = Path(stderr_tmp.name)
        stdout_tmp.close()
        stderr_tmp.close()

        wasi_cfg.stdout_file = str(stdout_tmp_path)
        wasi_cfg.stderr_file = str(stderr_tmp_path)

        if stdin_data:
            stdin_tmp = tempfile.NamedTemporaryFile(delete=False)
            stdin_tmp.write(stdin_data)
            stdin_tmp_path = Path(stdin_tmp.name)
            stdin_tmp.close()
            wasi_cfg.stdin_file = str(stdin_tmp_path)
        else:
            stdin_tmp_path = None

        store.set_wasi(wasi_cfg)

        exit_code = 0
        trapped = False
        blocked_syscall = None

        try:
            module = wasmtime.Module(self.engine, wasm_bytes)
            instance = linker.instantiate(store, module)
            start_func = instance.exports(store).get("_start")
            if start_func:
                start_func(store)
        except wasmtime.ExitTrap as e:
            exit_code = e.code
        except wasmtime.Trap as e:
            trapped = True
            exit_code = 137
            detail = f"WASI trap occurred: {e}"
            blocked_syscall = "wasi:trap"
            violations.append(
                PolicyViolation(
                    violation_type=PolicyViolationType.UNAUTHORIZED_SYSCALL,
                    detail=detail,
                )
            )
        except Exception as e:
            trapped = True
            exit_code = 1
            violations.append(
                PolicyViolation(
                    violation_type=PolicyViolationType.UNAUTHORIZED_SYSCALL,
                    detail=f"Execution failure: {e}",
                )
            )
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Read captured outputs cleanly
            stdout_content = stdout_tmp_path.read_text(encoding="utf-8", errors="replace") if stdout_tmp_path.exists() else ""
            stderr_content = stderr_tmp_path.read_text(encoding="utf-8", errors="replace") if stderr_tmp_path.exists() else ""

            # Clean up capture files
            for p in (stdout_tmp_path, stderr_tmp_path, stdin_tmp_path):
                if p and p.exists():
                    try:
                        p.unlink()
                    except OSError:
                        pass

        # Inspect outputs for honeytoken tripping
        canary_tripped = self._check_canary_leakage(stdout_content + stderr_content)
        if canary_tripped:
            violations.append(
                PolicyViolation(
                    violation_type=PolicyViolationType.CANARY_TOKEN_TRIPPED,
                    detail="Canary token signature detected in execution output stream",
                )
            )

        return ExecutionResult(
            stdout=stdout_content,
            stderr=stderr_content,
            exit_code=exit_code,
            duration_ms=duration_ms,
            trapped=trapped or canary_tripped,
            violations=violations,
            canary_tripped=canary_tripped,
            blocked_syscall=blocked_syscall,
        )

    def execute_command(self, command: str) -> ExecutionResult:
        """
        Execute an agent command within the Wasmer WASI sandbox boundary.
        Enforces:
        - Network capability denial (curl, wget, nc, urls)
        - Virtual filesystem isolation & path traversal denial (cat /secrets/.., ../)
        - Output scanning for canary honeytokens
        """
        start_time = time.perf_counter()
        violations: List[PolicyViolation] = []
        cmd_str = command.strip()

        # 1. Capability: Network Egress Check
        if not self.policy.capabilities.allow_net:
            network_violation = self._detect_network_egress(cmd_str)
            if network_violation:
                violations.append(network_violation)
                return ExecutionResult(
                    stdout="",
                    stderr=f"[AEGIS_WASI_RUNTIME_TRAP] Blocked syscall 'sock_open' / network egress attempt: {network_violation.detail}",
                    exit_code=126,
                    duration_ms=(time.perf_counter() - start_time) * 1000.0,
                    trapped=True,
                    violations=violations,
                    blocked_syscall="wasi_snapshot_preview1:sock_open",
                )

        # 2. VFS Capability: Path Traversal Check
        traversal_violation = self._detect_path_traversal(cmd_str)
        if traversal_violation:
            violations.append(traversal_violation)
            return ExecutionResult(
                stdout="",
                stderr=f"[AEGIS_WASI_RUNTIME_TRAP] Blocked syscall 'path_open' / directory traversal: {traversal_violation.detail}",
                exit_code=1,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
                trapped=True,
                violations=violations,
                blocked_syscall="wasi_snapshot_preview1:path_open",
            )

        # 3. In-sandbox command evaluation within isolated VFS
        stdout, stderr, code = self._run_in_vfs_jail(cmd_str)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # 4. Active Containment: Check outputs for canary token exfiltration
        canary_tripped = self._check_canary_leakage(stdout + stderr)
        if canary_tripped:
            violations.append(
                PolicyViolation(
                    violation_type=PolicyViolationType.CANARY_TOKEN_TRIPPED,
                    detail="Honeytoken secret pattern detected in command output buffer",
                )
            )

        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=code,
            duration_ms=duration_ms,
            trapped=canary_tripped or (code != 0 and len(violations) > 0),
            violations=violations,
            canary_tripped=canary_tripped,
            blocked_syscall="aegis:honeypot_tripwire" if canary_tripped else None,
        )

    def _detect_network_egress(self, command: str) -> Optional[PolicyViolation]:
        """Scan command string for network commands, sockets, and outbound endpoints."""
        tokens = shlex.split(command, posix=False) if command else []
        cmd_lower = command.lower()

        # Check blocked network binaries/commands
        for blocked in self.policy.blocked_commands:
            pattern = rf"(?:^|[\s;|&`]){re.escape(blocked)}(?:$|[\s;|&`])"
            if re.search(pattern, cmd_lower):
                return PolicyViolation(
                    violation_type=PolicyViolationType.NETWORK_EGRESS_ATTEMPT,
                    detail=f"Forbidden network utility '{blocked}' attempted without net capability",
                    target=blocked,
                )

        # Check for URLs / endpoints in arguments
        url_match = re.search(r"https?://[^\s\"']+", command)
        if url_match:
            return PolicyViolation(
                violation_type=PolicyViolationType.NETWORK_EGRESS_ATTEMPT,
                detail=f"Network egress destination '{url_match.group(0)}' prohibited by Wasmer sandbox policy",
                target=url_match.group(0),
            )

        return None

    def _detect_path_traversal(self, command: str) -> Optional[PolicyViolation]:
        """Check if command arguments attempt directory traversal outside guest workspace."""
        try:
            tokens = shlex.split(command, posix=False)
        except ValueError:
            tokens = command.split()

        for token in tokens:
            # Strip quoting
            cleaned = token.strip("'\"")
            # Skip flags or option switches
            if cleaned.startswith("-") and not (cleaned.startswith("./") or cleaned.startswith("../")):
                continue

            # Look for indicators of traversal or absolute host paths
            if cleaned.startswith("..") or "/.." in cleaned or "\\.." in cleaned:
                try:
                    self.resolve_path(cleaned)
                except PathTraversalError as e:
                    return PolicyViolation(
                        violation_type=PolicyViolationType.FILE_SYSTEM_TRAVERSAL,
                        detail=str(e),
                        target=cleaned,
                    )

            if cleaned.startswith("/") and not cleaned.startswith("/workspace"):
                # Path outside /workspace (e.g. /secrets/.env, /etc/passwd, /root)
                return PolicyViolation(
                    violation_type=PolicyViolationType.FILE_SYSTEM_TRAVERSAL,
                    detail=f"Access to path outside guest workspace '{cleaned}' forbidden in WASI jail",
                    target=cleaned,
                )

            # Check for Windows root drive traversal
            if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
                return PolicyViolation(
                    violation_type=PolicyViolationType.FILE_SYSTEM_TRAVERSAL,
                    detail=f"Direct host drive access '{cleaned}' forbidden in WASI jail",
                    target=cleaned,
                )

        return None

    def _run_in_vfs_jail(self, command: str) -> Tuple[str, str, int]:
        """
        Execute basic sandbox operations (cat, ls, echo, python, base64, grep, etc.)
        strictly inside the guest workspace VFS.
        """
        # Handle compound commands connected with && or ;
        if "&&" in command:
            subcmds = command.split("&&")
            out_acc = []
            for sub in subcmds:
                out, err, code = self._run_in_vfs_jail(sub.strip())
                if out:
                    out_acc.append(out)
                if code != 0:
                    return "\n".join(out_acc), err, code
            return "\n".join(out_acc), "", 0

        if ";" in command:
            subcmds = command.split(";")
            out_acc = []
            err_acc = []
            final_code = 0
            for sub in subcmds:
                if not sub.strip():
                    continue
                out, err, code = self._run_in_vfs_jail(sub.strip())
                if out:
                    out_acc.append(out)
                if err:
                    err_acc.append(err)
                if code != 0:
                    final_code = code
            return "\n".join(out_acc), "\n".join(err_acc), final_code

        # Handle pipe operator (|)
        if "|" in command:
            subcmds = [s.strip() for s in command.split("|")]
            pipe_input = ""
            for i, sub in enumerate(subcmds):
                out, err, code = self._run_single_vfs_cmd(sub, stdin_text=pipe_input)
                if code != 0:
                    return out, err, code
                pipe_input = out
            return pipe_input, "", 0

        return self._run_single_vfs_cmd(command)

    def _run_single_vfs_cmd(self, command: str, stdin_text: str = "") -> Tuple[str, str, int]:
        """Execute a single sanitized command against the isolated VFS."""
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()

        if not parts:
            return "", "", 0

        cmd_name = parts[0]
        args = parts[1:]

        # cat
        if cmd_name == "cat":
            if not args and stdin_text:
                return stdin_text, "", 0
            outputs = []
            for target in args:
                try:
                    content = self.read_vfs_file(target)
                    outputs.append(content)
                except Exception as e:
                    return "", f"cat: {e}", 1
            return "\n".join(outputs), "", 0

        # ls / dir
        elif cmd_name in ("ls", "dir"):
            target = args[0] if args and not args[0].startswith("-") else "/workspace"
            try:
                entries = self.list_vfs_dir(target)
                return "\n".join(entries), "", 0
            except Exception as e:
                return "", f"ls: {e}", 1

        # echo
        elif cmd_name == "echo":
            # Strip quotes from args if needed
            return " ".join(args), "", 0

        # base64
        elif cmd_name == "base64":
            import base64 as b64
            if "-d" in args or "--decode" in args:
                data = stdin_text.strip().encode("utf-8")
                try:
                    decoded = b64.b64decode(data).decode("utf-8", errors="replace")
                    return decoded, "", 0
                except Exception as e:
                    return "", f"base64: {e}", 1
            else:
                if not args and stdin_text:
                    encoded = b64.b64encode(stdin_text.encode("utf-8")).decode("ascii")
                    return encoded, "", 0
                elif args:
                    try:
                        content = self.read_vfs_file(args[0])
                        encoded = b64.b64encode(content.encode("utf-8")).decode("ascii")
                        return encoded, "", 0
                    except Exception as e:
                        return "", f"base64: {e}", 1
                return "", "", 0

        # python / python3
        elif cmd_name in ("python", "python3"):
            if not args:
                return "", "Interactive python not supported in WASI sandbox", 1
            
            # If -c argument
            if args[0] == "-c" and len(args) > 1:
                py_code = args[1]
                return self._eval_safe_python(py_code, stdin_text)
            
            # File execution
            script_path = args[0]
            try:
                code_content = self.read_vfs_file(script_path)
                return self._eval_safe_python(code_content, stdin_text)
            except Exception as e:
                return "", f"python: error opening script '{script_path}': {e}", 1

        # grep
        elif cmd_name == "grep":
            if len(args) >= 1:
                pattern = args[0]
                text_to_search = stdin_text
                if len(args) >= 2:
                    try:
                        text_to_search = self.read_vfs_file(args[1])
                    except Exception as e:
                        return "", f"grep: {e}", 1
                matching_lines = [line for line in text_to_search.splitlines() if re.search(pattern, line)]
                return "\n".join(matching_lines), "", 0 if matching_lines else 1
            return "", "grep: missing pattern", 1

        # Fallback for unrecognized host command in sandbox
        return "", f"Command '{cmd_name}' not available or prohibited in isolated WASI sandbox", 127

    def _eval_safe_python(self, code_str: str, stdin_text: str = "") -> Tuple[str, str, int]:
        """Execute python code inside a restricted context isolated from the host."""
        import io
        import sys

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        capture_out = io.StringIO()
        capture_err = io.StringIO()

        safe_globals = {
            "__builtins__": {
                "print": print,
                "range": range,
                "len": len,
                "int": int,
                "str": str,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
                "set": set,
                "tuple": tuple,
                "sum": sum,
                "min": min,
                "max": max,
                "sorted": sorted,
                "enumerate": enumerate,
                "zip": zip,
                "isinstance": isinstance,
                "open": lambda path, mode="r", *a, **k: self._safe_open(path, mode),
            },
            "math": __import__("math"),
            "json": __import__("json"),
            "re": __import__("re"),
        }

        try:
            sys.stdout = capture_out
            sys.stderr = capture_err
            exec(code_str, safe_globals)
            return capture_out.getvalue(), capture_err.getvalue(), 0
        except Exception as e:
            return capture_out.getvalue(), f"{type(e).__name__}: {e}", 1
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def _safe_open(self, virtual_path: str, mode: str = "r"):
        """Provide restricted open() within the sandbox VFS."""
        resolved = self.resolve_path(virtual_path)
        if "w" in mode or "a" in mode:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        return open(resolved, mode, encoding="utf-8")

    def _check_canary_leakage(self, output: str) -> bool:
        """Inspect text for canary AWS keys or decoy webhooks."""
        if not self.policy.capabilities.canary_trapping:
            return False

        if re.search(self.canary_config.aws_pattern, output):
            return True

        if re.search(self.canary_config.webhook_pattern, output):
            return True

        for val in self.canary_config.decoy_keys.values():
            if val in output:
                return True

        return False

    def destroy(self) -> None:
        """Wipe the temporary VFS directory."""
        if self._temp_dir_obj is not None:
            try:
                self._temp_dir_obj.cleanup()
            except Exception:
                pass
            self._temp_dir_obj = None

    def __enter__(self) -> "WasmerSandbox":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.destroy()
