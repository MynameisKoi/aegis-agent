"""Security policies and capability enforcement manifests for AegisAgent."""

from enum import Enum
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

from aegis.config import SandboxCapability


class PolicyViolationType(str, Enum):
    """Types of security policy violations caught at the sandbox boundary."""
    FILE_SYSTEM_TRAVERSAL = "FILE_SYSTEM_TRAVERSAL"
    NETWORK_EGRESS_ATTEMPT = "NETWORK_EGRESS_ATTEMPT"
    HOST_ENV_LEAK_ATTEMPT = "HOST_ENV_LEAK_ATTEMPT"
    CANARY_TOKEN_TRIPPED = "CANARY_TOKEN_TRIPPED"
    TIMEOUT_EXCEEDED = "TIMEOUT_EXCEEDED"
    MEMORY_LIMIT_EXCEEDED = "MEMORY_LIMIT_EXCEEDED"
    UNAUTHORIZED_SYSCALL = "UNAUTHORIZED_SYSCALL"


class PolicyViolation(BaseModel):
    """Structured record of a policy violation."""
    violation_type: PolicyViolationType
    detail: str
    target: Optional[str] = None
    timestamp: float = Field(default_factory=lambda: __import__("time").time())


class PathTraversalError(PermissionError):
    """Raised when an operation attempts directory traversal outside the sandbox jail."""
    def __init__(self, requested_path: str, reason: str = "Path traversal outside sandbox root forbidden"):
        super().__init__(f"{reason}: '{requested_path}'")
        self.requested_path = requested_path


class NetworkEgressBlockedError(PermissionError):
    """Raised when guest attempts prohibited socket creation or network egress."""
    def __init__(self, target_host: str = "unknown"):
        super().__init__(f"Network egress blocked by Wasmer capability policy: '{target_host}'")
        self.target_host = target_host


class SecurityPolicy(BaseModel):
    """Comprehensive security policy configuring WASI capability boundaries."""
    capabilities: SandboxCapability = Field(default_factory=SandboxCapability)
    allowed_virtual_roots: List[str] = Field(default_factory=lambda: ["/workspace", "/tmp"])
    read_only_paths: List[str] = Field(default_factory=list)
    blocked_commands: List[str] = Field(default_factory=lambda: [
        "curl", "wget", "nc", "netcat", "bash -i", "sh -i", "telnet", "ssh", "ncat", "socat"
    ])

    def resolve_sandbox_path(self, virtual_path: str, host_workspace: Path) -> Path:
        """
        Deterministically resolve a guest virtual path (e.g. '/workspace/file.txt' or 'file.txt')
        to the isolated host workspace directory.
        
        Strictly forbids:
        - Parent directory traversal ('../') escaping host_workspace
        - Direct host drive or root traversal ('/', 'C:\\', '/etc', etc.)
        """
        norm_str = str(virtual_path).strip()

        # Disallow empty or null-byte paths
        if not norm_str or "\x00" in norm_str:
            raise PathTraversalError(norm_str, "Invalid or null-byte path")

        # Disallow raw Windows drive roots (e.g., C:\, D:\)
        if len(norm_str) >= 2 and norm_str[1] == ":" and norm_str[0].isalpha():
            raise PathTraversalError(norm_str, "Absolute host drive access is forbidden in WASI jail")

        # If path starts with /workspace, strip the guest mount prefix
        if norm_str.startswith("/workspace/"):
            rel_str = norm_str[len("/workspace/"):]
        elif norm_str == "/workspace":
            rel_str = ""
        elif norm_str.startswith("/"):
            # Guest absolute path outside /workspace (e.g. /etc/passwd, /secrets/.env)
            # In WASI, paths outside mapped directories do not exist or violate root jail
            raise PathTraversalError(norm_str, "Access to host root '/' or unmapped VFS path is forbidden")
        else:
            rel_str = norm_str

        # Resolve relative to host_workspace
        resolved = (host_workspace / rel_str).resolve()
        host_workspace_resolved = host_workspace.resolve()

        # Ensure the resolved path is strictly within host_workspace
        try:
            resolved.relative_to(host_workspace_resolved)
        except ValueError:
            raise PathTraversalError(norm_str, "Path traversal ('../') escapes sandbox workspace")

        return resolved


# Default pre-configured policies
STRICT_SANDBOX_POLICY = SecurityPolicy(capabilities=SandboxCapability(allow_net=False, allow_env=False))
