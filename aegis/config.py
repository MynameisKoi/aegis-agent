"""Configuration settings and capability definitions for AegisAgent."""

from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ExecutionMode(str, Enum):
    """Runtime execution mode."""
    UNPROTECTED = "unprotected"  # Native host subprocess (vulnerable baseline)
    AEGIS = "aegis"              # Wasmer/WASI runtime containment sandbox


class NetworkPolicy(str, Enum):
    """Network egress policy."""
    DENY_ALL = "deny_all"
    ALLOW_ALL = "allow_all"


class SandboxCapability(BaseModel):
    """Defines granted vs restricted execution capabilities within a WASI sandbox."""
    allow_net: bool = Field(default=False, description="Whether guest can initiate network connections")
    allow_env: bool = Field(default=False, description="Whether host environment variables are passed to guest")
    allow_subprocesses: bool = Field(default=False, description="Whether guest can spawn sub-processes")
    read_only_root: bool = Field(default=True, description="Enforce read-only root VFS outside guest workspace")
    guest_workspace: str = Field(default="/workspace", description="Mount point inside the guest for working directory")
    timeout_seconds: float = Field(default=5.0, description="Max execution duration before preemptive kill")
    memory_limit_mb: int = Field(default=64, description="Memory ceiling in megabytes")
    fuel_limit: int = Field(default=500_000_000, description="WASI execution fuel / instruction limit")
    canary_trapping: bool = Field(default=True, description="Enable active honeytoken tripping and decoy interception")


class CanaryConfig(BaseModel):
    """Configuration for canary credentials and honeypot tripwires."""
    aws_pattern: str = r"AKIA[0-9A-Z]{16}"
    webhook_pattern: str = r"https?://(?:webhook\.site|canarytokens\.org|attacker\.invalid)[^\s\"'<>]*"
    decoy_env_filename: str = ".env"
    decoy_keys: Dict[str, str] = Field(default_factory=lambda: {
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "DATABASE_URL": "postgres://aegis_admin:h0n3yp0t_s3cr3t@prod-db.internal:5432/core_prod",
        "EXFILTRATION_ENDPOINT": "https://webhook.site/test-canary-uuid-exfil",
        "OPENAI_API_KEY": "sk-proj-CANARYTOKEN1234567890abcdefghijklmnopqrstuvwxyz",
    })


class AegisSettings(BaseModel):
    """Global system configuration for AegisAgent."""
    default_mode: ExecutionMode = ExecutionMode.AEGIS
    sandbox_policy: SandboxCapability = Field(default_factory=SandboxCapability)
    canary_config: CanaryConfig = Field(default_factory=CanaryConfig)
    workspace_root: Path = Field(default_factory=lambda: Path.cwd())
    log_level: str = "INFO"


# Global singleton instance with defaults
settings = AegisSettings()
