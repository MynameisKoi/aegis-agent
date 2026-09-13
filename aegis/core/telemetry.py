"""Phase 3: Structured Forensic Telemetry & Incident Reporting.

Handles dual-dispatch incident logging:
1. Local: Writes structured JSON incident payloads to disk.
2. Remote: Asynchronously streams events to the Tenki Cloud SIEM endpoint.
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from aegis.core.policy import PolicyViolation, PolicyViolationType

logger = logging.getLogger(__name__)

# Default Tenki Cloud SIEM endpoint (can be overridden via AEGIS_TENKI_ENDPOINT env var)
DEFAULT_TENKI_ENDPOINT = os.getenv(
    "AEGIS_TENKI_ENDPOINT", "http://localhost:8080/api/telemetry/ingest"
)
LOCAL_INCIDENT_LOG = Path("aegis_incidents.jsonl")


class IncidentSeverity(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ForensicIncident(BaseModel):
    """Structured forensic incident payload emitted when a sandbox security event fires."""
    incident_id: str = Field(default_factory=lambda: f"INC-{int(time.time() * 1000)}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str = IncidentSeverity.HIGH
    mode: str = "aegis"
    violations: List[PolicyViolation] = Field(default_factory=list)
    blocked_syscall: Optional[str] = None
    trapped_command: Optional[str] = None
    stdout_excerpt: Optional[str] = None
    stderr_excerpt: Optional[str] = None
    canary_tripped: bool = False
    canary_keys_leaked: List[str] = Field(default_factory=list)
    injection_payload_detected: Optional[str] = None
    sandbox_exit_code: int = 0
    duration_ms: float = 0.0
    extra: Dict[str, Any] = Field(default_factory=dict)

    def to_json(self) -> str:
        return self.model_dump_json()

    @property
    def is_critical(self) -> bool:
        return (
            self.canary_tripped
            or self.severity == IncidentSeverity.CRITICAL
            or any(v.violation_type == PolicyViolationType.CANARY_TOKEN_TRIPPED for v in self.violations)
        )


class TelemetryDispatcher:
    """
    Dual-dispatch telemetry: local JSONL log + async HTTP to the Tenki Cloud SIEM API.
    Thread-safe for concurrent sandbox traps.
    """

    def __init__(
        self,
        tenki_endpoint: str = DEFAULT_TENKI_ENDPOINT,
        local_log_path: Path = LOCAL_INCIDENT_LOG,
        stream_to_cloud: bool = True,
    ):
        self.tenki_endpoint = tenki_endpoint
        self.local_log_path = local_log_path
        self.stream_to_cloud = stream_to_cloud
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def emit(self, incident: ForensicIncident) -> None:
        """
        Save the incident locally (blocking) and fire-and-forget to the Tenki Cloud
        SIEM endpoint (non-blocking background thread).
        """
        self._save_local(incident)

        if self.stream_to_cloud:
            t = threading.Thread(
                target=self._stream_to_tenki,
                args=(incident,),
                daemon=True,
                name=f"aegis-telemetry-{incident.incident_id}",
            )
            t.start()

        level = logging.CRITICAL if incident.is_critical else logging.WARNING
        logger.log(
            level,
            "[AEGIS_TELEMETRY] %s | severity=%s | syscall=%s | canary=%s",
            incident.incident_id,
            incident.severity,
            incident.blocked_syscall or "N/A",
            incident.canary_tripped,
        )

    # ------------------------------------------------------------------
    # Local persistence
    # ------------------------------------------------------------------

    def _save_local(self, incident: ForensicIncident) -> None:
        """Append the incident JSON to the local JSONL audit log."""
        with self._lock:
            try:
                with open(self.local_log_path, "a", encoding="utf-8") as f:
                    f.write(incident.to_json() + "\n")
            except OSError as e:
                logger.error("Failed to write local incident log: %s", e)

    # ------------------------------------------------------------------
    # Tenki Cloud SIEM dispatch
    # ------------------------------------------------------------------

    def _stream_to_tenki(self, incident: ForensicIncident) -> None:
        """
        POST the structured forensic incident to the Tenki Cloud SIEM ingest endpoint.
        Silently fails if the endpoint is unreachable (graceful offline degradation).
        """
        payload_bytes = incident.to_json().encode("utf-8")
        req = urllib.request.Request(
            url=self.tenki_endpoint,
            data=payload_bytes,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Aegis-Version": "0.1.0",
                "X-Incident-ID": incident.incident_id,
                "X-Severity": incident.severity,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.getcode()
                logger.debug(
                    "[TENKI_CLOUD] Incident %s delivered → HTTP %s",
                    incident.incident_id,
                    status,
                )
        except urllib.error.URLError as e:
            logger.debug(
                "[TENKI_CLOUD] Endpoint unreachable (offline mode): %s", e.reason
            )
        except Exception as e:
            logger.debug("[TENKI_CLOUD] Delivery error: %s", e)

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    def incident_from_sandbox_result(
        self,
        sandbox_result: Any,
        original_command: Optional[str] = None,
    ) -> ForensicIncident:
        """Build a ForensicIncident from an ExecutionResult returned by WasmerSandbox."""
        severity = IncidentSeverity.LOW
        if sandbox_result.canary_tripped:
            severity = IncidentSeverity.CRITICAL
        elif sandbox_result.trapped:
            severity = IncidentSeverity.HIGH
        elif sandbox_result.violations:
            severity = IncidentSeverity.MEDIUM

        canary_keys: List[str] = [
            v.detail for v in sandbox_result.violations
            if v.violation_type == PolicyViolationType.CANARY_TOKEN_TRIPPED
        ]

        return ForensicIncident(
            severity=severity,
            violations=sandbox_result.violations,
            blocked_syscall=sandbox_result.blocked_syscall,
            trapped_command=original_command,
            stdout_excerpt=sandbox_result.stdout[:500] if sandbox_result.stdout else None,
            stderr_excerpt=sandbox_result.stderr[:500] if sandbox_result.stderr else None,
            canary_tripped=sandbox_result.canary_tripped,
            canary_keys_leaked=canary_keys,
            sandbox_exit_code=sandbox_result.exit_code,
            duration_ms=sandbox_result.duration_ms,
        )


# Global singleton dispatcher
_dispatcher: Optional[TelemetryDispatcher] = None


def get_dispatcher(
    tenki_endpoint: str = DEFAULT_TENKI_ENDPOINT,
    stream_to_cloud: bool = True,
) -> TelemetryDispatcher:
    """Get or initialize the global telemetry dispatcher."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = TelemetryDispatcher(
            tenki_endpoint=tenki_endpoint,
            stream_to_cloud=stream_to_cloud,
        )
    return _dispatcher
