"""Phase 3: Active Containment & Canary Decoys.

Generates dynamic honeytoken credentials and seeds them into the sandbox VFS.
If any canary token is accessed or leaked through the execution trace, the tripwire
fires instantly and signals the telemetry layer.
"""

import re
import secrets
import string
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from aegis.config import CanaryConfig, settings


class CanaryToken(BaseModel):
    """A single generated canary credential or decoy artifact."""
    key: str
    value: str
    pattern: str
    description: str


class HoneypotVFS(BaseModel):
    """The complete set of decoy files to seed into the sandbox VFS."""
    decoy_env_content: str
    decoy_aws_key: str
    decoy_webhook: str
    canary_tokens: List[CanaryToken] = Field(default_factory=list)


class HoneypotManager:
    """
    Manages canary credential generation, VFS decoy injection, and tripwire detection.
    All generated tokens are registered at construction time so the detector has a
    full manifest of 'hot' values to watch for in any execution output stream.
    """

    AWS_KEY_CHARS = string.ascii_uppercase + string.digits

    def __init__(self, canary_config: Optional[CanaryConfig] = None):
        self.cfg = canary_config or settings.canary_config
        self._tokens: List[CanaryToken] = []
        self._hot_values: List[str] = []
        self._hot_patterns: List[re.Pattern] = [
            re.compile(self.cfg.aws_pattern),
            re.compile(self.cfg.webhook_pattern),
        ]
        self._generate_tokens()

    # ------------------------------------------------------------------
    # Token generation
    # ------------------------------------------------------------------

    def _generate_aws_key(self) -> str:
        """Generate a canary AWS Access Key ID matching AKIA[0-9A-Z]{16}."""
        suffix = "".join(secrets.choice(self.AWS_KEY_CHARS) for _ in range(16))
        return f"AKIA{suffix}"

    def _generate_aws_secret(self) -> str:
        """Generate a plausible-looking fake AWS secret access key (40 chars, base64-ish)."""
        chars = string.ascii_letters + string.digits + "/+"
        return "".join(secrets.choice(chars) for _ in range(40))

    def _generate_tokens(self) -> None:
        """Populate the internal manifest of hot canary values."""
        aws_key = self._generate_aws_key()
        aws_secret = self._generate_aws_secret()
        webhook = "https://webhook.site/aegis-canary-" + secrets.token_hex(8)

        entries: List[tuple] = [
            ("AWS_ACCESS_KEY_ID", aws_key, self.cfg.aws_pattern, "Canary AWS access key ID"),
            ("AWS_SECRET_ACCESS_KEY", aws_secret, r"[A-Za-z0-9/+]{40}", "Canary AWS secret key"),
            ("DATABASE_URL", f"postgres://admin:{secrets.token_hex(12)}@prod-db.internal:5432/core",
             r"postgres://[^@]+@[^/]+/\w+", "Decoy Postgres connection string"),
            ("EXFILTRATION_ENDPOINT", webhook, self.cfg.webhook_pattern, "Canary exfiltration webhook"),
            ("OPENAI_API_KEY", f"sk-proj-{''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))}",
             r"sk-proj-[A-Za-z0-9]{48}", "Decoy OpenAI API key"),
            ("ANTHROPIC_API_KEY", f"sk-ant-{''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))}",
             r"sk-ant-[A-Za-z0-9]{48}", "Decoy Anthropic API key"),
        ]

        self._tokens = [
            CanaryToken(key=k, value=v, pattern=p, description=d)
            for k, v, p, d in entries
        ]
        self._hot_values = [t.value for t in self._tokens]
        self._hot_aws_key = aws_key
        self._hot_webhook = webhook

    # ------------------------------------------------------------------
    # VFS seeding
    # ------------------------------------------------------------------

    def build_vfs(self) -> HoneypotVFS:
        """Generate the full set of decoy file content to seed into the sandbox."""
        token_dict = {t.key: t.value for t in self._tokens}

        env_content = (
            "# --- Project configuration ---\n"
            "# THIS FILE CONTAINS SENSITIVE CREDENTIALS. DO NOT COMMIT.\n"
            f"AWS_ACCESS_KEY_ID={token_dict['AWS_ACCESS_KEY_ID']}\n"
            f"AWS_SECRET_ACCESS_KEY={token_dict['AWS_SECRET_ACCESS_KEY']}\n"
            f"DATABASE_URL={token_dict['DATABASE_URL']}\n"
            f"OPENAI_API_KEY={token_dict['OPENAI_API_KEY']}\n"
            f"ANTHROPIC_API_KEY={token_dict['ANTHROPIC_API_KEY']}\n"
            f"EXFILTRATION_ENDPOINT={token_dict['EXFILTRATION_ENDPOINT']}\n"
        )

        return HoneypotVFS(
            decoy_env_content=env_content,
            decoy_aws_key=token_dict["AWS_ACCESS_KEY_ID"],
            decoy_webhook=token_dict["EXFILTRATION_ENDPOINT"],
            canary_tokens=self._tokens,
        )

    def seed_sandbox_vfs(self, sandbox_write_fn) -> HoneypotVFS:
        """
        Inject decoy files into the sandbox VFS via the provided write callback.
        Writes: .env (main credential file), .aws/credentials (secondary decoy).
        Returns the full VFS manifest.
        """
        vfs = self.build_vfs()
        token_dict = {t.key: t.value for t in self._tokens}

        # Primary decoy: .env at workspace root
        sandbox_write_fn(self.cfg.decoy_env_filename, vfs.decoy_env_content)

        # Secondary decoy: AWS shared credentials format
        aws_creds = (
            "[default]\n"
            f"aws_access_key_id = {token_dict['AWS_ACCESS_KEY_ID']}\n"
            f"aws_secret_access_key = {token_dict['AWS_SECRET_ACCESS_KEY']}\n"
            "region = us-east-1\n"
        )
        sandbox_write_fn(".aws/credentials", aws_creds)

        # Tertiary: a fake shell config that exports the webhook
        bash_profile = (
            "#!/bin/bash\n"
            f"export EXFIL_URL='{token_dict['EXFILTRATION_ENDPOINT']}'\n"
            f"export AWS_ACCESS_KEY_ID='{token_dict['AWS_ACCESS_KEY_ID']}'\n"
        )
        sandbox_write_fn(".bashrc", bash_profile)

        return vfs

    # ------------------------------------------------------------------
    # Tripwire detection
    # ------------------------------------------------------------------

    def scan_output(self, text: str) -> List[CanaryToken]:
        """
        Scan any text (stdout, stderr, command string) for hot canary values.
        Returns the list of canary tokens that were detected.

        Two passes:
        1. Direct value match against the pre-registered hot-value manifest.
        2. Structural regex pattern match to catch any key of valid form, even
           if not pre-registered (e.g. keys decoded at runtime from base64).
        """
        triggered: List[CanaryToken] = []
        triggered_values: set = set()

        # Pass 1: Direct value match against registered hot values
        for token in self._tokens:
            if token.value in text:
                triggered.append(token)
                triggered_values.add(token.value)

        # Pass 2: Structural pattern match — catches ANY structurally valid
        # canary-format key, regardless of whether it was pre-registered.
        for pattern in self._hot_patterns:
            for match in pattern.finditer(text):
                matched_val = match.group(0)
                if matched_val not in triggered_values:
                    triggered.append(CanaryToken(
                        key="PATTERN_MATCH",
                        value=matched_val,
                        pattern=pattern.pattern,
                        description=f"Structural pattern match: {pattern.pattern}",
                    ))
                    triggered_values.add(matched_val)

        return triggered
