from __future__ import annotations

from app.config import Settings


class TrustPolicy:
    """SMTP trust checks. Local mode is permissive for Docker testing."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def allow_peer(self, peer: str | None) -> bool:
        if self.settings.is_local:
            return True
        # Production: restrict to provider egress IP ranges / connector identity.
        return peer is not None
