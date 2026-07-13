from __future__ import annotations

"""Startup recovery helpers (Step 8).

Accepted spool entries are retried by CaptureWorker automatically.
Messages stuck in `commands/processing` or `captures/processing` after a
crash should be moved back to `ready/` — implement when hardening.
"""

from app.spool.mta_spool import FilesystemSpoolStore

__all__ = ["FilesystemSpoolStore"]
