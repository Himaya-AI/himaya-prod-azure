"""HTTP schemas for the DLP v2 control plane."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class DlpStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["disabled", "ready"]
    pipeline_enabled: bool
    mode: Literal["monitor", "enforce"]
    classifier_url_configured: bool
    legacy_independent: bool = True
