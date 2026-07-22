"""Backend-only DLP lifecycle values.

These are intentionally separate from gateway spool/relay states.
"""

from enum import Enum


class ProcessingState(str, Enum):
    RECEIVED = "received"
    EXTRACTING = "extracting"
    EXTRACTED = "extracted"
    CLASSIFYING = "classifying"
    CLASSIFIED = "classified"
    EVALUATING = "evaluating"
    DECIDED = "decided"
    FAILED = "failed"


class TenantMode(str, Enum):
    MONITOR = "monitor"
    ENFORCE = "enforce"
