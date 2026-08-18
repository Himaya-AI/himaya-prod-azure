"""
File-type adapter for the DLP classification engine.

Why this exists
---------------
The dlp-classifier service is a TEXT/NER classifier — it extracts entities
(PERSON, EMAIL, CREDIT_CARD, ...) from document text. Feeding it a binary /
executable and mapping a stray ``PERSON`` hit to ``pii_person`` is a false
positive: a WildFire *test malware* APK (``wildfire-test-apk-file.apk``) was
being tagged ``pii_person`` / "confidential" instead of being flagged as an
executable that belongs in a malware-scan pipeline.

This adapter classifies by file type FIRST. Binaries / executables / archives
never go through the PII text path — they get an ``executable`` / ``archive``
category, and known malware-test artifacts (WildFire, EICAR) get ``malware``.
Normal documents return ``None`` so the caller falls back to the text/PII
classifier as before.
"""
from __future__ import annotations

import os
from typing import Optional

# Executables / installers / scripts — never carry PII by virtue of their name.
EXECUTABLE_EXTS = {
    ".exe", ".dll", ".msi", ".apk", ".ipa", ".app", ".dmg", ".pkg",
    ".deb", ".rpm", ".bin", ".com", ".scr", ".bat", ".cmd", ".ps1",
    ".sh", ".jar", ".war", ".msix", ".appx", ".elf", ".so", ".dylib",
    ".vbs", ".wsf", ".gadget", ".cpl", ".msc", ".run", ".out",
}

# Archives — opaque to the text classifier; contents may be anything.
ARCHIVE_EXTS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso",
    ".cab", ".tgz", ".tbz2", ".lz", ".lzma", ".z",
}

# Substrings that mark a KNOWN malware / AV test artifact.
MALWARE_TEST_MARKERS = (
    "wildfire", "eicar", "malware-test", "testmalware",
    "test-virus", "test-malware", "malware_test",
)

# A regex (Postgres ``~`` flavour, case-insensitive on lower()) matching any
# of the binary/archive extensions above. Kept in sync with the sets so the
# re-classification sweep and the Python adapter agree on what a "binary" is.
_ALL_BINARY_EXTS = sorted(
    e[1:] for e in (EXECUTABLE_EXTS | ARCHIVE_EXTS)
)
BINARY_EXT_REGEX = r"\.(" + "|".join(_ALL_BINARY_EXTS) + r")$"


def _ext(name: str) -> str:
    return os.path.splitext((name or "").strip().lower())[1]


def classify_file_type(name: str) -> Optional[dict]:
    """Return a deterministic file-type verdict for binaries, else ``None``.

    The verdict shape mirrors the dlp-classifier response so callers can use
    it interchangeably: ``{categories, risk_level, label, confidence, source,
    note}``. ``None`` means "this is a normal document — run the text/PII
    classifier".
    """
    n = (name or "").lower()
    ext = _ext(n)

    is_exec = ext in EXECUTABLE_EXTS
    is_archive = ext in ARCHIVE_EXTS
    if not (is_exec or is_archive):
        return None

    if any(m in n for m in MALWARE_TEST_MARKERS):
        return {
            "categories": ["malware", "executable"],
            "risk_level": "critical",
            "label": "highly_confidential",
            "confidence": 0.99,
            "source": "file_type_adapter",
            "note": (
                "Known malware/AV test artifact — routed to the malware "
                "category, NOT PII. Should be handled by the malware-scan "
                "pipeline."
            ),
        }

    if is_exec:
        return {
            "categories": ["executable"],
            "risk_level": "high",
            "label": "confidential",
            "confidence": 0.9,
            "source": "file_type_adapter",
            "note": (
                "Executable/installer/script — flagged for malware review; "
                "not PII-classified (binary content is opaque to the text "
                "classifier)."
            ),
        }

    return {
        "categories": ["archive"],
        "risk_level": "medium",
        "label": "confidential",
        "confidence": 0.7,
        "source": "file_type_adapter",
        "note": (
            "Archive — contents are opaque to the text classifier; unpack "
            "and scan before trusting any inner classification."
        ),
    }
