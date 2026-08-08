# Himaya automated detonation image.
# Base = official Playwright Python (Chromium + all browser deps preinstalled),
# layered with open-source static-analysis tooling for extracting signals from
# email attachments and URLs inside an ephemeral, network-isolated ACI container.
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# ── OSS analysis tooling ──────────────────────────────────────────────────────
#   yara            - signature scanning
#   clamav          - antivirus engine + signature DB
#   p7zip/unzip/unar- archive listing & extraction (incl. encrypted detection)
#   exiftool        - document/image metadata
#   poppler-utils   - pdftotext / pdfinfo
#   libmagic/file   - content type detection
#   binutils        - strings
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    clamav clamav-freshclam \
    p7zip-full unzip unar \
    libimage-exiftool-perl \
    poppler-utils \
    libmagic1 file \
    binutils \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Bake the ClamAV signature DB into the image so detonation is fast and needs no
# network for AV (freshclam may rate-limit in CI — never fail the build on it).
RUN mkdir -p /var/lib/clamav && (freshclam --quiet || true)

# Python analysis libraries
RUN pip install --no-cache-dir \
    "oletools==0.60.2" \
    "yara-python==4.5.1" \
    "python-magic==0.4.27"

# ── Detonation harness + YARA rules ──────────────────────────────────────────
COPY analyze.py /opt/detonator/analyze.py
COPY rules/ /opt/detonator/rules/

WORKDIR /opt/detonator
CMD ["python", "analyze.py"]
