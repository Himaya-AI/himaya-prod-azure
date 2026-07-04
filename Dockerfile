FROM python:3.12-slim

WORKDIR /app

# System deps + Chromium for URL detonation (Playwright)
# chromium is installed as a system package to avoid QEMU/JIT issues during cross-compilation.
# Playwright is configured to use the system Chromium binary at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libpq-dev \
    chromium chromium-driver \
    fonts-liberation fonts-noto-color-emoji \
    libnss3 libatk-bridge2.0-0 libdrm2 libxcomposite1 libxdamage1 \
    libxrandr2 libgbm1 libxkbcommon0 libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Backend requirements only (no heavy ML/torch — those run on SageMaker)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Playwright Python package — uses system Chromium (set via PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH)
RUN pip install --no-cache-dir playwright==1.44.0

ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# Copy app code
COPY backend/ ./backend/
COPY models/shared/ ./models/shared/
COPY models/content_classifier/ ./models/content_classifier/
COPY models/risk_orchestrator/ ./models/risk_orchestrator/
COPY models/sender_reputation/ ./models/sender_reputation/
COPY models/__init__.py ./models/__init__.py

EXPOSE 8000

# NOTE: --workers 1 is required because background tasks (delta_sync, draft_scan, spam_sync,
# saas_security_loop) are started in startup events and would duplicate with multiple workers.
# For horizontal scaling, use ECS service desired_count instead of uvicorn workers.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
