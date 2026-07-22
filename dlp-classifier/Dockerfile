FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates tar \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/install_betterleaks.sh ./scripts/install_betterleaks.sh
RUN chmod +x ./scripts/install_betterleaks.sh \
    && ./scripts/install_betterleaks.sh

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY config ./config

RUN useradd --create-home --uid 10001 dlp \
    && chown -R dlp:dlp /app

USER dlp

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
