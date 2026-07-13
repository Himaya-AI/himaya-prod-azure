FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY conf ./conf
COPY scripts ./scripts

RUN mkdir -p /var/dlp/spool /var/dlp/data /var/dlp/queues \
    && useradd --create-home --uid 10001 dlp \
    && chown -R dlp:dlp /var/dlp /app

USER dlp

EXPOSE 2525 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "-m", "app.main"]
