FROM python:3.14.8-slim-bookworm@sha256:c8137f4c460908c8763f281c8f22c431eb5c538514ba9553fc3a89c06b7cfb88

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN groupadd --gid 10001 reconstructor \
    && useradd --uid 10001 --gid reconstructor --no-create-home --shell /usr/sbin/nologin reconstructor

COPY --chown=10001:10001 src/ ./src/
COPY --chown=10001:10001 datasets/ ./datasets/

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=2).read()"]

CMD ["python", "-m", "cloud_breach_reconstructor", "serve", "--host", "0.0.0.0", "--port", "8080"]
