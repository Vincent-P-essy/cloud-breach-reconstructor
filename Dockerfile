FROM python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576

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
