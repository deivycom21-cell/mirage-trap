# mirage-trap container. Data (world, telemetry, SSH host keys, token) lives in /data.
#
#   docker build -t mirage-trap .
#   docker run -d --name mirage -p 80:8080 -p 22:2222 -p 23:2323 -v mirage-data:/data mirage-trap
#
# See docker-compose.yml for the trap + dashboard pair.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE config.example.toml ./
COPY mirage_trap ./mirage_trap
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /wheels

FROM python:3.12-slim
LABEL org.opencontainers.image.title="mirage-trap" \
      org.opencontainers.image.description="High-interaction deception honeypot (HTTP, SSH, Telnet)" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MIRAGE_STORAGE__DATA_DIR=/data \
    MIRAGE_SERVER__HOST=0.0.0.0 \
    MIRAGE_PROFILE=nginx-php-legacy
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl "maxminddb>=2.5" && rm -rf /wheels \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin mirage \
 && mkdir -p /data && chown mirage:mirage /data
USER mirage
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080 2222 2323
# First start: write /data/config.toml, generate the world, keys and dashboard token.
ENTRYPOINT ["/bin/sh", "-c", "[ -f /data/config.toml ] || mirage-trap --config /data/config.toml init --profile \"$MIRAGE_PROFILE\"; exec mirage-trap --config /data/config.toml \"$@\"", "--"]
CMD ["run"]
