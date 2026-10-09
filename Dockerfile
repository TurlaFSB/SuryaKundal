# syntax=docker/dockerfile:1
#
# Surya Kundal: the analysis pipeline and the dashboard, in one small image.
# Cowrie itself runs separately; this image only reads its log.

ARG PYTHON_IMAGE=python:3.13-slim-bookworm

# --- build: turn the source into a wheel -------------------------------------
FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist

# --- runtime: wheel only, no compilers, no source, no root -------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATABASE_URL=sqlite:////data/surya_kundal.db \
    GEOIP_DB_DIR=/data/geoip \
    TOR_EXIT_LIST_PATH=/data/tor_exit_nodes.txt \
    WAZUH_ALERTS_PATH=/data/wazuh_alerts.jsonl \
    COWRIE_LOG_PATH=/cowrie-log/cowrie.json

# A fixed, unprivileged account. /data is created and owned before the VOLUME line, so a
# new named volume inherits that ownership.
RUN groupadd --system --gid 10001 surya \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin surya \
 && mkdir /data && chown 10001:10001 /data

COPY --from=build /dist/*.whl /tmp/wheel/
RUN pip install "$(ls /tmp/wheel/*.whl)[dashboard]" && rm -rf /tmp/wheel

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

# The default command runs the whole pipeline; compose overrides it for the dashboard.
ENTRYPOINT ["surya-kundal"]
CMD ["run"]
