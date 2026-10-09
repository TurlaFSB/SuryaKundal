# syntax=docker/dockerfile:1
#
# Surya Kundal: the Cowrie honeypot with the deception kit baked in.
#
# Build context is this directory (cowrie/). Cowrie is fetched at a pinned tag and the
# build fails if the tag does not point at the pinned commit, so a moved tag cannot slip
# different code into the image. The kit (deploy.sh and its overlays) runs at every start
# and keeps persona, host keys and boot time stable inside the state volume.

# --- build: Cowrie and its dependencies into a virtualenv ----------------------
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS build
ARG COWRIE_REF=v3.1.1
ARG COWRIE_COMMIT=c17c9b73d6af0972334ea1e90b20d974cb24eeca
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --quiet --depth 1 --branch "${COWRIE_REF}" https://github.com/cowrie/cowrie.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${COWRIE_COMMIT}"
RUN python -m venv /opt/cowrie-venv \
 && /opt/cowrie-venv/bin/pip install -r /src/requirements.txt /src
# Twisted caches its plugin list next to the plugins; build it now because the runtime
# filesystem is read-only and Cowrie would warn about it on every start.
RUN /opt/cowrie-venv/bin/python -c "from twisted.plugin import IPlugin, getPlugins; import twisted.plugins; list(getPlugins(IPlugin, twisted.plugins))"

# --- runtime ---------------------------------------------------------------------
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/cowrie-venv/bin:$PATH \
    COWRIE_VENV=/opt/cowrie-venv \
    COWRIE_STDOUT=yes \
    COWRIE_POLICY=collect
# openssl: password hashes for the fake /etc/shadow. openssh-client: ssh-keygen for host keys.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10002 cowrie \
 && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /cowrie --shell /usr/sbin/nologin cowrie \
 && mkdir -p /cowrie/etc /cowrie/var/log/cowrie /cowrie/var/lib/cowrie/tty /cowrie/var/lib/cowrie/downloads /cowrie/var/run \
 && chown -R 10002:10002 /cowrie
COPY --from=build /opt/cowrie-venv /opt/cowrie-venv
COPY . /opt/kit
RUN chmod 0755 /opt/kit/deploy.sh /opt/kit/docker-entrypoint.sh /opt/kit/healthcheck.py
WORKDIR /cowrie
USER 10002:10002
EXPOSE 2222
VOLUME ["/cowrie"]
ENTRYPOINT ["/opt/kit/docker-entrypoint.sh"]
CMD ["start"]
