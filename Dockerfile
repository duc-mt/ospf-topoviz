# syntax=docker/dockerfile:1.7
#
# OSPF TopoViz - production image for `main.py --serve` (embedded web server).
#
#   docker build -t ospf-topoviz .
#   docker run --rm -p 127.0.0.1:8080:8080 -v "$PWD/config:/app/config" -v "$PWD/data:/app/data" \
#              -v "$PWD/output:/app/output" ospf-topoviz
#
# Two stages: the first compiles/installs the Python dependencies with the build tools; the second is the
# runtime image - Graphviz, tzdata, the virtualenv and the code, with no compiler - running as an unprivileged
# user. Any other mode works too: `docker run ... ospf-topoviz --replay samples/vyos --dry-run`.

ARG PYTHON_VERSION=3.12

# ------------------------------------------------------------------------------------------------ builder
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Build tools for the dependencies that have no wheel for this platform (cryptography, psutil, lxml, ...).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# requirements.txt: loose pins that resolve on the image's Python. requirements.lock is pinned but was compiled
# with another Python version (see its header); use it with --build-arg REQUIREMENTS=requirements.lock only
# when it matches PYTHON_VERSION.
ARG REQUIREMENTS=requirements.txt
COPY requirements.txt requirements.lock ./
RUN pip install --upgrade pip && pip install -r "${REQUIREMENTS}"

# ------------------------------------------------------------------------------------------------ runtime
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="OSPF TopoViz" \
      org.opencontainers.image.description="OSPF topology visualizer, history and explorer web server" \
      org.opencontainers.image.licenses="MIT"

# graphviz: the "dot" binary the diagrams are drawn with; fonts-dejavu-core: without a font Graphviz draws no
# text on a slim image; tzdata: correct local times in reports and logs (set TZ).
RUN apt-get update \
    && apt-get install -y --no-install-recommends graphviz fonts-dejavu-core tzdata \
    && rm -rf /var/lib/apt/lists/*

# An unprivileged user with a fixed ID, so the bind-mounted folders can be given to it.
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --create-home --home-dir /home/appuser \
               --shell /usr/sbin/nologin appuser

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    HOME=/home/appuser \
    OSPF_MONITOR_HOST=0.0.0.0 \
    OSPF_MONITOR_PORT=8080

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser main.py ./
COPY --chown=appuser:appuser src ./src
COPY --chown=appuser:appuser samples ./samples
COPY --chown=appuser:appuser config/settings.yaml.example ./config/settings.yaml.example
RUN mkdir -p /app/config /app/data /app/output \
    && chown -R appuser:appuser /app/config /app/data /app/output

USER appuser

# State lives outside the image: settings (with credentials), the topology baseline + history, the diagrams.
VOLUME ["/app/config", "/app/data", "/app/output"]
EXPOSE 8080

# /api/status answers 200 whenever the server is up, even before the first poll. The port comes from the
# environment; if you set server.port in settings.yaml instead, set OSPF_MONITOR_PORT to the same value.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, sys, urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:%s/api/status' % os.environ.get('OSPF_MONITOR_PORT', '8080'), timeout=4).status == 200 else 1)"

ENTRYPOINT ["python", "main.py"]
CMD ["--serve"]
