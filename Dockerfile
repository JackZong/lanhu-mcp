FROM python:3.12-slim-bookworm

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG APT_MIRROR

# Dependency/browser layers survive application-only upgrades.
COPY requirements.txt ./
RUN if [ -n "$APT_MIRROR" ]; then sed -i "s|http://deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi \
    && pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt setuptools wheel \
    && playwright install-deps chromium \
    && mkdir -p /app/data /app/logs \
    && rm -rf /var/lib/apt/lists/*
ARG PLAYWRIGHT_DOWNLOAD_HOST
ARG PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST
RUN playwright install --only-shell chromium
COPY pyproject.toml README.md LICENSE lanhu_mcp_server.py ./
COPY lanhu_design ./lanhu_design
COPY lanhu_auth ./lanhu_auth
RUN pip install --no-cache-dir --no-build-isolation --no-deps .

EXPOSE 8000
CMD ["lanhu-mcp", "--transport", "http", "--host", "0.0.0.0"]
