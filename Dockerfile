# Flow2API Token Updater v3.1
# 持久化浏览器上下文 + VNC 登录 + Headless 刷新

FROM python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:99
ENV NOVNC_PORT=6080
ENV RESOLUTION=1024x768x16
ENV ENABLE_VNC=1

WORKDIR /app

# 安装系统依赖
RUN sed -i 's#http://deb.debian.org/#https://deb.debian.org/#g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    # VNC
    x11vnc \
    xvfb \
    fluxbox \
    novnc \
    websockify \
    # Chromium 依赖
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libxshmfence1 \
    # 字体
    fonts-liberation \
    fonts-noto-cjk \
    # 工具
    supervisor \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright Chromium
RUN playwright install chromium \
    && chmod a+rx /root /root/.cache \
    && chmod -R a+rX /root/.cache/ms-playwright

# 应用代码
COPY token_updater/ /app/token_updater/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 目录
RUN mkdir -p /app/profiles /app/logs /app/data

EXPOSE 6080 8002

VOLUME ["/app/profiles", "/app/logs", "/app/data"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
