# Debian 12 (Bookworm) — proper .deb packages for Firefox + TigerVNC (no snap stubs)
FROM debian:bookworm-slim
LABEL maintainer="himaya-sandbox"
LABEL description="Himaya isolated email sandbox — TigerVNC + noVNC + Firefox + tcpdump"

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:1
ENV VNC_RESOLUTION=1280x800
ENV VNC_DEPTH=24
ENV NO_VNC_PORT=6080
ENV VNC_PORT=5901

# ── Base + analysis applications ─────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    tigervnc-standalone-server \
    tigervnc-common \
    openbox \
    obconf \
    firefox-esr \
    python3 \
    python3-pip \
    python3-websockify \
    tcpdump \
    net-tools \
    curl \
    wget \
    supervisor \
    xterm \
    fonts-liberation \
    fonts-noto \
    fonts-noto-color-emoji \
    dbus-x11 \
    x11-utils \
    procps \
    thunar \
    libreoffice-writer \
    libreoffice-calc \
    libreoffice-impress \
    libreoffice-draw \
    evince \
    mousepad \
    eog \
    file-roller \
    unzip \
    p7zip-full \
    wine \
    wine64 \
    tshark \
    less \
    nano \
    feh \
    imagemagick \
    && rm -rf /var/lib/apt/lists/*

# ── Configure Wine silently (no GUI popups on first run) ──────────────────────
ENV WINEDEBUG=-all
ENV WINEPREFIX=/root/.wine
RUN wineboot --init 2>/dev/null || true

# ── noVNC ─────────────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages websockify==0.11.0 boto3 2>/dev/null || \
    pip3 install --no-cache-dir websockify==0.11.0 boto3

RUN mkdir -p /opt/novnc/utils/websockify && \
    curl -fsSL https://github.com/novnc/noVNC/archive/refs/tags/v1.4.0.tar.gz | \
    tar -xz -C /opt/novnc --strip-components=1 && \
    ln -sf /usr/lib/python3/dist-packages/websockify /opt/novnc/utils/websockify && \
    chmod +x /opt/novnc/utils/launch.sh 2>/dev/null || true

# ── Himaya branding: custom chrome-free viewer + logo (hides all noVNC branding) ─
# himaya.html embeds the noVNC core RFB client full-screen with no toolbar/logo.
# It becomes the default landing page so vnc.html (and its noVNC logo) is bypassed.
COPY himaya_logo.png /opt/novnc/himaya_logo.png
COPY himaya_favicon.png /opt/novnc/himaya_favicon.png
COPY himaya.html /opt/novnc/himaya.html
RUN cp /opt/novnc/himaya.html /opt/novnc/index.html && \
    cp /opt/novnc/himaya_logo.png /usr/share/pixmaps/himaya_logo.png

# ── Enterprise desktop wallpaper (dark canvas + centered Himaya logo) ─────────
RUN convert -size 1280x800 xc:'#0b1424' \
      \( /opt/novnc/himaya_logo.png -resize 360x \) -gravity center -geometry +0-30 -composite \
      -font /usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf \
      -gravity south -fill '#5b6b82' -pointsize 16 \
      -annotate +0+70 'Himaya Secure Sandbox   -   Isolated Analysis Environment' \
      /usr/share/pixmaps/himaya-wallpaper.png

# ── Openbox config + right-click application menu ─────────────────────────
RUN mkdir -p /root/.config/openbox /root/Downloads
COPY openbox-rc.xml /root/.config/openbox/rc.xml
COPY openbox-menu.xml /root/.config/openbox/menu.xml

# ── Wine desktop entry so Thunar can open .exe/.msi ──────────────────────────
RUN mkdir -p /root/.local/share/applications && \
    printf '[Desktop Entry]\nType=Application\nName=Wine Executor\nExec=wine %%f\nMimeType=application/x-msdownload;application/x-msi;\n' \
    > /root/.local/share/applications/wine-exec.desktop

# ── VNC password ────────────────────────────────────────────────────────────────────
COPY make_vnc_passwd.py /tmp/make_vnc_passwd.py
RUN python3 /tmp/make_vnc_passwd.py

# ── Supervisor config ──────────────────────────────────────────────────────────
COPY supervisord.conf /etc/supervisor/conf.d/sandbox.conf

# ── Entrypoint script ─────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Email HTML landing dir (enterprise placeholder, shown until email loads) ──
RUN mkdir -p /sandbox/email
COPY landing.html /sandbox/email/index.html
COPY himaya_logo.png /sandbox/email/himaya_logo.png

EXPOSE 6080 5901

ENTRYPOINT ["/entrypoint.sh"]
