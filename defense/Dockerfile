# 防禦監控容器 — Debian Bookworm + Python 3.11 + BCC (eBPF) + Docker CLI + RPi.GPIO
#
# Base image 改用 debian:bookworm-slim 是為了相容 python3-bpfcc：bcc 的 Python
# binding 是 Debian apt 套件，必須綁系統 Python（Bookworm = 3.11），不能跟
# python:3.9-slim 共存。
FROM debian:bookworm-slim

# 系統套件：
#   python3 / python3-pip      — 系統 Python 3.11
#   bpfcc-tools / python3-bpfcc — eBPF runtime + Python binding
#   docker-ce-cli              — docker logs / docker exec / docker inspect
#   gcc / python3-dev          — RPi.GPIO 編譯需要
#   ca-certificates / curl / gnupg — apt 設定 docker 來源用
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
        python3 python3-pip python3-dev gcc \
        bpfcc-tools python3-bpfcc \
        libbpf1 && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg \
         -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
    https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get purge -y gnupg && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Python pip 相依（RPi.GPIO + pigpio，bcc 已從 apt 進來不要重裝）
# Debian 12 預設 PEP 668 鎖 system Python，--break-system-packages 是必要的
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

WORKDIR /app

CMD ["python3", "-u", "monitor.py"]
