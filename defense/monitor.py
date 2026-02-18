#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統
=============================
常駐程式，包含兩個監控執行緒：
  執行緒 A（LED1 黃色 GPIO 17 + LED2 紅色 GPIO 27）：Docker Log 即時監控
    - LED1：Regex 比對 /admin 路徑存取
    - LED2：偵測 dashboard.php HTTP 200（SQL Injection 繞過）
  執行緒 B（LED3 GPIO 22）：Netstat 連線快照監控
    - IP 白名單機制，偵測非白名單 ESTABLISHED 連線（Reverse Shell）
"""

import os
import sys
import re
import json
import time
import subprocess
import threading
import logging
import ipaddress

try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False
    logging.warning("RPi.GPIO 無法使用 — 以模擬模式運行")

# ---------------------------------------------------------------------------
# 組態設定
# ---------------------------------------------------------------------------
PIN_YELLOW = 17   # LED1：/admin 路徑探測警示
PIN_RED    = 27   # LED2：SQL Injection 繞過警示
PIN_GREEN  = 22   # LED3：Reverse Shell 警示

WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
NETSTAT_INTERVAL = 3  # netstat 輪詢間隔（秒）

# LED1：偵測 GET /admin 路徑存取
ADMIN_PATTERN = re.compile(r'GET /admin[\s/\?]')

# LED2：偵測 GET /dashboard.php 回傳 HTTP 200
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# LED3：IP 白名單（自動偵測 Docker 網段 + 固定白名單）
def build_whitelist():
    """啟動時自動偵測 web 容器所在的 Docker 網段，加入白名單。"""
    networks = [
        ipaddress.ip_network('127.0.0.0/8'),        # Loopback
        ipaddress.ip_network('169.254.0.0/16'),      # Link-local
    ]
    try:
        result = subprocess.run(
            ["docker", "inspect", WEB_CONTAINER,
             "--format", "{{json .NetworkSettings.Networks}}"],
            capture_output=True, text=True, timeout=10,
        )
        for name, cfg in json.loads(result.stdout.strip()).items():
            gateway = cfg.get("Gateway", "")
            prefix = cfg.get("IPPrefixLen", 16)
            if gateway:
                net = ipaddress.ip_network(f"{gateway}/{prefix}", strict=False)
                networks.append(net)
    except Exception:
        # 偵測失敗時使用保守預設值
        networks.append(ipaddress.ip_network('172.16.0.0/12'))
    return networks

WHITELIST_NETWORKS = build_whitelist()

# ---------------------------------------------------------------------------
# 日誌設定
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    force=True,
)
log = logging.getLogger("defense")

# ---------------------------------------------------------------------------
# GPIO 輔助函式
# ---------------------------------------------------------------------------
def gpio_setup():
    if not GPIO_AVAILABLE:
        log.info("GPIO 模擬模式：腳位 %s 設為 OUTPUT/LOW",
                 [PIN_YELLOW, PIN_RED, PIN_GREEN])
        return
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    for pin in (PIN_YELLOW, PIN_RED, PIN_GREEN):
        GPIO.setup(pin, GPIO.OUT, initial=GPIO.LOW)
    log.info("GPIO 已初始化（BCM 模式）")


def led_on(pin, label=""):
    if GPIO_AVAILABLE:
        GPIO.output(pin, GPIO.HIGH)
    log.warning("LED 常亮 -> GPIO %d  [%s]", pin, label)


# ---------------------------------------------------------------------------
# 執行緒 A — Docker Log 監控（LED1 + LED2）
# ---------------------------------------------------------------------------
def docker_log_monitor():
    """
    透過 subprocess 即時串流 web 容器的 Docker log，
    同時偵測 /admin 路徑存取（LED1）和 dashboard.php 200 回應（LED2）。
    觸發後 LED 常亮，不自動熄滅。
    """
    log.info("[執行緒-A] Docker Log 監控已啟動（容器：%s）", WEB_CONTAINER)

    led1_triggered = False
    led2_triggered = False

    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "0", WEB_CONTAINER],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                # LED1：偵測 /admin 路徑存取
                if not led1_triggered and ADMIN_PATTERN.search(line):
                    log.warning("[LED1] 偵測到 /admin 路徑存取：%s", line)
                    led_on(PIN_YELLOW, "/admin 路徑探測")
                    led1_triggered = True

                # LED2：偵測 dashboard.php HTTP 200（SQL Injection 繞過）
                if not led2_triggered and DASHBOARD_PATTERN.search(line):
                    log.warning("[LED2] 偵測到 SQL Injection 繞過"
                                "（dashboard.php 200）：%s", line)
                    led_on(PIN_RED, "SQL Injection 繞過")
                    led2_triggered = True

            proc.wait()
            log.warning("[執行緒-A] docker logs 程序結束（代碼：%d），"
                        "3 秒後重試…", proc.returncode)

        except Exception as exc:
            log.error("[執行緒-A] 監控錯誤：%s", exc)

        time.sleep(3)


# ---------------------------------------------------------------------------
# 執行緒 B — Netstat 連線監控（LED3）
# ---------------------------------------------------------------------------
def netstat_monitor():
    """
    定期透過 docker exec 在 web 容器內執行 netstat，
    檢查是否存在非白名單的 ESTABLISHED 連線（判定為 Reverse Shell）。
    觸發後 LED 常亮，不自動熄滅。
    """
    log.info("[執行緒-B] Netstat 連線監控已啟動（容器：%s，間隔：%ds）",
             WEB_CONTAINER, NETSTAT_INTERVAL)

    triggered = False

    while True:
        if triggered:
            time.sleep(NETSTAT_INTERVAL)
            continue

        try:
            result = subprocess.run(
                ["docker", "exec", WEB_CONTAINER, "netstat", "-tn"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.splitlines():
                if "ESTABLISHED" not in line:
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                # 解析遠端位址（格式：IP:PORT）
                foreign_addr = parts[4]
                ip_str = foreign_addr.rsplit(":", 1)[0]

                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue

                # 白名單比對
                if any(ip in net for net in WHITELIST_NETWORKS):
                    continue

                log.warning("[LED3] 偵測到非白名單連線：%s → 判定為 Reverse Shell",
                            foreign_addr)
                led_on(PIN_GREEN, f"Reverse Shell → {foreign_addr}")
                triggered = True
                break

        except subprocess.TimeoutExpired:
            log.warning("[執行緒-B] netstat 執行逾時")
        except Exception as exc:
            log.error("[執行緒-B] 監控錯誤：%s", exc)

        time.sleep(NETSTAT_INTERVAL)


# ---------------------------------------------------------------------------
# 主程式
# ---------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統")
    log.info("  監控容器：%s", WEB_CONTAINER)
    log.info("  GPIO 模式：%s", "實體硬體" if GPIO_AVAILABLE else "模擬模式")
    log.info("=" * 60)

    gpio_setup()

    threads = [
        threading.Thread(target=docker_log_monitor,
                         name="Docker-Log-監控", daemon=True),
        threading.Thread(target=netstat_monitor,
                         name="Netstat-監控", daemon=True),
    ]

    for t in threads:
        t.start()
        log.info("已啟動執行緒：%s", t.name)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("正在關閉系統...")
        if GPIO_AVAILABLE:
            GPIO.cleanup()
        sys.exit(0)


if __name__ == "__main__":
    main()
