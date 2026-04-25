#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統 v2.4 (回歸經典邏輯版)
=====================================
硬體對應規則（跟之前一樣）：
1. 偵測到 /admin 探測        -> 點亮綠燈 (GPIO 22)
2. 偵測到 SQLi (成功登入)    -> 點亮紅燈 (GPIO 24)
3. 偵測到 Reverse Shell      -> 擊倒標靶 (GPIO 18 馬達)
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
import signal

# ---------------------------------------------------------------------------
# 硬體函式庫載入
# ---------------------------------------------------------------------------
try:
    import RPi.GPIO as GPIO
    import pigpio
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False
    logging.warning("硬體函式庫無法使用 — 以模擬模式運行")

# ---------------------------------------------------------------------------
# 組態設定
# ---------------------------------------------------------------------------
PIN_GREEN  = 22   # LED1：/admin 路徑探測 (跟之前一樣)
PIN_RED    = 24   # LED2：SQL Injection 繞過 (跟之前一樣)
PIN_SERVO  = 18   # LED3 汰換：實體標靶馬達 (跟之前一樣)

SERVO_UP   = 500  # 標靶立起
SERVO_DOWN = 1500 # 標靶擊倒

WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
NETSTAT_INTERVAL = 1
WEB_SERVICE_PORT = "80"

pi = None

# ---------------------------------------------------------------------------
# Regex 比對規則
# ---------------------------------------------------------------------------
ADMIN_PATTERN = re.compile(r'GET /admin[\s/?]')
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# ---------------------------------------------------------------------------
# 通訊優化：自動偵測宿主機 IP
# ---------------------------------------------------------------------------
def get_host_gateway_ip():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            if "default via" in line:
                return line.split()[2]
    except:
        pass
    return "127.0.0.1"

# ---------------------------------------------------------------------------
# 優雅降落 (Graceful Shutdown)
# ---------------------------------------------------------------------------
def shutdown_handler(signum, frame):
    logging.info("接收到訊號，執行安全清理...")
    if GPIO_AVAILABLE:
        if pi and pi.connected:
            pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
            time.sleep(1)
            pi.set_servo_pulsewidth(PIN_SERVO, 0)
            pi.stop()
        GPIO.output(PIN_GREEN, GPIO.LOW)
        GPIO.output(PIN_RED, GPIO.LOW)
        GPIO.cleanup([PIN_GREEN, PIN_RED])
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ---------------------------------------------------------------------------
# 硬體初始化
# ---------------------------------------------------------------------------
def hardware_setup():
    global pi
    if not GPIO_AVAILABLE:
        logging.info("模擬模式：綠燈(22), 紅燈(24), 馬達(18)")
        return

    # LED 初始化：啟動時全部熄滅
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_GREEN, GPIO.OUT, initial=GPIO.LOW)
    GPIO.setup(PIN_RED, GPIO.OUT, initial=GPIO.LOW)

    # 馬達初始化
    host_ip = get_host_gateway_ip()
    pi = pigpio.pi(host_ip)
    if not pi.connected:
        pi = pigpio.pi("localhost")

    if pi.connected:
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP) # 標靶立起
        logging.info("硬體已就緒 (燈號熄滅 / 標靶立起)")
    else:
        logging.error("錯誤：無法建立 pigpio 連線。")

# ---------------------------------------------------------------------------
# 獨立觸發動作
# ---------------------------------------------------------------------------
def trigger_green():
    logging.warning("!!! [綠燈亮起] 偵測到 /admin 探測 !!!")
    if GPIO_AVAILABLE:
        GPIO.output(PIN_GREEN, GPIO.HIGH)

def trigger_red():
    logging.warning("!!! [紅燈亮起] 偵測到 SQLi 繞過 (成功登入) !!!")
    if GPIO_AVAILABLE:
        GPIO.output(PIN_RED, GPIO.HIGH)

def trigger_motor():
    logging.warning("!!! [標靶擊倒] 偵測到 Reverse Shell !!!")
    if GPIO_AVAILABLE and pi and pi.connected:
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)

# ---------------------------------------------------------------------------
# 監控執行緒
# ---------------------------------------------------------------------------
def docker_log_monitor():
    logging.info("[執行緒-A] Log 監控啟動")
    time.sleep(2) # 啟動靜默期
    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "0", WEB_CONTAINER],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            for line in proc.stdout:
                line = line.strip()
                if not line: continue

                if ADMIN_PATTERN.search(line):
                    trigger_green()
                if DASHBOARD_PATTERN.search(line):
                    trigger_red()
            proc.wait()
        except Exception as exc:
            logging.error("[執行緒-A] 錯誤：%s", exc)
        time.sleep(3)

def netstat_monitor(whitelist):
    logging.info("[執行緒-B] Netstat 監控啟動")
    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "exec", WEB_CONTAINER, "bash", "-c",
                 f"while true; do netstat -tn 2>/dev/null; echo '---SNAPSHOT---'; "
                 f"sleep {NETSTAT_INTERVAL}; done"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            for line in proc.stdout:
                line = line.strip()
                if not line or line == "---SNAPSHOT---" or "ESTABLISHED" not in line:
                    continue

                parts = line.split()
                if len(parts) < 5: continue
                local_port = parts[3].rsplit(":", 1)[-1]
                if local_port == WEB_SERVICE_PORT: continue

                ip_str = foreign_addr = parts[4].rsplit(":", 1)[0].replace("::ffff:", "")
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if any(ip in net for net in whitelist): continue
                except: continue

                trigger_motor()
            proc.wait()
        except Exception as exc:
            logging.error("[執行緒-B] 錯誤：%s", exc)
        time.sleep(3)

# ---------------------------------------------------------------------------
# 主程式
# ---------------------------------------------------------------------------
def build_whitelist():
    networks = [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('169.254.0.0/16')]
    try:
        result = subprocess.run(["docker", "inspect", WEB_CONTAINER, "--format", "{{json .NetworkSettings.Networks}}"], capture_output=True, text=True, timeout=10)
        for name, cfg in json.loads(result.stdout.strip()).items():
            gateway = cfg.get("Gateway", ""); prefix = cfg.get("IPPrefixLen", 16)
            if gateway: networks.append(ipaddress.ip_network(f"{gateway}/{prefix}", strict=False))
    except: pass
    networks.append(ipaddress.ip_network('172.16.0.0/12'))
    return networks

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s  %(message)s", force=True)

def main():
    logging.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統 v2.4 (經典獨立偵測版)")
    log.info("=" * 60)

    whitelist = build_whitelist()
    hardware_setup()

    threading.Thread(target=docker_log_monitor, daemon=True).start()
    threading.Thread(target=netstat_monitor, args=(whitelist,), daemon=True).start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
