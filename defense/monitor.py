#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統 v2.1
=============================
修復說明：
1. 修正 is_triggered 邏輯：確保即使標靶已擊倒，偵測日誌仍會持續輸出。
2. 增強 netstat IP 解析：支援 IPv4-mapped IPv6 位址 (::ffff:x.x.x.x)。
3. 優化硬體作動：確保 trigger_attack_event 每次呼叫都會執行 GPIO 輸出。
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
# 硬體函式庫載入 (RPi.GPIO + pigpio)
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
PIN_NORMAL = 22   # 綠燈：系統正常
PIN_ALARM  = 24   # 紅燈：系統警報
PIN_SERVO  = 18   # 伺服馬達：物理標靶 (SG90)

SERVO_UP   = 500  # 0度 (立起)
SERVO_DOWN = 1500 # 90度 (擊倒)

WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
NETSTAT_INTERVAL = 1
WEB_SERVICE_PORT = "80"

pi = None
is_triggered = False  # 僅用於標記狀態，不應阻止物理動作執行
hardware_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Regex 比對規則
# ---------------------------------------------------------------------------
ADMIN_PATTERN = re.compile(r'GET /admin[\s/?]')
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# ---------------------------------------------------------------------------
# 優雅降落 (Graceful Shutdown)
# ---------------------------------------------------------------------------
def shutdown_handler(signum, frame):
    logging.info("接收到中斷訊號 (%d)，執行安全清理流程...", signum)
    if GPIO_AVAILABLE and pi:
        logging.info("安全復位：將標靶立起...")
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
        time.sleep(1)
        pi.set_servo_pulsewidth(PIN_SERVO, 0)
        pi.stop()
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.LOW)
        GPIO.cleanup([PIN_NORMAL, PIN_ALARM])
    logging.info("清理完成，程式結束。")
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ---------------------------------------------------------------------------
# 硬體初始化
# ---------------------------------------------------------------------------
def hardware_setup():
    global pi
    if not GPIO_AVAILABLE:
        logging.info("模擬模式：綠燈(22) ON, 紅燈(24) OFF, 馬達(18) -> %d", SERVO_UP)
        return

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_NORMAL, GPIO.OUT, initial=GPIO.HIGH)
    GPIO.setup(PIN_ALARM, GPIO.OUT, initial=GPIO.LOW)

    pi = pigpio.pi()
    if not pi.connected:
        logging.error("無法連接 pigpiod 守護行程！請確保宿主機已執行 sudo pigpiod")
        sys.exit(1)
    
    pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
    logging.info("硬體初始化完成：綠燈亮 / 標靶立起")

def trigger_attack_event(label=""):
    """
    執行攻擊觸發動作：
    即使 is_triggered 為 True，依然執行 GPIO 指令，確保硬體狀態同步。
    """
    global is_triggered
    
    logging.warning("!!! 偵測到關鍵攻擊行為 [%s] !!!", label)
    
    if GPIO_AVAILABLE:
        # 狀態燈切換
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.HIGH)
        # 標靶擊倒
        if pi:
            pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)
    
    with hardware_lock:
        is_triggered = True
    
    logging.warning("物理動作執行完成：標靶擊倒")

# ---------------------------------------------------------------------------
# 執行緒 A — Docker Log 監控
# ---------------------------------------------------------------------------
def docker_log_monitor():
    log.info("[執行緒-A] Docker Log 監控啟動")
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
                    trigger_attack_event("探測 /admin 路徑")
                elif DASHBOARD_PATTERN.search(line):
                    trigger_attack_event("SQL Injection 驗證繞過")
            proc.wait()
        except Exception as exc:
            log.error("[執行緒-A] 錯誤：%s", exc)
        time.sleep(3)

# ---------------------------------------------------------------------------
# 執行緒 B — Netstat 持續監控
# ---------------------------------------------------------------------------
def netstat_monitor(whitelist):
    log.info("[執行緒-B] Netstat 監控啟動 (白名單計 %d 項)", len(whitelist))
    while True:
        try:
            # 增加 -W 參數以顯示完整寬度位址，避免 IP 被截斷
            proc = subprocess.Popen(
                ["docker", "exec", WEB_CONTAINER, "bash", "-c",
                 f"while true; do netstat -tnW 2>/dev/null; echo '---SNAPSHOT---'; "
                 f"sleep {NETSTAT_INTERVAL}; done"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            for line in proc.stdout:
                line = line.strip()
                if not line or line == "---SNAPSHOT---" or "ESTABLISHED" not in line:
                    continue

                parts = line.split()
                if len(parts) < 5: continue
                
                # 解析本地與遠端位址
                # netstat -W 格式: Proto Recv-Q Send-Q Local_Address Foreign_Address State
                local_addr = parts[3]
                foreign_addr = parts[4]

                # 提取 Port (最後一個冒號後面的內容)
                local_port = local_addr.rsplit(":", 1)[-1]
                if local_port == WEB_SERVICE_PORT:
                    continue

                # 提取 IP (處理 IPv4-mapped IPv6，例如 ::ffff:192.168.1.100)
                ip_str = foreign_addr.rsplit(":", 1)[0]
                if ip_str.startswith("::ffff:"):
                    ip_str = ip_str.replace("::ffff:", "")
                
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if any(ip in net for net in whitelist):
                        continue
                except ValueError:
                    log.debug("無法解析 IP 位址: %s", ip_str)
                    continue

                # 判定為 Reverse Shell
                trigger_attack_event(f"Reverse Shell → {ip_str}")
            proc.wait()
        except Exception as exc:
            log.error("[執行緒-B] 錯誤：%s", exc)
        time.sleep(3)

# ---------------------------------------------------------------------------
# 輔助函式
# ---------------------------------------------------------------------------
def build_whitelist():
    networks = [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('169.254.0.0/16')]
    for attempt in range(5):
        try:
            result = subprocess.run(
                ["docker", "inspect", WEB_CONTAINER, "--format", "{{json .NetworkSettings.Networks}}"],
                capture_output=True, text=True, timeout=10,
            )
            for name, cfg in json.loads(result.stdout.strip()).items():
                gateway = cfg.get("Gateway", "")
                prefix = cfg.get("IPPrefixLen", 16)
                if gateway:
                    networks.append(ipaddress.ip_network(f"{gateway}/{prefix}", strict=False))
            return networks
        except Exception:
            time.sleep(3)
    networks.append(ipaddress.ip_network('172.16.0.0/12'))
    return networks

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s  %(message)s", force=True)
log = logging.getLogger("defense")

def main():
    log.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統 v2.1 (SG90 物理標靶版)")
    log.info("=" * 60)

    whitelist = build_whitelist()
    log.info("白名單網段：%s", [str(n) for n in whitelist])
    hardware_setup()

    threads = [
        threading.Thread(target=docker_log_monitor, name="Log-Monitor", daemon=True),
        threading.Thread(target=netstat_monitor, args=(whitelist,), name="Net-Monitor", daemon=True),
    ]

    for t in threads:
        t.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
