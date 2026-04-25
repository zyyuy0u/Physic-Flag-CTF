#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統 v2.2 (終極穩定版)
=====================================
主要修復：
1. 縮緊白名單：移除寬泛的 172.16.0.0/12，防止誤判 NAT 連線。
2. 增強 Reverse Shell 偵測：即使來源是 Gateway，只要 Local Port 不是 80 且非資料庫通訊，即觸發。
3. 增加偵測日誌：詳細輸出連線判定過程，方便現場除錯。
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
PIN_NORMAL = 22   # 綠燈
PIN_ALARM  = 24   # 紅燈
PIN_SERVO  = 18   # 馬達 (SG90)

SERVO_UP   = 500
SERVO_DOWN = 1500

WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
DB_CONTAINER  = os.environ.get("DB_CONTAINER", "db")
NETSTAT_INTERVAL = 1
WEB_SERVICE_PORT = "80"

pi = None
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
    logging.info("接收到中斷訊號，執行安全清理...")
    if GPIO_AVAILABLE and pi:
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
        time.sleep(1)
        pi.set_servo_pulsewidth(PIN_SERVO, 0)
        pi.stop()
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.LOW)
        GPIO.cleanup()
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ---------------------------------------------------------------------------
# 硬體初始化
# ---------------------------------------------------------------------------
def hardware_setup():
    global pi
    if not GPIO_AVAILABLE:
        logging.info("模擬模式啟動")
        return

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_NORMAL, GPIO.OUT, initial=GPIO.HIGH)
    GPIO.setup(PIN_ALARM, GPIO.OUT, initial=GPIO.LOW)

    # 嘗試連接 pigpiod (優先連向宿主機網關)
    pi = pigpio.pi('172.21.0.1') # 這裡建議根據實際網關調整，或使用 localhost
    if not pi.connected:
        pi = pigpio.pi() # 回退到 localhost
        
    if not pi.connected:
        logging.error("無法連接 pigpiod！")
        sys.exit(1)
    
    pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
    logging.info("硬體已就緒 (綠燈 ON / 標靶立起)")

def trigger_attack_event(label=""):
    logging.warning("!!! 攻擊偵測 [%s] !!!", label)
    if GPIO_AVAILABLE:
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.HIGH)
        if pi:
            pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)
    logging.warning("物理作動完成：標靶擊倒")

# ---------------------------------------------------------------------------
# 執行緒 B — Netstat 持續監控 (核心修復)
# ---------------------------------------------------------------------------
def netstat_monitor(whitelist, db_ips):
    log.info("[執行緒-B] Netstat 監控啟動")
    while True:
        try:
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
                
                local_addr = parts[3]
                foreign_addr = parts[4]

                local_port = local_addr.rsplit(":", 1)[-1]
                # 排除正常的入站 Web 流量 (Port 80)
                if local_port == WEB_SERVICE_PORT:
                    continue

                remote_ip_str = foreign_addr.rsplit(":", 1)[0].replace("::ffff:", "")
                try:
                    remote_ip = ipaddress.ip_address(remote_ip_str)
                except ValueError: continue

                # 精準過濾：
                # 1. 排除 Loopback 與 Link-local
                if any(remote_ip in net for net in whitelist):
                    continue
                
                # 2. 排除與 db 容器的正常通訊
                if remote_ip_str in db_ips:
                    continue

                # 如果走到這，代表這是一個非 Port 80 且非資料庫通訊的外連
                trigger_attack_event(f"Reverse Shell 偵測: {remote_ip_str}:{foreign_addr.rsplit(':', 1)[-1]}")
            proc.wait()
        except Exception as exc:
            log.error("[執行緒-B] 錯誤：%s", exc)
        time.sleep(3)

# ---------------------------------------------------------------------------
# 輔助函式 (強化白名單)
# ---------------------------------------------------------------------------
def get_container_ips(name):
    """獲取指定容器的 IP 清單"""
    try:
        result = subprocess.run(
            ["docker", "inspect", name, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().split()
    except:
        return []

def build_base_whitelist():
    """基礎白名單：僅限本地迴路"""
    return [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('169.254.0.0/16')]

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s  %(message)s", force=True)
log = logging.getLogger("defense")

def main():
    log.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統 v2.2 (終極穩定版)")
    log.info("=" * 60)

    # 建立最小化白名單
    whitelist = build_base_whitelist()
    
    # 獲取資料庫 IP
    db_ips = []
    for _ in range(5):
        db_ips = get_container_ips(DB_CONTAINER)
        if db_ips: break
        time.sleep(2)
    
    log.info("資料庫 IP 白名單：%s", db_ips)
    hardware_setup()

    # 啟動監控
    from threading import Thread
    def docker_log_monitor():
        log.info("[執行緒-A] Log 監控啟動")
        while True:
            try:
                p = subprocess.Popen(["docker", "logs", "-f", "--tail", "0", WEB_CONTAINER],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in p.stdout:
                    if ADMIN_PATTERN.search(line) or DASHBOARD_PATTERN.search(line):
                        trigger_attack_event("日誌異常偵測")
                p.wait()
            except: pass
            time.sleep(3)

    Thread(target=docker_log_monitor, daemon=True).start()
    netstat_monitor(whitelist, db_ips)

if __name__ == "__main__":
    main()
