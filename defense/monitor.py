#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統
=============================
常駐程式，包含兩個監控執行緒：

  執行緒 A（LED1 GPIO 17 + LED2 GPIO 27）：Docker Log 即時監控
    - 透過 subprocess.Popen 執行 docker logs -f，即時串流 Apache Access Log
    - LED1：使用 Regex 比對 GET /admin 路徑存取
    - LED2：使用 Regex 比對 dashboard.php HTTP 200（SQL Injection 繞過）

  執行緒 B（LED3 GPIO 22）：Netstat 持續監控
    - 透過 subprocess.Popen 在容器內啟動持續運行的 netstat 程序
    - 每秒取得一次連線快照，逐行即時分析
    - 啟動時自動偵測 Docker 網段建立 IP 白名單
    - 排除本地端口 80 的正常 HTTP 連線，僅偵測容器主動對外的連線
    - 偵測到非白名單 ESTABLISHED 連線 → 判定為 Reverse Shell

兩個執行緒架構相同：都使用 subprocess.Popen 建立持續串流的子程序，
主程式逐行讀取輸出並即時分析，達到近即時偵測效果。
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
# GPIO 腳位定義 (BCM)
PIN_NORMAL = 22   # 綠燈：系統正常
PIN_ALARM  = 24   # 紅燈：系統警報
PIN_SERVO  = 18   # 伺服馬達：物理標靶 (SG90)

# 馬達脈衝寬度 (Pulse Width)
SERVO_UP   = 500  # 0度 (立起)
SERVO_DOWN = 1500 # 90度 (擊倒)

# 外部連線監控設定
WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
NETSTAT_INTERVAL = 1
WEB_SERVICE_PORT = "80"

# 全域硬體物件
pi = None
is_triggered = False  # 標記是否已觸發攻擊狀態
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
    """
    處理 SIGTERM/SIGINT，確保 Docker 停止時馬達安全復位。
    """
    logging.info("接收到中斷訊號 (%d)，執行安全清理流程...", signum)
    
    if GPIO_AVAILABLE and pi:
        # 1. 標靶安全復位 (立起)
        logging.info("安全復位：將標靶立起...")
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
        
        # 2. 保留物理作動時間 (1秒)
        time.sleep(1)
        
        # 3. 休眠與斷開 pigpio
        pi.set_servo_pulsewidth(PIN_SERVO, 0)
        pi.stop()
        
        # 4. 清理 LED 燈號
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.LOW)
        GPIO.cleanup([PIN_NORMAL, PIN_ALARM])
        
    logging.info("清理完成，程式結束。")
    sys.exit(0)

# 註冊信號捕捉器
signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ---------------------------------------------------------------------------
# 硬體初始化
# ---------------------------------------------------------------------------
def hardware_setup():
    """初始化 GPIO 與伺服馬達"""
    global pi
    if not GPIO_AVAILABLE:
        logging.info("模擬模式：綠燈(22) ON, 紅燈(24) OFF, 馬達(18) -> %d", SERVO_UP)
        return

    # 初始化 RPi.GPIO (LED)
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_NORMAL, GPIO.OUT, initial=GPIO.HIGH) # 綠燈預設亮
    GPIO.setup(PIN_ALARM, GPIO.OUT, initial=GPIO.LOW)  # 紅燈預設滅

    # 初始化 pigpio (Servo)
    pi = pigpio.pi()
    if not pi.connected:
        logging.error("無法連接 pigpiod 守護行程！請確保宿主機已執行 sudo pigpiod")
        sys.exit(1)
    
    pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP) # 標靶預設立起
    logging.info("硬體初始化完成：綠燈亮 / 標靶立起")

def trigger_attack_event(label=""):
    """
    執行攻擊觸發動作：
    1. 熄滅綠燈 -> 點亮紅燈
    2. 擊倒物理標靶 (馬達設為 1500)
    """
    global is_triggered
    with hardware_lock:
        if is_triggered:
            return
        is_triggered = True

    logging.warning("!!! 偵測到關鍵攻擊行為 [%s] !!!", label)
    
    if GPIO_AVAILABLE:
        # 燈號切換
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.HIGH)
        # 擊倒標靶
        if pi:
            pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)
    
    logging.warning("物理動作：標靶擊倒 (GPIO %d -> %d)", PIN_SERVO, SERVO_DOWN)

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

                # /admin 或 SQLi 雖不一定是 Reverse Shell，但作為展示，觸發警報
                if ADMIN_PATTERN.search(line) or DASHBOARD_PATTERN.search(line):
                    trigger_attack_event("Log 異常偵測")
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

                ip_str = parts[4].rsplit(":", 1)[0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if any(ip in net for net in whitelist): continue
                except ValueError: continue

                # 判定為 Reverse Shell
                trigger_attack_event(f"Reverse Shell → {ip_str}")
            proc.wait()
        except Exception as exc:
            log.error("[執行緒-B] 錯誤：%s", exc)
        time.sleep(3)

# ---------------------------------------------------------------------------
# 其餘輔助函式 (保留並優化)
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
    log.info("  IoT 蜜罐防禦監控系統 v2.0 (SG90 物理標靶版)")
    log.info("=" * 60)

    whitelist = build_whitelist()
    hardware_setup()

    threads = [
        threading.Thread(target=docker_log_monitor, name="Log-Monitor", daemon=True),
        threading.Thread(target=netstat_monitor, args=(whitelist,), name="Net-Monitor", daemon=True),
    ]

    for t in threads:
        t.start()

    # 主執行緒等待，signal_handler 會處理結束動作
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
