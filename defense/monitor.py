#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統 v2.3
=============================
核心修復：
1. 完全還原原始偵測邏輯（不修改偵測方式）。
2. 自動偵測 Docker Gateway IP 以正確連向宿主機 pigpiod。
3. 實作任務二要求的優雅降落 (Graceful Shutdown) 機制。
4. 使用 pigpio 控制 GPIO 18 (SG90)，RPi.GPIO 控制 GPIO 22/24。
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
# 組態設定 (完全依照需求)
# ---------------------------------------------------------------------------
PIN_NORMAL = 22   # 綠燈：系統正常
PIN_ALARM  = 24   # 紅燈：系統警報
PIN_SERVO  = 18   # 伺服馬達：物理標靶 (SG90)

SERVO_UP   = 500  # 0度 (立起)
SERVO_DOWN = 1500 # 90度 (擊倒)

WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
NETSTAT_INTERVAL = 1
WEB_SERVICE_PORT = "80"

# 全域狀態
pi = None
is_triggered = False
hardware_lock = threading.Lock()

# ---------------------------------------------------------------------------
# 原始偵測規則 (保持不變)
# ---------------------------------------------------------------------------
ADMIN_PATTERN = re.compile(r'GET /admin[\s/?]')
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# ---------------------------------------------------------------------------
# 通訊優化：自動偵測宿主機 IP
# ---------------------------------------------------------------------------
def get_host_gateway_ip():
    """偵測 Docker 容器的網關 IP，通常即為宿主機位址"""
    try:
        # 執行 ip route 命令並解析 default 路由
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            if "default via" in line:
                return line.split()[2]
    except:
        pass
    return "127.0.0.1"

# ---------------------------------------------------------------------------
# 優雅降落 (任務二)
# ---------------------------------------------------------------------------
def shutdown_handler(signum, frame):
    logging.info("接收到訊號 (%d)，執行安全清理...", signum)
    if GPIO_AVAILABLE:
        # 1. 標靶安全復位 (立起)
        if pi and pi.connected:
            logging.info("標靶安全復位...")
            pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
            time.sleep(1) # 保留物理作動時間
            pi.set_servo_pulsewidth(PIN_SERVO, 0) # 斷電防止發熱
            pi.stop()
        
        # 2. 清理燈號
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.LOW)
        GPIO.cleanup([PIN_NORMAL, PIN_ALARM])
    
    logging.info("清理完成，結束行程。")
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# ---------------------------------------------------------------------------
# 硬體初始化 (任務一)
# ---------------------------------------------------------------------------
def hardware_setup():
    global pi
    if not GPIO_AVAILABLE:
        logging.info("模擬模式：綠亮(22), 紅滅(24), 馬達(18)->500")
        return

    # LED 初始化
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_NORMAL, GPIO.OUT, initial=GPIO.HIGH) # 綠燈亮
    GPIO.setup(PIN_ALARM, GPIO.OUT, initial=GPIO.LOW)  # 紅燈滅

    # 馬達初始化 (連向宿主機 pigpiod)
    host_ip = get_host_gateway_ip()
    logging.info("嘗試連接 pigpiod @ %s", host_ip)
    pi = pigpio.pi(host_ip)
    
    if not pi.connected:
        logging.warning("無法連接宿主機網關，嘗試 localhost...")
        pi = pigpio.pi("localhost")

    if pi.connected:
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
        logging.info("馬達已就緒 (腳位 18, 脈衝 500)")
    else:
        logging.error("錯誤：無法建立 pigpio 連線。請確保宿主機已執行 sudo pigpiod")

def trigger_attack_event(label=""):
    """觸發物理警報動作"""
    global is_triggered
    logging.warning("!!! 攻擊偵測 [%s] !!!", label)
    
    if GPIO_AVAILABLE:
        # 燈號切換
        GPIO.output(PIN_NORMAL, GPIO.LOW)
        GPIO.output(PIN_ALARM, GPIO.HIGH)
        # 擊倒標靶
        if pi and pi.connected:
            pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)
            logging.info("物理動作：標靶擊倒 (GPIO 18 -> 1500)")
    
    with hardware_lock:
        is_triggered = True

# ---------------------------------------------------------------------------
# 原始偵測流程 (完全保留原本的監控方式)
# ---------------------------------------------------------------------------
def docker_log_monitor():
    logging.info("[執行緒-A] Docker Log 監控啟動")
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
                local_addr = parts[3]
                local_port = local_addr.rsplit(":", 1)[-1]
                if local_port == WEB_SERVICE_PORT:
                    continue

                foreign_addr = parts[4]
                ip_str = foreign_addr.rsplit(":", 1)[0].replace("::ffff:", "")
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if any(ip in net for net in whitelist):
                        continue
                except ValueError:
                    continue

                # 判定為 Reverse Shell (原始偵測邏輯)
                trigger_attack_event(f"Reverse Shell → {ip_str}")
            proc.wait()
        except Exception as exc:
            logging.error("[執行緒-B] 錯誤：%s", exc)
        time.sleep(3)

# ---------------------------------------------------------------------------
# 輔助函式 (保留原始白名單建立方式)
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

def main():
    logging.info("=" * 60)
    logging.info("  IoT 蜜罐防禦監控系統 v2.3 (物理標靶穩定版)")
    logging.info("=" * 60)

    whitelist = build_whitelist()
    hardware_setup()

    t1 = threading.Thread(target=docker_log_monitor, daemon=True)
    t2 = threading.Thread(target=netstat_monitor, args=(whitelist,), daemon=True)
    
    t1.start()
    t2.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
