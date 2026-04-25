#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統 v2.6 (修正標記與馬達穩定性)
=====================================
硬體對應：
   - /admin 探測 -> 綠燈 (GPIO 22)  日誌標記 [LED1]
   - SQLi 成功   -> 紅燈 (GPIO 24)  日誌標記 [LED2]
   - RevShell    -> 標靶馬達 (GPIO 18) 日誌標記 [MOTOR]
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
# 硬體載入與腳位定義
# ---------------------------------------------------------------------------
try:
    import RPi.GPIO as GPIO
    import pigpio
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False
    logging.warning("硬體函式庫無法使用 — 以模擬模式運行")

PIN_GREEN  = 22   # LED1 路徑探測
PIN_RED    = 24   # LED2 SQLi 繞過
PIN_SERVO  = 18   # 標靶馬達

SERVO_UP   = 500  # 標靶立起
SERVO_DOWN = 1500 # 標靶擊倒

WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")
NETSTAT_INTERVAL = 1
WEB_SERVICE_PORT = "80"

# Reverse Shell 偵測冷卻時間（秒），避免馬達指令重複發送
MOTOR_COOLDOWN = 5

pi = None
motor_triggered = False
motor_lock = threading.Lock()
log = logging.getLogger("defense")

# ---------------------------------------------------------------------------
# 偵測規則
# ---------------------------------------------------------------------------
ADMIN_PATTERN = re.compile(r'GET /admin[\s/?]')
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# ---------------------------------------------------------------------------
# 硬體控制輔助
# ---------------------------------------------------------------------------
def get_host_gateway_ip():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            if "default via" in line:
                return line.split()[2]
    except Exception:
        pass
    return "127.0.0.1"

def shutdown_handler(signum, frame):
    log.info("接收到訊號，執行安全清理...")
    if GPIO_AVAILABLE:
        # 先關燈
        try:
            GPIO.output(PIN_GREEN, GPIO.LOW)
            GPIO.output(PIN_RED, GPIO.LOW)
        except Exception:
            pass
        # 再關馬達
        if pi and pi.connected:
            try:
                pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
                time.sleep(1)
                pi.set_servo_pulsewidth(PIN_SERVO, 0)
                pi.stop()
            except Exception:
                pass
        # 最後清理 GPIO
        try:
            GPIO.cleanup()
        except Exception:
            pass
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

def hardware_setup():
    global pi
    if not GPIO_AVAILABLE:
        log.info("模擬模式：綠燈(22), 紅燈(24), 馬達(18)")
        return

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_GREEN, GPIO.OUT, initial=GPIO.LOW)
    GPIO.setup(PIN_RED, GPIO.OUT, initial=GPIO.LOW)

    host_ip = get_host_gateway_ip()
    pi = pigpio.pi(host_ip)
    if not pi.connected:
        log.warning("pigpio 連線失敗 (%s)，嘗試 localhost...", host_ip)
        pi = pigpio.pi("localhost")

    if pi.connected:
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
        log.info("硬體初始化完成：標靶已立起")
    else:
        log.error("pigpio 連線全部失敗，馬達將無法控制！")

# ---------------------------------------------------------------------------
# 監控執行緒
# ---------------------------------------------------------------------------
def docker_log_monitor():
    log.info("[執行緒-A] Log 監控啟動 (目標：%s)", WEB_CONTAINER)
    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "0", WEB_CONTAINER],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                if ADMIN_PATTERN.search(line):
                    log.warning("[LED1] 命中 /admin 探測 -> 點亮綠燈")
                    if GPIO_AVAILABLE:
                        GPIO.output(PIN_GREEN, GPIO.HIGH)

                if DASHBOARD_PATTERN.search(line):
                    log.warning("[LED2] 命中 SQLi 繞過 -> 點亮紅燈")
                    if GPIO_AVAILABLE:
                        GPIO.output(PIN_RED, GPIO.HIGH)
            proc.wait()
        except Exception as e:
            log.error("[執行緒-A] 錯誤: %s", e)
        time.sleep(2)

def motor_cooldown_reset():
    """冷卻結束後重置 motor_triggered 旗標"""
    global motor_triggered
    time.sleep(MOTOR_COOLDOWN)
    with motor_lock:
        motor_triggered = False
    log.info("[MOTOR] 馬達冷卻結束，可再次觸發")

def netstat_monitor(whitelist):
    global motor_triggered
    log.info("[執行緒-B] Netstat 監控啟動 (白名單已建立)")
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
                if len(parts) < 5:
                    continue

                local_port = parts[3].rsplit(":", 1)[-1]
                if local_port == WEB_SERVICE_PORT:
                    continue

                ip_str = parts[4].rsplit(":", 1)[0].replace("::ffff:", "")
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if any(ip in net for net in whitelist):
                        continue
                except Exception:
                    continue

                # 判定為 Reverse Shell — 帶冷卻防重複
                with motor_lock:
                    if motor_triggered:
                        continue
                    motor_triggered = True

                log.warning("[MOTOR] 命中 Reverse Shell (%s) -> 擊倒標靶", ip_str)
                if GPIO_AVAILABLE and pi and pi.connected:
                    pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)
                    log.info("[MOTOR] 馬達指令已發送 (pulse=%d)", SERVO_DOWN)
                elif not GPIO_AVAILABLE:
                    log.info("[MOTOR] 模擬模式：馬達指令 (pulse=%d)", SERVO_DOWN)
                else:
                    log.error("[MOTOR] pigpio 未連線，無法控制馬達！")

                # 啟動冷卻計時器
                threading.Thread(target=motor_cooldown_reset, daemon=True).start()

            proc.wait()
        except Exception as e:
            log.error("[執行緒-B] 錯誤: %s", e)
        time.sleep(2)

# ---------------------------------------------------------------------------
# 主程式
# ---------------------------------------------------------------------------
def build_whitelist():
    """快速建立白名單，不阻塞啟動流程"""
    networks = [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('169.254.0.0/16')]
    try:
        result = subprocess.run(
            ["docker", "inspect", WEB_CONTAINER, "--format", "{{json .NetworkSettings.Networks}}"],
            capture_output=True, text=True, timeout=5,
        )
        for name, cfg in json.loads(result.stdout.strip()).items():
            gateway = cfg.get("Gateway", "")
            prefix = cfg.get("IPPrefixLen", 16)
            if gateway:
                networks.append(ipaddress.ip_network(f"{gateway}/{prefix}", strict=False))
    except Exception:
        pass
    networks.append(ipaddress.ip_network('172.16.0.0/12'))
    return networks

def main():
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s  %(message)s", force=True)
    log.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統 v2.6")
    log.info("=" * 60)

    # 1. 硬體初始化
    hardware_setup()

    # 2. 建立白名單
    whitelist = build_whitelist()
    log.info("白名單: %s", [str(n) for n in whitelist])

    # 3. 啟動監控執行緒
    t1 = threading.Thread(target=docker_log_monitor, daemon=True)
    t2 = threading.Thread(target=netstat_monitor, args=(whitelist,), daemon=True)
    t1.start()
    t2.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
