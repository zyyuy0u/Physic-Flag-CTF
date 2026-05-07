#!/usr/bin/env python3
"""
IoT 蜜罐防禦監控系統 v3.0 (eBPF Reverse Shell 偵測)
=====================================
硬體對應：
   - /admin 探測 -> 綠燈 (GPIO 22)  日誌標記 [LED1]
   - SQLi 成功   -> 紅燈 (GPIO 24)  日誌標記 [LED2]
   - RevShell    -> 標靶馬達 (GPIO 18) 日誌標記 [MOTOR]

重要：宿主機必須以遠端模式啟動 pigpiod：
   sudo pigpiod -n 0.0.0.0
   額外要求：kernel ≥ 5.8（ringbuf 支援），bcc 套件
   (apt install bpfcc-tools python3-bpfcc)。
   容器需要 pid: host 與 /sys/kernel/debug, /sys/fs/bpf,
   /sys/fs/cgroup, /lib/modules, /usr/src 掛載。
"""

import atexit
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

try:
    from bpf_loader import BpfReverseShellProbe, ParsedEvent
    BPF_AVAILABLE = True
except ImportError as e:
    BPF_AVAILABLE = False
    logging.basicConfig(level=logging.ERROR, format="[%(asctime)s] %(levelname)s  %(message)s", force=True)
    logging.getLogger("defense").error(
        "eBPF Reverse Shell 偵測無法啟動 (bcc/bpf_loader 不可用): %s — "
        "LED1/LED2 仍會運作，但第三階段（馬達）會失效", e,
    )

# 硬體載入與腳位定義
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

# pigpio 連線目標：優先使用環境變數 PIGPIO_HOST（由 docker-compose 注入）
PIGPIO_HOST = os.environ.get("PIGPIO_HOST", "")

# Reverse Shell 偵測冷卻時間（秒），避免馬達指令重複發送
MOTOR_COOLDOWN = 5

pi = None
motor_triggered = False
motor_lock = threading.Lock()
_cleanup_done = False  # latched by _cleanup_hardware so atexit/SIGTERM/main-exit don't double-clean
log = logging.getLogger("defense")

# 偵測規則
# LED1 涵蓋常見的 path enum 手法：GET 是預設、HEAD 是部分掃描器（更快、不
# 抓 body）、POST 較少見但路徑掃描或誤打 admin form 也會出現。case 維持
# sensitive — Apache 預設 case-sensitive，/Admin 不會比對到實際的檔案，
# 加 IGNORECASE 反而會把噪音算進偵測率。
ADMIN_PATTERN = re.compile(r'(?:GET|HEAD|POST) /admin[\s/?]')
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# 硬體控制輔助
def get_host_gateway_ip():
    """從容器內部取得 Docker bridge gateway IP（即宿主機 IP）"""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            if "default via" in line:
                return line.split()[2]
    except Exception:
        pass
    return None

def connect_pigpio():
    """
    嘗試多種方式連線到宿主機的 pigpiod daemon。
    連線順序：
      1. 環境變數 PIGPIO_HOST（docker-compose 注入的 host.docker.internal）
      2. Docker bridge gateway IP（ip route 取得）
      3. localhost（萬一 monitor 直接跑在宿主機上）
    """
    candidates = []

    if PIGPIO_HOST:
        candidates.append(PIGPIO_HOST)

    gateway = get_host_gateway_ip()
    if gateway and gateway not in candidates:
        candidates.append(gateway)

    if "localhost" not in candidates and "127.0.0.1" not in candidates:
        candidates.append("localhost")

    for host in candidates:
        log.info("[PIGPIO] 嘗試連線到 pigpiod @ %s:8888 ...", host)
        try:
            p = pigpio.pi(host)
            if p.connected:
                log.info("[PIGPIO] 成功連線到 pigpiod @ %s", host)
                return p
            else:
                log.warning("[PIGPIO] 連線失敗: %s (pigpiod 可能未啟動或未允許遠端連線)", host)
        except Exception as e:
            log.warning("[PIGPIO] 連線例外: %s -> %s", host, e)

    log.error("=" * 60)
    log.error("[PIGPIO] 所有連線嘗試均失敗！馬達將無法控制！")
    log.error("[PIGPIO] 請確認宿主機已執行: sudo pigpiod -n 0.0.0.0")
    log.error("=" * 60)
    return None

def _cleanup_hardware():
    """Hardware shutdown that survives concurrent signals and Thread B.

    Two concurrency hazards are handled here:

      1. Operator hits Ctrl-C twice (or SIGTERM + SIGINT) while we're
         mid-PWM. The 1-second sleep is load-bearing — interrupting it
         leaves the SG90 buzzing at SERVO_UP forever. We install SIG_IGN
         for SIGTERM/SIGINT first thing on entry so a second signal
         cannot abort us; original handlers are restored in finally.

      2. Thread B (bpf_event_consumer) is mid-event and holds motor_lock
         while running pi.set_servo_pulsewidth(). We acquire motor_lock
         for the entire cleanup (not just the flag latch), so Thread B
         either finishes its servo command first or waits — never
         interleaves with our SERVO_UP/sleep/0/stop sequence.

    Re-entry from atexit after a signal-triggered cleanup is harmless:
    _cleanup_done is checked before the work, so the second pass returns
    immediately.
    """
    global motor_triggered, _cleanup_done
    if _cleanup_done:
        return

    old_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        with motor_lock:
            if _cleanup_done:
                return
            _cleanup_done = True
            motor_triggered = True
            if not GPIO_AVAILABLE:
                return
            try:
                GPIO.output(PIN_GREEN, GPIO.LOW)
                GPIO.output(PIN_RED, GPIO.LOW)
            except Exception:
                pass
            if pi and pi.connected:
                try:
                    pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
                    time.sleep(1)
                    pi.set_servo_pulsewidth(PIN_SERVO, 0)
                    pi.stop()
                except Exception:
                    pass
            try:
                GPIO.cleanup()
            except Exception:
                pass
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)


def shutdown_handler(signum, frame):
    log.info("接收到訊號 %s，執行安全清理...", signum)
    _cleanup_hardware()
    sys.exit(0)


# atexit covers the non-signal paths: main-loop exit, sys.exit() from
# any code path, and uncaught exceptions in the main thread. Combined
# with the signal handlers and _cleanup_done latch, hardware always
# gets cleaned up exactly once.
atexit.register(_cleanup_hardware)
signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

def hardware_setup():
    global pi
    if not GPIO_AVAILABLE:
        log.info("模擬模式：綠燈(22), 紅燈(24), 馬達(18)")
        return

    # LED 初始化
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_GREEN, GPIO.OUT, initial=GPIO.LOW)
    GPIO.setup(PIN_RED, GPIO.OUT, initial=GPIO.LOW)
    log.info("[GPIO] LED 初始化完成（綠燈=22, 紅燈=24）")

    # pigpio 連線（多候選位址）
    pi = connect_pigpio()

    if pi and pi.connected:
        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_UP)
        time.sleep(0.5)
        log.info("[MOTOR] 硬體初始化完成：標靶已立起 (pulse=%d)", SERVO_UP)
    else:
        log.error("[MOTOR] 馬達初始化失敗 — pigpio 未連線")

# 監控執行緒
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
    """冷卻結束後重置 motor_triggered 旗標。

    刻意 *不* 把 servo 推回 SERVO_UP — 這是 demo 設計：擊倒後標靶要持續
    保持倒下狀態作為「系統已被攻擊」的視覺證據，直到人工觸發 docker compose
    restart（會走 shutdown_handler → servo 回 500）才會復位。

    後續攻擊會繼續觸發 [MOTOR] log（用於偵測率統計），但 servo 已經在
    SERVO_DOWN，再送相同脈寬不會有實體動作。
    """
    global motor_triggered
    time.sleep(MOTOR_COOLDOWN)
    with motor_lock:
        motor_triggered = False
    log.info("[MOTOR] 馬達冷卻結束，可再次觸發（標靶保持倒下，需重啟系統復位）")

def _normalize_addr(ip_str):
    """把 IPv4-mapped IPv6（::ffff:1.2.3.4）轉回 IPv4，方便用 IPv4 白名單比對"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip

def bpf_event_consumer(whitelist):
    """
    Thread B：消費 bpf_probe.c 從 inet_sock_set_state tracepoint 推上來的事件。
    時鐘域：event.ts_ns 來自 BPF helper bpf_ktime_get_ns()，是 CLOCK_MONOTONIC；
    event.recv_ts_ns 與 t0/t1 用 time.monotonic_ns()，在 Linux 同樣是
    CLOCK_MONOTONIC。兩者直接相減得到的是真實 latency，不要混進 wall clock。
    """
    global motor_triggered
    probe = None
    try:
        probe = BpfReverseShellProbe(web_container_name=WEB_CONTAINER)
        log.info("[執行緒-B] eBPF Reverse Shell 監控啟動 (白名單已建立)")
        probe.start()
        for event in probe.iter_events(poll_timeout_ms=200):
            ip = _normalize_addr(event.daddr)
            if ip is None:
                continue
            if any(ip in net for net in whitelist):
                continue

            # Cooldown gates the servo command, not the log line:
            # detection-rate stats need every event recorded, while
            # the SG90 only needs to be commanded once per knock-down
            # (it stays at SERVO_DOWN until manual reset). See
            # motor_cooldown_reset() for the full rationale.
            latency_us = (event.recv_ts_ns - event.ts_ns) // 1000
            log.warning("[MOTOR] 命中 Reverse Shell (%s -> %s:%d, "
                        "comm=%s pid=%d) -> 擊倒標靶",
                        event.saddr, event.daddr, event.dport,
                        event.comm, event.pid)
            log.info("[LATENCY] kernel→user=%dµs", latency_us)

            # Hold motor_lock across the cooldown check AND the pigpio
            # call so _cleanup_hardware (which also takes motor_lock)
            # cannot interleave its SERVO_UP/sleep/stop sequence with
            # this thread's SERVO_DOWN command. t1 is when the pigpio
            # call returns — physical SG90 motion takes ~100-300ms more
            # which is intentionally NOT measured.
            fired = False
            t1: int | None = None
            pigpio_ok = False
            with motor_lock:
                if not motor_triggered:
                    motor_triggered = True
                    fired = True
                    if pi and pi.connected:
                        pi.set_servo_pulsewidth(PIN_SERVO, SERVO_DOWN)
                        t1 = time.monotonic_ns()
                        pigpio_ok = True

            if not fired:
                log.info("[MOTOR] 冷卻中 — 跳過 servo 動作（事件已記錄）")
                continue

            if pigpio_ok:
                log.info("[MOTOR] 馬達指令已發送 (pulse=%d)", SERVO_DOWN)
                log.info("[LATENCY] user→pigpio_return=%dµs",
                         (t1 - event.recv_ts_ns) // 1000)
                log.info("[LATENCY] total kernel→pigpio_return=%dµs",
                         (t1 - event.ts_ns) // 1000)
            else:
                log.error("[MOTOR] pigpio 未連線，無法控制馬達！請確認 pigpiod 狀態")

            # 啟動冷卻計時器
            threading.Thread(target=motor_cooldown_reset, daemon=True).start()
    except Exception as e:
        log.error("[執行緒-B] eBPF Reverse Shell 監控錯誤: %s", e)
    finally:
        if probe:
            try:
                probe.stop()
            except Exception:
                pass

# 主程式
def build_whitelist():
    """建立白名單：loopback + link-local + web-app 所在的 Docker 子網。

    刻意 fail-closed：拿不到 docker 子網就 raise，讓 defense 容器以
    非零狀態結束。compose 的 ``restart: unless-stopped`` 會讓它在
    ``docker compose ps`` 中顯示為 ``Restarting``，operator 看得到、
    避免在白名單不完整的狀態下默默運作（會誤把合法的 docker bridge
    流量當成 reverse shell）。也刻意 *不* 加 172.16/12 這種 RFC1918
    catchall — 那會把真實 LAN 上的攻擊者（例如 listener 在
    172.20.x.x）漏掉。
    """
    networks = [
        ipaddress.IPv4Network('127.0.0.0/8'),
        ipaddress.IPv4Network('169.254.0.0/16'),
        ipaddress.IPv6Network('::1/128'),
        ipaddress.IPv6Network('fe80::/10'),
    ]
    try:
        result = subprocess.run(
            ["docker", "inspect", WEB_CONTAINER, "--format", "{{json .NetworkSettings.Networks}}"],
            capture_output=True, text=True, timeout=5, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"docker inspect 失敗，無法取得 {WEB_CONTAINER} 的網段資訊；"
            "為避免在白名單不完整下誤判，defense 拒絕啟動。"
            f"原因：{exc}"
        ) from exc

    nets_json = json.loads(result.stdout.strip())
    added = 0
    for name, cfg in nets_json.items():
        gateway = cfg.get("Gateway", "")
        prefix = cfg.get("IPPrefixLen", 16)
        if not gateway:
            continue
        network_cls = (
            ipaddress.IPv4Network
            if ipaddress.ip_address(gateway).version == 4
            else ipaddress.IPv6Network
        )
        networks.append(network_cls(f"{gateway}/{prefix}", strict=False))
        log.info("[白名單] Docker 網段: %s/%s (from %s)", gateway, prefix, name)
        added += 1

    if added == 0:
        raise RuntimeError(
            f"docker inspect 回傳的 {WEB_CONTAINER} 網段為空；"
            "若繼續運行偵測會把所有對外流量視為 reverse shell。"
        )
    return networks

def main():
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s  %(message)s", force=True)
    log.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統 v3.0")
    log.info("  PIGPIO_HOST=%s", PIGPIO_HOST or "(未設定)")
    log.info("  WEB_CONTAINER=%s", WEB_CONTAINER)
    log.info("=" * 60)

    # 1. 硬體初始化
    hardware_setup()

    # 2. 建立白名單
    whitelist = build_whitelist()
    log.info("白名單: %s", [str(n) for n in whitelist])

    # 3. 啟動監控執行緒
    #    - Thread A (LED1/LED2) 永遠啟動，與 BPF 解耦
    #    - Thread B (eBPF Reverse Shell) 只在 bcc 可用時啟動；失敗不會拖垮 Thread A
    t1 = threading.Thread(target=docker_log_monitor, daemon=True)
    t1.start()

    t2 = None
    if BPF_AVAILABLE:
        t2 = threading.Thread(target=bpf_event_consumer, args=(whitelist,), daemon=True)
        t2.start()
        log.info("所有監控執行緒已啟動，eBPF Reverse Shell 偵測就緒")
    else:
        log.warning("BPF 不可用 — 僅啟動 LED1/LED2 偵測，馬達將不會被觸發")

    # 主迴圈：只要 Thread A 活著就維持運行；Thread B 死掉只記 warning
    bpf_dead_logged = False
    while t1.is_alive():
        if t2 is not None and not t2.is_alive() and not bpf_dead_logged:
            log.error("[執行緒-B] eBPF Reverse Shell 監控已停止 — LED 偵測仍在運作")
            bpf_dead_logged = True
        time.sleep(1)
    log.error("[執行緒-A] LED 監控已停止，主程式結束")
    sys.exit(1)

if __name__ == "__main__":
    main()
