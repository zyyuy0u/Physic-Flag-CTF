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

# ---------------------------------------------------------------------------
# RPi.GPIO 載入
# ---------------------------------------------------------------------------
# 嘗試載入 Raspberry Pi 的 GPIO 函式庫
# 若在非 Pi 環境（如 Mac/PC）執行，會自動切換為模擬模式（僅輸出日誌）
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False
    logging.warning("RPi.GPIO 無法使用 — 以模擬模式運行")

# ---------------------------------------------------------------------------
# 組態設定
# ---------------------------------------------------------------------------
# GPIO 腳位定義（BCM 編號，非物理腳位編號）
PIN_YELLOW = 17   # LED1：/admin 路徑探測警示
PIN_RED    = 27   # LED2：SQL Injection 繞過警示
PIN_GREEN  = 22   # LED3：Reverse Shell 警示

# 要監控的 Docker 容器名稱（可透過環境變數覆蓋）
WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "web-app")

# Netstat 持續監控的取樣間隔（容器內部迴圈的 sleep 秒數）
NETSTAT_INTERVAL = 1

# Web 容器對外服務的端口（用於排除正常 HTTP 連線）
WEB_SERVICE_PORT = "80"

# ---------------------------------------------------------------------------
# Regex 比對規則
# ---------------------------------------------------------------------------
# LED1：比對 Apache Log 中的 GET /admin 路徑存取
# 範例命中：GET /admin HTTP/1.1、GET /admin/ HTTP/1.1、GET /admin?x=1 HTTP/1.1
# [\s/\?] 確保是完整的 /admin 路徑，避免誤判 /administrator 等
ADMIN_PATTERN = re.compile(r'GET /admin[\s/\?]')

# LED2：比對 Apache Log 中 dashboard.php 回傳 HTTP 200 的紀錄
# 範例命中："GET /dashboard.php HTTP/1.1" 200 1234
# 正常情況下未登入存取 dashboard.php 會被 302 重導，
# 若回傳 200 代表攻擊者已繞過登入驗證（SQL Injection）
DASHBOARD_PATTERN = re.compile(r'"GET /dashboard\.php\b[^"]*"\s+200\b')

# ---------------------------------------------------------------------------
# IP 白名單（啟動時自動偵測 Docker 網段）
# ---------------------------------------------------------------------------
def build_whitelist():
    """
    建立 IP 白名單：
    1. 固定加入 Loopback（127.x.x.x）和 Link-local（169.254.x.x）
    2. 透過 docker inspect 查詢 web 容器的網路設定，
       取得 Gateway IP 和子網路遮罩長度，算出容器所屬的 Docker 網段
    3. 將該網段加入白名單，這樣容器間的正常通訊不會被誤判
    4. 若偵測失敗（例如容器尚未啟動），最多重試 10 次（每次間隔 3 秒）
    5. 全部重試失敗後，使用保守的 172.16.0.0/12 作為預設值
    """
    networks = [
        ipaddress.ip_network('127.0.0.0/8'),        # Loopback
        ipaddress.ip_network('169.254.0.0/16'),      # Link-local
    ]

    # 重試機制：等待 web 容器啟動完成
    for attempt in range(10):
        try:
            # 執行 docker inspect 取得容器的網路設定（JSON 格式）
            result = subprocess.run(
                ["docker", "inspect", WEB_CONTAINER,
                 "--format", "{{json .NetworkSettings.Networks}}"],
                capture_output=True, text=True, timeout=10,
            )
            # 解析每個網路的 Gateway 和子網路遮罩長度
            # 例如：Gateway=172.21.0.1, IPPrefixLen=16 → 172.21.0.0/16
            for name, cfg in json.loads(result.stdout.strip()).items():
                gateway = cfg.get("Gateway", "")
                prefix = cfg.get("IPPrefixLen", 16)
                if gateway:
                    net = ipaddress.ip_network(f"{gateway}/{prefix}", strict=False)
                    networks.append(net)
            return networks
        except Exception:
            logging.warning("白名單偵測失敗（第 %d/10 次），3 秒後重試…", attempt + 1)
            time.sleep(3)

    # 全部重試失敗，使用保守預設值（涵蓋所有 Docker 預設網段）
    logging.warning("白名單偵測全部失敗，使用預設值 172.16.0.0/12")
    networks.append(ipaddress.ip_network('172.16.0.0/12'))
    return networks

# ---------------------------------------------------------------------------
# 日誌設定
# ---------------------------------------------------------------------------
# force=True 是關鍵：因為 RPi.GPIO import 時可能已觸發 logging.warning()，
# 導致 basicConfig 被提前以預設值（WARNING 等級）初始化。
# 加上 force=True 可強制覆蓋，確保 INFO 等級的日誌也能正常輸出。
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
    """初始化 GPIO 腳位為輸出模式，預設電位為 LOW（LED 不亮）。"""
    if not GPIO_AVAILABLE:
        log.info("GPIO 模擬模式：腳位 %s 設為 OUTPUT/LOW",
                 [PIN_YELLOW, PIN_RED, PIN_GREEN])
        return
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)       # 使用 BCM 編號（非物理腳位）
    for pin in (PIN_YELLOW, PIN_RED, PIN_GREEN):
        GPIO.setup(pin, GPIO.OUT, initial=GPIO.LOW)
    log.info("GPIO 已初始化（BCM 模式）")


def led_on(pin, label=""):
    """將指定 GPIO 腳位設為 HIGH（LED 亮燈），觸發後不會自動熄滅。"""
    if GPIO_AVAILABLE:
        GPIO.output(pin, GPIO.HIGH)
    log.warning("LED 常亮 -> GPIO %d  [%s]", pin, label)


# ---------------------------------------------------------------------------
# 執行緒 A — Docker Log 即時監控（LED1 + LED2）
# ---------------------------------------------------------------------------
def docker_log_monitor():
    """
    【運作原理】
    使用 subprocess.Popen 執行 docker logs -f --tail 0，
    以串流方式即時讀取 web 容器的 Apache Access Log。

    --tail 0 表示只讀取啟動後的新日誌，不讀取歷史紀錄。
    -f 表示持續追蹤（類似 tail -f），有新日誌就立刻輸出。

    主程式透過 for line in proc.stdout 逐行讀取，
    每收到一行就立刻用 Regex 比對，達到即時偵測效果。

    【偵測邏輯】
    LED1：比對到 GET /admin 路徑 → 有人在探測管理後台
    LED2：比對到 dashboard.php 回傳 200 → SQL Injection 繞過成功

    【容錯機制】
    若 docker logs 程序意外結束（例如容器重啟），
    等待 3 秒後自動重新連接。
    """
    log.info("[執行緒-A] Docker Log 監控已啟動（容器：%s）", WEB_CONTAINER)

    led1_triggered = False
    led2_triggered = False

    while True:
        try:
            # 啟動持續串流的子程序，即時讀取容器日誌
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "0", WEB_CONTAINER],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            # 逐行即時讀取日誌（阻塞式，有新日誌才會往下走）
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                # LED1：比對 /admin 路徑存取
                if not led1_triggered and ADMIN_PATTERN.search(line):
                    log.warning("[LED1] 偵測到 /admin 路徑存取：%s", line)
                    led_on(PIN_YELLOW, "/admin 路徑探測")
                    led1_triggered = True

                # LED2：比對 dashboard.php HTTP 200（SQL Injection 繞過）
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
# 執行緒 B — Netstat 持續監控（LED3）
# ---------------------------------------------------------------------------
def netstat_monitor(whitelist):
    """
    【運作原理】
    使用 subprocess.Popen 在 web 容器內啟動一個持續運行的 bash 迴圈，
    每秒執行一次 netstat -tn，並將結果即時串流回主程式。

    與執行緒 A 的架構相同：都是透過 Popen 建立持續串流的子程序，
    主程式逐行讀取輸出並即時分析，不需要反覆建立新的 docker exec 程序。

    每次 netstat 輸出結束後，會印出一行分隔符號 ---SNAPSHOT---，
    用來區分不同時間點的快照。

    【偵測邏輯】
    1. 逐行讀取 netstat 輸出
    2. 篩選 ESTABLISHED 狀態的連線（代表已建立的 TCP 連線）
    3. 檢查本地端口 — 若為 80（Web 服務），代表是正常的 HTTP 連線，跳過
    4. 解析遠端 IP 位址
    5. 比對 IP 白名單（Docker 內部網段、Loopback、Link-local）
    6. 若本地端口非 80 且遠端 IP 非白名單 → 判定為 Reverse Shell

    【為何要排除端口 80】
    netstat 顯示的 ESTABLISHED 連線包含兩種：
      - 正常 HTTP：外部瀏覽器 → 容器:80（本地端口 80，對方連進來）
      - Reverse Shell：容器:隨機端口 → 攻擊者:監聽端口（容器主動連出去）
    不排除端口 80 的話，任何瀏覽網站的人都會觸發 LED3（誤判）。

    【容錯機制】
    若容器內的 bash 程序意外結束，等待 3 秒後自動重新連接。
    """
    log.info("[執行緒-B] Netstat 持續監控已啟動（容器：%s，取樣間隔：%ds）",
             WEB_CONTAINER, NETSTAT_INTERVAL)

    triggered = False

    while True:
        try:
            # 在容器內啟動持續運行的 bash 迴圈
            # 每 NETSTAT_INTERVAL 秒執行一次 netstat，結果即時串流回主程式
            # ---SNAPSHOT--- 作為每次快照的分隔符號
            proc = subprocess.Popen(
                [
                    "docker", "exec", WEB_CONTAINER,
                    "bash", "-c",
                    f"while true; do "
                    f"netstat -tn 2>/dev/null; "
                    f"echo '---SNAPSHOT---'; "
                    f"sleep {NETSTAT_INTERVAL}; "
                    f"done"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            # 逐行即時讀取 netstat 輸出
            for line in proc.stdout:
                line = line.strip()

                # 跳過分隔符號、空行、表頭
                if not line or line == "---SNAPSHOT---":
                    continue
                if "ESTABLISHED" not in line:
                    continue

                # 已觸發過就不再分析，但保持程序運行
                if triggered:
                    continue

                # 解析 netstat 輸出行
                # 格式：Proto Recv-Q Send-Q Local_Address Foreign_Address State
                # 範例：tcp   0      0      172.21.0.3:80  172.20.10.2:54321 ESTABLISHED
                parts = line.split()
                if len(parts) < 5:
                    continue

                # 取出本地位址（第 4 欄），格式為 IP:PORT
                local_addr = parts[3]
                local_port = local_addr.rsplit(":", 1)[-1]

                # 排除本地端口 80 的連線 — 這是正常的 HTTP 請求
                # 瀏覽器連進來：Local=容器:80, Foreign=瀏覽器:隨機Port → 正常
                # Reverse Shell：Local=容器:隨機Port, Foreign=攻擊者:Port → 異常
                if local_port == WEB_SERVICE_PORT:
                    continue

                # 取出遠端位址（第 5 欄），格式為 IP:PORT
                foreign_addr = parts[4]
                ip_str = foreign_addr.rsplit(":", 1)[0]

                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue

                # 比對 IP 白名單
                # 若遠端 IP 屬於白名單中的任一網段，視為正常的容器間通訊
                # 例如：容器連接 db（172.21.0.2）屬於 Docker 內部網段，正常
                if any(ip in net for net in whitelist):
                    continue

                # 本地端口非 80 + 遠端 IP 非白名單 → Reverse Shell
                log.warning("[LED3] 偵測到非白名單連線：%s（本地端口：%s）"
                            "→ 判定為 Reverse Shell", foreign_addr, local_port)
                led_on(PIN_GREEN, f"Reverse Shell → {foreign_addr}")
                triggered = True

            proc.wait()
            log.warning("[執行緒-B] netstat 程序結束（代碼：%d），"
                        "3 秒後重試…", proc.returncode)

        except Exception as exc:
            log.error("[執行緒-B] 監控錯誤：%s", exc)

        time.sleep(3)


# ---------------------------------------------------------------------------
# 主程式
# ---------------------------------------------------------------------------
def main():
    """
    程式進入點：
    1. 顯示系統資訊（監控容器名稱、GPIO 模式）
    2. 建立 IP 白名單（含重試機制，等待 web 容器就緒）
    3. 初始化 GPIO 腳位
    4. 啟動兩個背景執行緒（daemon=True，主程式結束時自動終止）
    5. 主執行緒進入無限等待，直到收到 Ctrl+C 中斷
    """
    log.info("=" * 60)
    log.info("  IoT 蜜罐防禦監控系統")
    log.info("  監控容器：%s", WEB_CONTAINER)
    log.info("  GPIO 模式：%s", "實體硬體" if GPIO_AVAILABLE else "模擬模式")
    log.info("=" * 60)

    # 建立白名單（含重試機制）
    whitelist = build_whitelist()
    log.info("  白名單網段：%s", [str(n) for n in whitelist])

    gpio_setup()

    threads = [
        threading.Thread(target=docker_log_monitor,
                         name="Docker-Log-監控", daemon=True),
        threading.Thread(target=netstat_monitor, args=(whitelist,),
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
