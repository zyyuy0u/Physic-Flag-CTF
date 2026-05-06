#!/usr/bin/env python3
"""
LED2 SQL Injection 自動化測試
==============================
測試 defense-system 是否能可靠偵測 SQL Injection 繞過登入。

對 Generic-SQLi.txt 的每一條 payload（268 條）：
  1. 建立全新 HTTP session
  2. GET admin_login_v2.php 取得 CSRF token
  3. POST 登入表單（username=payload, password=test123）
  4. 判斷 bypass 是否成功（302 → dashboard.php → 200）
  5. 透過 docker logs 背景監控執行緒驗證偵測結果

用法：
  python3 tests/test_led2_sqli.py
"""

import csv
import os
import re
import subprocess
import threading
import time
from datetime import datetime

import requests

# ---------------------------------------------------------------------------
# 設定
# ---------------------------------------------------------------------------
BASE_URL = os.environ.get("BASE_URL", "http://localhost:9090")
LOGIN_URL = f"{BASE_URL}/admin_login_v2.php"
DASHBOARD_URL = f"{BASE_URL}/dashboard.php"
PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "..", "Generic-SQLi.txt")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
CONTAINER = "iot-honeypot-defense-system-1"

CSRF_PATTERN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')
LED2_PATTERN = re.compile(r"\[LED2\]")

# 每條 payload 測試後等待 defense-system 處理的寬限時間（秒）
DETECTION_GRACE_PERIOD = 3

# HTTP 請求逾時（秒）
REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Docker Log 背景監控執行緒
# ---------------------------------------------------------------------------
class DockerLogMonitor:
    """背景執行緒，串流讀取 defense-system 的 docker logs，
    計算 [LED2] 出現次數。"""

    def __init__(self):
        self.count = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._proc = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # 等待 docker logs 連線建立
        time.sleep(1)

    def stop(self):
        self._stop_event.set()
        if self._proc:
            self._proc.terminate()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def current_count(self):
        with self._lock:
            return self.count

    def _run(self):
        try:
            self._proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "0", CONTAINER],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in self._proc.stdout:
                if self._stop_event.is_set():
                    break
                if LED2_PATTERN.search(line):
                    with self._lock:
                        self.count += 1
        except Exception as exc:
            print(f"[監控執行緒] 錯誤：{exc}")


# ---------------------------------------------------------------------------
# 輔助函式
# ---------------------------------------------------------------------------
def load_payloads(path):
    """讀取 SQLi payload 字典檔。"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def test_payload(payload):
    """
    對單一 payload 執行完整的 SQLi 測試流程。

    回傳：(bypass_success: bool, http_status: int)
    """
    session = requests.Session()

    try:
        # Step 1: GET 登入頁面，取得 CSRF token
        resp = session.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
        match = CSRF_PATTERN.search(resp.text)
        if not match:
            return False, 0

        csrf_token = match.group(1)

        # Step 2: POST 登入表單
        data = {
            "username": payload,
            "password": "test123",
            "csrf_token": csrf_token,
        }
        resp = session.post(LOGIN_URL, data=data,
                            allow_redirects=False,
                            timeout=REQUEST_TIMEOUT)

        # Step 3: 判斷 bypass
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            if "dashboard.php" in location:
                # 跟隨 redirect，確認 dashboard 回傳 200
                dash_resp = session.get(DASHBOARD_URL, timeout=REQUEST_TIMEOUT)
                return dash_resp.status_code == 200, dash_resp.status_code

        return False, resp.status_code

    except requests.RequestException:
        return False, 0


# ---------------------------------------------------------------------------
# 主程式
# ---------------------------------------------------------------------------
def main():
    # 載入 payloads
    payload_path = os.path.abspath(PAYLOAD_FILE)
    payloads = load_payloads(payload_path)
    print(f"已載入 {len(payloads)} 條 SQLi payload（來自 {payload_path}）")

    # 確保結果目錄存在
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 啟動 Docker Log 監控
    monitor = DockerLogMonitor()
    monitor.start()
    print(f"Docker Log 監控已啟動（容器：{CONTAINER}）")

    # 準備 CSV
    csv_path = os.path.join(RESULTS_DIR, "led2_sqli_results.csv")
    csv_file = open(csv_path, "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(csv_file, fieldnames=[
        "payload_id", "payload", "bypass_success", "detected",
        "http_status", "timestamp"
    ])
    writer.writeheader()

    bypass_count = 0
    detected_count = 0
    anomaly_missed = []    # bypass=True, detected=False
    anomaly_false = []     # bypass=False, detected=True
    total = len(payloads)

    print(f"\n開始測試：共 {total} 條 payload\n")

    for idx, payload in enumerate(payloads, start=1):
        timestamp = datetime.now().isoformat()

        # 記錄測試前的計數
        before = monitor.current_count

        # 執行測試
        bypass_success, http_status = test_payload(payload)

        # 等待 defense-system 處理日誌
        time.sleep(DETECTION_GRACE_PERIOD)

        # 檢查是否偵測到
        after = monitor.current_count
        detected = after > before

        if bypass_success:
            bypass_count += 1
        if detected:
            detected_count += 1

        # 分類結果
        if bypass_success and not detected:
            anomaly_missed.append(idx)
            status = "MISS"
        elif not bypass_success and detected:
            anomaly_false.append(idx)
            status = "FALSE+"
        elif bypass_success and detected:
            status = "OK"
        else:
            status = "--"

        # 寫入 CSV
        writer.writerow({
            "payload_id": idx,
            "payload": payload,
            "bypass_success": bypass_success,
            "detected": detected,
            "http_status": http_status,
            "timestamp": timestamp,
        })
        csv_file.flush()

        # 進度輸出（截斷過長的 payload）
        display_payload = payload[:50] + "..." if len(payload) > 50 else payload
        print(f"  [{status:>6}] #{idx:>3}/{total} | "
              f"bypass={str(bypass_success):>5} | "
              f"detected={str(detected):>5} | "
              f"HTTP {http_status:>3} | "
              f"{display_payload}")

    # 清理
    csv_file.close()
    monitor.stop()

    # 摘要
    print(f"\n{'=' * 60}")
    print(f"Total payloads: {total}")
    print(f"Bypass successful: {bypass_count}")
    print(f"Bypass detected: {detected_count}")
    if bypass_count > 0:
        det_rate = detected_count / bypass_count * 100
        print(f"Detection rate: {det_rate:.1f}% ({detected_count}/{bypass_count})")
    else:
        print("Detection rate: N/A (no bypass succeeded)")

    if anomaly_missed:
        print(f"\n  ANOMALY - Bypass but NOT detected: {anomaly_missed}")
    if anomaly_false:
        print(f"\n  ANOMALY - No bypass but detected: {anomaly_false}")

    print(f"\n結果已儲存至：{csv_path}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
