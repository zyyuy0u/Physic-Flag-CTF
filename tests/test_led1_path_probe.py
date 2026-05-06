#!/usr/bin/env python3
"""
LED1 路徑探測自動化測試
========================
測試 defense-system 是否能在大量路徑請求中可靠偵測到 /admin 存取。

每一輪：
  1. 讀取 common.txt（4748 條路徑）
  2. 將 /admin 插入隨機位置
  3. 並發送出全部 4749 條 HTTP GET 請求
  4. 透過 docker logs 背景監控執行緒驗證 defense-system 是否偵測到

用法：
  python3 tests/test_led1_path_probe.py --start 1 --batch 100
"""

import argparse
import csv
import os
import random
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

# ---------------------------------------------------------------------------
# 設定
# ---------------------------------------------------------------------------
BASE_URL = os.environ.get("BASE_URL", "http://localhost:9090")
WORDLIST = os.path.join(os.path.dirname(__file__), "..", "common.txt")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
CONTAINER = "iot-honeypot-defense-system-1"
MAX_WORKERS = 50
LED1_PATTERN = re.compile(r"\[LED1\]")

# 每輪結束後等待 defense-system 處理日誌的寬限時間（秒）
DETECTION_GRACE_PERIOD = 3

# HTTP 請求逾時（秒）
REQUEST_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Docker Log 背景監控執行緒
# ---------------------------------------------------------------------------
class DockerLogMonitor:
    """背景執行緒，串流讀取 defense-system 的 docker logs，
    計算 [LED1] 出現次數。"""

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
                if LED1_PATTERN.search(line):
                    with self._lock:
                        self.count += 1
        except Exception as exc:
            print(f"[監控執行緒] 錯誤：{exc}")


# ---------------------------------------------------------------------------
# 輔助函式
# ---------------------------------------------------------------------------
def load_wordlist(path):
    """讀取字典檔，返回路徑列表。"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def send_request(session, path):
    """發送單一 HTTP GET 請求，忽略錯誤。"""
    url = f"{BASE_URL}/{path.lstrip('/')}"
    try:
        session.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        pass


def run_round(round_id, paths, admin_pos, session):
    """執行單一輪次：並發送出所有路徑請求。"""
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(send_request, session, p) for p in paths]
        for f in as_completed(futures):
            pass  # 等待全部完成


# ---------------------------------------------------------------------------
# 主程式
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="LED1 路徑探測自動化測試")
    parser.add_argument("--start", type=int, default=1,
                        help="起始輪次（預設 1）")
    parser.add_argument("--batch", type=int, default=100,
                        help="批次大小（預設 100）")
    args = parser.parse_args()

    start = args.start
    end = start + args.batch - 1

    # 載入字典
    wordlist_path = os.path.abspath(WORDLIST)
    base_paths = load_wordlist(wordlist_path)
    print(f"已載入 {len(base_paths)} 條路徑（來自 {wordlist_path}）")

    # 確保結果目錄存在
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 啟動 Docker Log 監控
    monitor = DockerLogMonitor()
    monitor.start()
    print(f"Docker Log 監控已啟動（容器：{CONTAINER}）")

    # 準備 CSV
    csv_path = os.path.join(RESULTS_DIR, f"led1_batch_{start}_{end}.csv")
    csv_file = open(csv_path, "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(csv_file, fieldnames=[
        "round_id", "admin_position", "total_paths", "detected", "timestamp"
    ])
    writer.writeheader()

    detected_count = 0
    total_rounds = args.batch
    session = requests.Session()

    print(f"\n開始測試：第 {start} ~ {end} 輪（共 {total_rounds} 輪）\n")

    for round_id in range(start, end + 1):
        timestamp = datetime.now().isoformat()

        # 複製路徑列表，隨機插入 /admin
        paths = list(base_paths)
        admin_pos = random.randint(0, len(paths))
        paths.insert(admin_pos, "admin")
        total_paths = len(paths)

        # 記錄測試前的計數
        before = monitor.current_count

        # 執行本輪請求
        round_start = time.time()
        run_round(round_id, paths, admin_pos, session)
        elapsed = time.time() - round_start

        # 等待 defense-system 處理日誌
        time.sleep(DETECTION_GRACE_PERIOD)

        # 檢查是否偵測到
        after = monitor.current_count
        detected = after > before

        if detected:
            detected_count += 1

        # 寫入 CSV
        writer.writerow({
            "round_id": round_id,
            "admin_position": admin_pos,
            "total_paths": total_paths,
            "detected": detected,
            "timestamp": timestamp,
        })
        csv_file.flush()

        # 進度輸出
        status = "OK" if detected else "MISS"
        progress = round_id - start + 1
        print(f"  [{status}] 第 {round_id} 輪 | "
              f"admin@{admin_pos}/{total_paths} | "
              f"{elapsed:.1f}s | "
              f"進度 {progress}/{total_rounds}")

    # 清理
    csv_file.close()
    monitor.stop()

    # 摘要
    rate = (detected_count / total_rounds * 100) if total_rounds > 0 else 0
    print(f"\n{'=' * 60}")
    print(f"Batch {start}-{end}: "
          f"{detected_count}/{total_rounds} detected ({rate:.1f}%)")
    print(f"結果已儲存至：{csv_path}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
