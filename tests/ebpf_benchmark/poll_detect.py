#!/usr/bin/env python3
"""輪詢 baseline 偵測器：每 --interval-ms 毫秒檢查 log 檔，模擬「每 N 毫秒掃一次 log」的傳統做法。

行為：
  1. 從目前 log 檔 EOF 開始 tail（不重讀歷史紀錄）
  2. 主迴圈：sleep -> 讀新行 -> 記 detect_user_ns -> 算 latency

這份設計刻意把 detect_user_ns 記在「讀完新行的當下」而不是「行寫進去的當下」——
這正是「輪詢」的本質：直到我下一次去看，我才知道有新事件。
所以 latency 期望值 ≈ interval / 2，最壞 ≈ interval。
"""
import argparse
import csv
import json
import os
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--log", default="/tmp/ctfbench/ctf_event.log")
    ap.add_argument("--csv", default="/tmp/ctfbench/poll_latency.csv")
    ap.add_argument("--interval-ms", type=int, default=100,
                    help="輪詢週期（毫秒）。100 是常見教育平台預設")
    ap.add_argument("--limit", type=int, default=110)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.csv), exist_ok=True)
    open(args.log, "a").close()

    fields = ["mechanism", "run_id", "polling_interval_ms",
              "trial", "t0_ns", "detect_user_ns", "latency_ms"]
    seen, count = set(), 0

    with open(args.csv, "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        out.flush()

        # 從目前 EOF 開始 tail
        offset = os.path.getsize(args.log)

        print(f"[POLL] run_id={args.run_id} interval={args.interval_ms}ms "
              f"limit={args.limit} ready, waiting for trigger.py...", flush=True)

        try:
            while count < args.limit:
                cur_size = os.path.getsize(args.log)
                if cur_size < offset:  # log 被 truncate
                    offset = 0
                with open(args.log, "r") as f:
                    f.seek(offset)
                    lines = f.readlines()
                    offset = f.tell()

                # 「我發現的時間」記在讀完之後 —— 這是輪詢的真實延遲
                detect_user_ns = time.monotonic_ns()

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("run_id") != args.run_id:
                        continue
                    trial = int(item["trial"])
                    if trial in seen:
                        continue
                    seen.add(trial)
                    t0_ns = int(item["t0_ns"])
                    latency_ms = (detect_user_ns - t0_ns) / 1_000_000.0
                    writer.writerow({
                        "mechanism": "log_polling",
                        "run_id": args.run_id,
                        "polling_interval_ms": args.interval_ms,
                        "trial": trial,
                        "t0_ns": t0_ns,
                        "detect_user_ns": detect_user_ns,
                        "latency_ms": f"{latency_ms:.6f}",
                    })
                    out.flush()
                    count += 1
                    if trial % 20 == 0 or trial < 3:
                        print(f"[POLL] trial={trial} latency={latency_ms:.4f} ms", flush=True)
                    if count >= args.limit:
                        break

                time.sleep(args.interval_ms / 1000.0)
        except KeyboardInterrupt:
            pass

    print(f"[POLL] done. events={count} csv={args.csv}", flush=True)


if __name__ == "__main__":
    main()
