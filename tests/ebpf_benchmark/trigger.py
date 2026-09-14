#!/usr/bin/env python3
"""觸發器：連續產生 marker file 開檔事件，t0_ns 編碼在檔名。

兩個偵測器 (ebpf_detect.py / poll_detect.py) 共用這個觸發源：
- ebpf_detect 透過 sys_enter_openat tracepoint 直接拿到檔名，解出 t0_ns
- poll_detect 讀 ctf_event.log（JSON-lines）解出 t0_ns

時鐘：time.monotonic_ns()，跨 process CLOCK_MONOTONIC 一致。
"""
import argparse
import json
import os
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True, help="唯一實驗識別字串")
    ap.add_argument("--n", type=int, default=110,
                    help="總 trials 數（建議 110：丟前 10 暖機 + 100 量測）")
    ap.add_argument("--gap-ms", type=int, default=137,
                    help="事件間隔（毫秒）。預設 137 與 100ms 互質，避免相位鎖定")
    ap.add_argument("--base", default="/tmp/ctfbench")
    args = ap.parse_args()

    marker_dir = os.path.join(args.base, "markers")
    log_path = os.path.join(args.base, "ctf_event.log")
    os.makedirs(marker_dir, exist_ok=True)
    # append-only：偵測器邊讀邊寫不會被 truncate
    open(log_path, "a").close()

    print(f"[TRIGGER] run_id={args.run_id} n={args.n} gap_ms={args.gap_ms}")
    print(f"[TRIGGER] marker_dir={marker_dir}")
    print(f"[TRIGGER] log={log_path}")
    print(f"[TRIGGER] 預計總時長: {args.n * args.gap_ms / 1000:.1f} s")

    for trial in range(args.n):
        t0_ns = time.monotonic_ns()
        # 檔名編碼：CTF_<run_id>_<trial>_<t0_ns>.flag
        # 這次 open() 就是 eBPF 要捕捉的目標事件
        fname = f"CTF_{args.run_id}_{trial}_{t0_ns}.flag"
        path = os.path.join(marker_dir, fname)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.write(fd, b"FLAG{synthetic_marker}\n")
        os.close(fd)

        # 同步寫進 log 給輪詢端讀。flush+fsync 強制落盤，避免 buffer 拖慢輪詢
        record = {"run_id": args.run_id, "trial": trial, "t0_ns": t0_ns, "path": path}
        with open(log_path, "a") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())

        if trial % 20 == 0 or trial == args.n - 1:
            print(f"  trial={trial} t0_ns={t0_ns}", flush=True)
        time.sleep(args.gap_ms / 1000.0)

    print("[TRIGGER] done.")


if __name__ == "__main__":
    main()
