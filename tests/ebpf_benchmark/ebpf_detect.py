#!/usr/bin/env python3
"""eBPF 偵測器：掛 sys_enter_openat tracepoint，量 t0_ns -> user-space 偵測延遲。

Kernel side (BPF program)：每次 openat 進入時 perf_submit 一個事件，含 kernel_ts、pid、檔名。
User side：收到事件後 detect_user_ns = time.monotonic_ns()，從檔名 parse 出 t0_ns，
          latency = (detect_user_ns - t0_ns) / 1_000_000 毫秒。

Filename encoding 的好處：完全不需要查表/IPC，user-space 一拿到事件就有 t0。

需要 root 權限（BPF + tracepoint）。
"""
import argparse
import csv
import os
import re
import sys
import time
from bcc import BPF

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
struct data_t {
    u64 kernel_ts_ns;
    u32 pid;
    char filename[256];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.kernel_ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


def main():
    if os.geteuid() != 0:
        sys.exit("ERROR: 必須以 root 執行 (sudo python3 ebpf_detect.py ...)")

    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--csv", default="/tmp/ctfbench/ebpf_latency.csv")
    ap.add_argument("--limit", type=int, default=110, help="收到幾個 matching 事件後結束")
    ap.add_argument("--marker-dir", default="/tmp/ctfbench/markers")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.csv), exist_ok=True)
    pattern = re.compile(
        rf"CTF_{re.escape(args.run_id)}_(?P<trial>\d+)_(?P<t0>\d+)\.flag$"
    )

    b = BPF(text=BPF_PROGRAM)
    fields = ["mechanism", "run_id", "trial", "t0_ns",
              "detect_user_ns", "kernel_ts_ns", "latency_ms"]
    out = open(args.csv, "w", newline="")
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    out.flush()

    seen, state = set(), {"count": 0, "stop": False}

    def handle_event(cpu, data, size):
        # 第一動作就是記時，避免後續解析計入延遲
        detect_user_ns = time.monotonic_ns()
        event = b["events"].event(data)
        filename = event.filename.decode("utf-8", errors="replace")
        if args.marker_dir not in filename:
            return
        m = pattern.search(os.path.basename(filename))
        if not m:
            return
        trial = int(m.group("trial"))
        t0_ns = int(m.group("t0"))
        if trial in seen:
            return
        seen.add(trial)
        latency_ms = (detect_user_ns - t0_ns) / 1_000_000.0
        writer.writerow({
            "mechanism": "ebpf_openat_tracepoint",
            "run_id": args.run_id,
            "trial": trial,
            "t0_ns": t0_ns,
            "detect_user_ns": detect_user_ns,
            "kernel_ts_ns": event.kernel_ts_ns,
            "latency_ms": f"{latency_ms:.6f}",
        })
        out.flush()
        state["count"] += 1
        if trial % 20 == 0 or trial < 3:
            print(f"[eBPF] trial={trial} latency={latency_ms:.4f} ms", flush=True)
        if state["count"] >= args.limit:
            state["stop"] = True

    b["events"].open_perf_buffer(handle_event, page_cnt=64)
    print(f"[eBPF] run_id={args.run_id} limit={args.limit} ready, waiting for trigger.py...", flush=True)
    try:
        while not state["stop"]:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass
    finally:
        out.close()
        print(f"[eBPF] done. events={state['count']} csv={args.csv}", flush=True)


if __name__ == "__main__":
    main()
