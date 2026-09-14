# eBPF Detection-Latency Benchmark

獨立 microbenchmark：量「事件驅動 eBPF」vs「定時輪詢 log」的偵測延遲差距。

> **重要**：這份 benchmark **跟 honeypot 三階段偵測無關**。它用 `sys_enter_openat` 當乾淨的人造事件，純粹驗證「機制本身」的延遲。它**不會**動到 honeypot 的 docker 容器、防禦監控、GPIO，也不需要停掉 docker stack。

## 一次性環境準備（Pi 上）

```bash
sudo apt update
sudo apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r) tmux
# 驗證
sudo python3 -c "from bcc import BPF; print('BCC OK')"
```

## 執行（Pi 上）

需要 **3 個 terminal**（用 tmux 或 3 個 SSH session 都可）。

```bash
# 通用：產生 run-id
RUN_ID="run-$(date +%s)"

# Terminal 1（root）— eBPF 偵測器
sudo python3 tests/ebpf_benchmark/ebpf_detect.py --run-id "$RUN_ID" --limit 110

# Terminal 2 — 輪詢 baseline（先別動 Terminal 3，等這兩個都印 "ready"）
python3 tests/ebpf_benchmark/poll_detect.py --run-id "$RUN_ID" --interval-ms 100 --limit 110

# Terminal 3 — 觸發 110 events（約 15 秒）
python3 tests/ebpf_benchmark/trigger.py --run-id "$RUN_ID" --n 110 --gap-ms 137
```

跑完後三個 process 都會自動結束。CSV 在 `/tmp/ctfbench/`：

```bash
ls /tmp/ctfbench/
# ebpf_latency.csv  poll_latency.csv  ctf_event.log  markers/
```

## 出表格

```bash
python3 tests/ebpf_benchmark/summarize.py --drop-first 10 \
  /tmp/ctfbench/ebpf_latency.csv \
  /tmp/ctfbench/poll_latency.csv
```

預期輸出（數字實測會異動）：

```
| Detection method        | Polling interval | n   | p50 (ms) | p95 (ms) | p99 (ms) |
|-------------------------|------------------|----:|---------:|---------:|---------:|
| ebpf_openat_tracepoint  | N/A              | 100 |    0.050 |    0.200 |    0.500 |
| log_polling             | 100              | 100 |   51.000 |   98.000 |  100.000 |
```

## 設計重點

- **時鐘**：`time.monotonic_ns()`（CLOCK_MONOTONIC，跨 process 一致）
- **t0 傳遞**：嵌進 marker 檔名，eBPF 端零 IPC
- **公平性**：log 寫入後 `flush()` + `fsync()`，避免輪詢端被 buffer 不公平拖慢
- **避免相位鎖定**：`gap-ms=137`（質數，與輪詢間隔互質）
- **暖機**：110 trials 丟掉前 10，報 100 筆 warm-state

## 為什麼需要 root

`sudo` 是 eBPF / tracepoint 的要求，不是腳本要做特權動作。`ebpf_detect.py` 不會碰任何 host 檔案，只在 `/tmp/ctfbench/` 寫 CSV。

## 清掉實驗暫存

```bash
rm -rf /tmp/ctfbench/
```

`/tmp` 是 tmpfs，重開機自然消失。
