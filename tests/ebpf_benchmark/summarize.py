#!/usr/bin/env python3
"""彙整 latency CSV，丟掉前 N 筆暖機，印 p50/p95/p99 markdown 表格。"""
import argparse
import csv
import statistics


def percentile(vals, p):
    """線性插值法 percentile（與 numpy.percentile default 同義）。"""
    vals = sorted(vals)
    if not vals:
        return 0.0
    k = (len(vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(vals) - 1)
    if f == c:
        return vals[f]
    return vals[f] + (vals[c] - vals[f]) * (k - f)


def summarize(path, drop):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("latency_ms"):
                rows.append(row)
    rows.sort(key=lambda r: int(r["trial"]))
    rows = rows[drop:]
    vals = [float(r["latency_ms"]) for r in rows]
    if not vals:
        return None
    return {
        "mechanism": rows[0].get("mechanism", "?"),
        "interval": rows[0].get("polling_interval_ms", "N/A") or "N/A",
        "n": len(vals),
        "p50": percentile(vals, 50),
        "p95": percentile(vals, 95),
        "p99": percentile(vals, 99),
        "mean": statistics.mean(vals),
        "min": min(vals),
        "max": max(vals),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csvs", nargs="+")
    ap.add_argument("--drop-first", type=int, default=10,
                    help="丟掉前 N 筆（暖機效應）")
    args = ap.parse_args()

    print(f"\n===== Detection Latency (drop first {args.drop_first} warmup) =====\n")
    print("| Detection method | Polling interval | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) | min (ms) | max (ms) |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for path in args.csvs:
        s = summarize(path, args.drop_first)
        if not s:
            print(f"(no data) {path}")
            continue
        print(f"| {s['mechanism']} | {s['interval']} | {s['n']} | "
              f"{s['p50']:.3f} | {s['p95']:.3f} | {s['p99']:.3f} | "
              f"{s['mean']:.3f} | {s['min']:.3f} | {s['max']:.3f} |")
    print()


if __name__ == "__main__":
    main()
