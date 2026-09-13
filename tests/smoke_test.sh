#!/bin/bash
# 端到端煙霧測試：一次驗證三階段偵測都活著
# 用法（在 Pi 上、docker compose up -d 已起來後）：
#   bash tests/smoke_test.sh
#   BASE_URL=http://<Pi的Wi-Fi-IP>:8080 REVERSE_TARGET_IP=<電腦的Wi-Fi-IP> bash tests/smoke_test.sh
# REVERSE_TARGET_IP 指定 LAN 內的測試設備，該設備不用啟動 listener。
#
# 不蒐集統計，純粹檢查 [LED1]、[BUZZER]、[MOTOR] 三個標記都會在 log 中出現。
# 馬達冷卻 5 秒，所以三階段中間有 sleep。

set -u

BASE_URL="${BASE_URL:-http://localhost:8080}"
REVERSE_TARGET_IP="${REVERSE_TARGET_IP:-8.8.8.8}"
REVERSE_TARGET_PORT="${REVERSE_TARGET_PORT:-12345}"
CONTAINER=$(docker ps --filter "name=defense-system" --format "{{.Names}}" | head -1)
WEB=$(docker ps --filter "name=web-app" --format "{{.Names}}" | head -1)

if [ -z "$CONTAINER" ] || [ -z "$WEB" ]; then
    echo "ERROR: 找不到 defense-system 或 web-app 容器，請先 docker compose up -d"
    exit 1
fi

echo "Defense container: $CONTAINER"
echo "Web container:     $WEB"
echo "Base URL:          $BASE_URL"
echo

# 抓現在 log 行數作為 baseline，後面只看新增的行
BASELINE=$(docker logs "$CONTAINER" 2>&1 | wc -l)
new_logs() { docker logs "$CONTAINER" 2>&1 | tail -n +$((BASELINE + 1)); }

FAIL_COUNT=0
check() {
    if new_logs | grep -q "$1"; then
        echo "  [PASS] $1"
    else
        echo "  [FAIL] $1"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# -------- Stage 1: LED1 (/admin 路徑探測) --------
echo "====== Stage 1: LED1 (/admin probe) ======"
curl -s -o /dev/null "$BASE_URL/admin"
sleep 2
check "\[LED1\] 命中 /admin"

# -------- Stage 2: BUZZER (SQLi/auth 繞過) --------
echo
echo "====== Stage 2: BUZZER (SQLi/auth bypass) ======"
COOKIE=$(mktemp)
CSRF=$(curl -s -c "$COOKIE" "$BASE_URL/admin_login_v2.php" \
       | grep -oE 'name="csrf_token"[^>]+value="[^"]+"' \
       | grep -oE 'value="[^"]+"' | cut -d'"' -f2)
if [ -z "$CSRF" ]; then
    echo "  [FAIL] 無法取得 CSRF token，可能登入頁結構變了"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    curl -s -b "$COOKIE" -c "$COOKIE" "$BASE_URL/admin_login_v2.php" \
        --data-urlencode "username=' OR 1=1 -- " \
        --data-urlencode "password=x" \
        --data-urlencode "csrf_token=$CSRF" \
        -L -o /dev/null
    sleep 2
    check "\[BUZZER\] 命中 SQLi"
fi
rm -f "$COOKIE"

# -------- Stage 3: MOTOR (Reverse Shell SYN_SENT) --------
echo
echo "====== Stage 3: MOTOR (reverse shell SYN_SENT) ======"
echo "從 web-app 內對 $REVERSE_TARGET_IP:$REVERSE_TARGET_PORT 發 SYN（不需 listener，eBPF 在 SYN_SENT 即觸發）"
if ! docker exec "$WEB" python3 -c '
import ipaddress
import socket
import sys

address = ipaddress.IPv4Address(sys.argv[1])
port = int(sys.argv[2])
if not 1 <= port <= 65535:
    raise ValueError("port must be between 1 and 65535")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(1)
    sock.connect_ex((str(address), port))
' "$REVERSE_TARGET_IP" "$REVERSE_TARGET_PORT"; then
    echo "  [FAIL] 無法送出 TCP 連線測試，請檢查目標 IPv4、埠與 web-app 狀態"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
sleep 2
check "\[MOTOR\] 命中 Reverse Shell"

# -------- Latency summary --------
echo
echo "====== Latency markers ======"
new_logs | grep "\[LATENCY\]" || echo "  (未捕捉到 [LATENCY]，可能 Stage 3 沒觸發)"

echo
echo "====== 完整新增 log（debug 用）======"
new_logs | grep -E '\[(LED1|BUZZER|MOTOR|LATENCY|執行緒)' | head -30

echo
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "====== 結果：FAIL（$FAIL_COUNT 個檢查失敗）======"
    exit 1
else
    echo "====== 結果：PASS（三階段全通）======"
    exit 0
fi
