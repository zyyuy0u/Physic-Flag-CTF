#!/bin/bash
set -e

# 等待資料庫就緒
# 使用環境變數中的 DB_HOST，預設為 'db'
HOST="${DB_HOST:-db}"
PORT=3306

echo "--- 等待資料庫 ($HOST:$PORT) 啟動中... ---"

# 持續偵測 3306 端口是否開放
until nc -z "$HOST" "$PORT"; do
  echo "資料庫尚未就緒，2 秒後重試..."
  sleep 2
done

echo "--- 資料庫已連線，開始初始化資料庫... ---"

# 執行初始化腳本
php /var/www/html/setup_db.php

echo "--- 初始化完成，啟動 Apache 服務 ---"

# 執行 Dockerfile 原本的啟動指令 (apache2-foreground)
exec "$@"
