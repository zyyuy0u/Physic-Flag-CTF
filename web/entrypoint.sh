#!/bin/bash
set -e

# 等待資料庫就緒
HOST="${DB_HOST:-db}"
USER="${DB_USER:-webuser}"
PASS="${DB_PASS:-webpass123}"
DB="${DB_NAME:-honeypot}"

echo "--- 等待資料庫 ($HOST) 真正就緒中... ---"

# 使用 PHP 腳本測試資料庫連線，而不只是看端口
# 我們會嘗試連線，如果失敗就等 2 秒再試
until php -r "
\$conn = @new mysqli('$HOST', '$USER', '$PASS', '$DB');
if (\$conn->connect_error) {
    exit(1);
}
\$conn->close();
" > /dev/null 2>&1; do
  echo "資料庫連線測試失敗（可能還在初始化），2 秒後重試..."
  sleep 2
done

echo "--- 資料庫已就緒！執行初始化腳本... ---"

# 執行初始化腳本
php /var/www/html/setup_db.php

echo "--- 初始化完成，啟動 Apache 服務 ---"

# 執行 Dockerfile 原本的啟動指令
exec "$@"
