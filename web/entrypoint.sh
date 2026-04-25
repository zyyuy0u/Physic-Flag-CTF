#!/bin/bash
set -e

# 等待資料庫就緒
HOST="${DB_HOST:-db}"
USER="${DB_USER:-webuser}"
PASS="${DB_PASS:-webpass123}"

echo "--- [自動初始化] 等待 MariaDB 伺服器 ($HOST) 響應中... ---"

MAX_RETRIES=30
COUNT=0

until php -r "
\$conn = @new mysqli('$HOST', '$USER', '$PASS');
if (\$conn->connect_error) {
    exit(1);
}
\$conn->close();
" > /dev/null 2>&1; do
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "錯誤：等待資料庫連線逾時 ($MAX_RETRIES 次重試)。"
    exit 1
  fi
  echo "資料庫尚未就緒 ($COUNT/$MAX_RETRIES)，等待 2 秒..."
  sleep 2
done

echo "--- [自動初始化] 伺服器已就緒！執行初始化... ---"
php /var/www/html/setup_db.php

echo "--- [自動初始化] 啟動主服務: $@ ---"

# 執行主指令 (apache2-foreground)
exec "$@"
