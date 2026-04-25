#!/bin/bash
set -e

# 等待資料庫就緒
HOST="${DB_HOST:-db}"
USER="${DB_USER:-webuser}"
PASS="${DB_PASS:-webpass123}"

echo "--- [自動初始化] 等待 MariaDB 伺服器 ($HOST) 響應中... ---"

# 修正：連線測試不指定資料庫名稱 ($DB)，因為第一次啟動時資料庫還不存在
# 只要能連上伺服器，就代表可以執行 setup_db.php 了
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
    echo "錯誤：等待資料庫連線逾時 ($MAX_RETRIES 次重試)。請檢查 db 容器狀態。"
    exit 1
  fi
  echo "資料庫尚未就緒 ($COUNT/$MAX_RETRIES)，等待 2 秒..."
  sleep 2
done

echo "--- [自動初始化] 伺服器已就緒！開始執行初始化腳本... ---"

# 執行初始化腳本
# 注意：這裡必須路徑正確
if [ -f "/var/www/html/setup_db.php" ]; then
    php /var/www/html/setup_db.php
else
    echo "錯誤：找不到 /var/www/html/setup_db.php，跳過初始化。"
fi

echo "--- [自動初始化] 流程結束，啟動 Apache ---"

# 執行 Dockerfile 原本的啟動指令
exec "$@"
