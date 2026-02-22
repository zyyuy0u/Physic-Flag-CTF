# 受害網站容器 — PHP 8.2 + Apache
FROM php:8.2-apache

# 安裝 MySQL 擴充套件
RUN docker-php-ext-install mysqli pdo pdo_mysql

# 安裝工具套件
#   net-tools：提供 netstat，供防禦監控系統使用
#   iputils-ping：提供 ping，供網路診斷頁面使用
#   netcat-traditional：提供 nc（含 -e 參數），可用於建立 Reverse Shell
#   python3：提供 python3，可用於建立 Reverse Shell
#   perl：提供 perl，可用於建立 Reverse Shell
#   socat：提供 socat，可用於建立 Reverse Shell
#   curl：提供 curl，可用於下載惡意腳本
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        net-tools \
        iputils-ping \
        netcat-traditional \
        python3 \
        perl \
        socat \
        curl && \
    rm -rf /var/lib/apt/lists/*

# 啟用 URL 重寫模組
RUN a2enmod rewrite

# 允許 .htaccess 檔案覆蓋配置
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

EXPOSE 80
