# 受害網站容器 — PHP 8.2 + Apache
FROM php:8.2-apache

# 安裝 MySQL 擴充套件
RUN docker-php-ext-install mysqli pdo pdo_mysql

# 安裝 net-tools（提供 netstat，供防禦監控系統使用）
RUN apt-get update && \
    apt-get install -y --no-install-recommends net-tools && \
    rm -rf /var/lib/apt/lists/*

# 啟用 URL 重寫模組
RUN a2enmod rewrite

# 允許 .htaccess 檔案覆蓋配置
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

EXPOSE 80
