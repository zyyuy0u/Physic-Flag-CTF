<?php
/**
 * 資料庫初始化工具
 * 執行一次即可建立使用者資料表並新增管理員帳號。
 * 存取方式：docker exec web-app php /var/www/html/setup_db.php
 */

$host = getenv('DB_HOST') ?: 'db';
$user = getenv('DB_USER') ?: 'webuser';
$pass = getenv('DB_PASS') ?: 'webpass123';
$db   = getenv('DB_NAME') ?: 'honeypot';

echo "<pre>\n";
echo "=== SmartHome IoT Hub - 資料庫初始化 ===\n\n";

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("連線失敗：" . $conn->connect_error . "\n");
}
echo "[成功] 已連線至資料庫 '$db'\n";

// 建立使用者資料表
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

if ($conn->query($sql)) {
    echo "[成功] 資料表 'users' 已建立（或已存在）\n";
} else {
    echo "[錯誤] " . $conn->error . "\n";
}

// 檢查管理員帳號是否存在
$check = $conn->query("SELECT id FROM users WHERE username = 'admin'");
if ($check && $check->num_rows === 0) {
    $conn->query("INSERT INTO users (username, password, role) VALUES ('admin', 'sm@rtH0me2024!', 'administrator')");
    echo "[成功] 管理員帳號已建立（admin / sm@rtH0me2024!）\n";
} else {
    echo "[成功] 管理員帳號已存在\n";
}

// 新增誘餌帳號
$decoys = [
    ['operator', 'oper1234', 'operator'],
    ['technician', 'tech5678', 'maintenance'],
    ['viewer', 'view_only', 'readonly'],
];
foreach ($decoys as $d) {
    $check = $conn->query("SELECT id FROM users WHERE username = '{$d[0]}'");
    if ($check && $check->num_rows === 0) {
        $conn->query("INSERT INTO users (username, password, role) VALUES ('{$d[0]}', '{$d[1]}', '{$d[2]}')");
        echo "[成功] 誘餌帳號 '{$d[0]}' 已建立\n";
    }
}

echo "\n=== 初始化完成 ===\n";
echo "</pre>\n";

$conn->close();
?>
