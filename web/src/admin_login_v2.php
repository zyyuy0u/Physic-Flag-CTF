<?php
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        $error = '請求無效，請重新操作。';
    } else {
        $host = getenv('DB_HOST') ?: 'db';
        $user = getenv('DB_USER') ?: 'webuser';
        $pass = getenv('DB_PASS') ?: 'webpass123';
        $db   = getenv('DB_NAME') ?: 'honeypot';

        $conn = new mysqli($host, $user, $pass, $db);

        if ($conn->connect_error) {
            $error = '資料庫連線失敗。';
        } else {
            $u = $_POST['username'] ?? '';
            $p = $_POST['password'] ?? '';

            // 漏洞：未過濾輸入 — 故意留下 SQL 注入漏洞
            $sql = "SELECT * FROM users WHERE username = '$u' AND password = '$p'";
            $result = $conn->query($sql);

            if ($result && $result->num_rows > 0) {
                $row = $result->fetch_assoc();

                session_regenerate_id(true);
                $_SESSION['logged_in'] = true;
                $_SESSION['user'] = $row['username'] ?? 'admin';
                $success = true;
            } else {
                $error = '帳號或密碼錯誤。';
            }
            $conn->close();
        }
    }
}

if ($success) {
    header('Location: dashboard.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理員登入 - SmartHome IoT Hub</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0F172A;
            --bg-card: #1E293B;
            --border: #334155;
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --text-muted: #64748B;
            --accent: #22C55E;
            --accent-hover: #16A34A;
            --accent-glow: rgba(34, 197, 94, 0.15);
            --danger: #EF4444;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Fira Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .login-box {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
        }

        .login-box .brand {
            font-family: 'Fira Code', monospace;
            font-weight: 700;
            color: var(--accent);
            font-size: 1.1rem;
            text-align: center;
            margin-bottom: 6px;
        }

        .login-box h2 {
            color: var(--text-primary);
            text-align: center;
            margin-bottom: 28px;
            font-weight: 700;
            font-size: 1.4rem;
        }

        .form-label {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.85rem;
        }

        .form-control {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 12px 14px;
            border-radius: 8px;
            font-family: 'Fira Sans', sans-serif;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-control:focus {
            background: var(--bg-primary);
            border-color: var(--accent);
            color: var(--text-primary);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .form-control::placeholder {
            color: var(--text-muted);
        }

        .btn-login {
            background: var(--accent);
            border: none;
            padding: 12px;
            font-weight: 600;
            width: 100%;
            border-radius: 8px;
            color: #fff;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-login:hover {
            background: var(--accent-hover);
            color: #fff;
        }

        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: var(--danger);
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 0.9rem;
        }

        .version-tag {
            text-align: center;
            margin-top: 24px;
            font-size: 0.72rem;
            color: var(--text-muted);
            font-family: 'Fira Code', monospace;
        }

        /* Reduced motion */
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
</head>
<body>

<div class="login-box">
    <div class="brand">SmartHome IoT Hub</div>
    <h2>管理員面板</h2>

    <?php if ($error): ?>
        <div class="alert alert-danger mb-3"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <div class="mb-3">
            <label class="form-label" for="username">使用者名稱</label>
            <input type="text" name="username" id="username" class="form-control" placeholder="請輸入使用者名稱" required>
        </div>
        <div class="mb-3">
            <label class="form-label" for="password">密碼</label>
            <input type="password" name="password" id="password" class="form-control" placeholder="請輸入密碼" required>
        </div>
        <button type="submit" class="btn btn-login">登入</button>
    </form>

    <div class="version-tag">
        管理員面板 v2.4.1 &bull; 僅限授權人員使用
    </div>
</div>

</body>
</html>
