<?php
session_start();

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: index.php');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$output = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['target_ip'])) {
    if (hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        $target = $_POST['target_ip'];
        // 漏洞：未過濾輸入 — 故意留下指令注入漏洞
        $output = shell_exec("ping -c 3 " . $target . " 2>&1");
    }
}

$user = htmlspecialchars($_SESSION['user'] ?? 'admin');
?>
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>網路診斷 - SmartHome IoT Hub</title>
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
            --cyan: #06B6D4;
            --cyan-glow: rgba(6, 182, 212, 0.15);
            --danger: #EF4444;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Fira Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            line-height: 1.6;
        }

        /* Navbar */
        .navbar {
            background: var(--bg-card) !important;
            border-bottom: 1px solid var(--border);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            padding: 0 0;
        }
        .navbar-brand {
            font-family: 'Fira Code', monospace;
            font-weight: 700;
            color: var(--accent) !important;
            font-size: 1.25rem;
            letter-spacing: -0.02em;
            cursor: pointer;
        }
        .navbar-nav .nav-link {
            color: var(--text-secondary) !important;
            font-weight: 500;
            font-size: 0.9rem;
            padding: 8px 16px !important;
            border-radius: 8px;
            transition: color 0.2s, background 0.2s;
            cursor: pointer;
        }
        .navbar-nav .nav-link:hover {
            color: var(--text-primary) !important;
            background: rgba(255, 255, 255, 0.05);
        }
        .navbar-nav .nav-link.active {
            color: var(--accent) !important;
            background: var(--accent-glow);
        }
        .user-section {
            color: var(--text-secondary);
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .user-section .username {
            color: var(--text-primary);
            font-weight: 600;
        }
        .btn-logout {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 6px 16px;
            border-radius: 8px;
            font-size: 0.8rem;
            text-decoration: none;
            transition: all 0.2s;
            cursor: pointer;
        }
        .btn-logout:hover {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--danger);
            color: var(--danger);
        }

        /* Diagnostic Card */
        .diag-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px;
            max-width: 640px;
            margin: 48px auto 0;
        }
        .diag-card .card-header-row {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 8px;
        }
        .diag-card .card-icon {
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: var(--cyan-glow);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .diag-card .card-icon svg {
            width: 22px;
            height: 22px;
            color: var(--cyan);
        }
        .diag-card h4 {
            color: var(--text-primary);
            font-weight: 700;
            font-size: 1.15rem;
            margin: 0;
        }
        .diag-card .card-desc {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 24px;
            margin-left: 58px;
        }
        .form-control {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            font-family: 'Fira Sans', sans-serif;
            padding: 12px 16px;
            border-radius: 8px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-control:focus {
            background: var(--bg-primary);
            border-color: var(--cyan);
            color: var(--text-primary);
            box-shadow: 0 0 0 3px var(--cyan-glow);
        }
        .form-control::placeholder {
            color: var(--text-muted);
        }
        .btn-test {
            background: var(--accent);
            border: none;
            color: #fff;
            padding: 12px 28px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.95rem;
            transition: background 0.2s;
            cursor: pointer;
        }
        .btn-test:hover {
            background: var(--accent-hover);
            color: #fff;
        }

        /* Result Card */
        .result-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 28px 32px;
            max-width: 640px;
            margin: 20px auto 48px;
        }
        .result-card .result-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
        }
        .result-card .result-header svg {
            width: 18px;
            height: 18px;
            color: var(--accent);
        }
        .result-card h5 {
            color: var(--text-primary);
            font-weight: 700;
            font-size: 1rem;
            margin: 0;
        }
        .result-content {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
            max-height: 400px;
            overflow-y: auto;
            line-height: 1.7;
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

<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container py-2">
        <a class="navbar-brand" href="dashboard.php">SmartHome IoT Hub</a>
        <div class="navbar-nav me-auto ms-4">
            <a class="nav-link" href="dashboard.php">儀表板</a>
            <a class="nav-link" href="dashboard.php">商品管理</a>
            <a class="nav-link active" href="network.php">網路診斷</a>
        </div>
        <div class="user-section">
            <span>歡迎，<span class="username"><?php echo $user; ?></span></span>
            <a href="logout.php" class="btn-logout">登出</a>
        </div>
    </div>
</nav>

<div class="container">

    <div class="diag-card">
        <div class="card-header-row">
            <div class="card-icon">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" x2="12.01" y1="20" y2="20"/></svg>
            </div>
            <h4>裝置連線測試</h4>
        </div>
        <p class="card-desc">輸入裝置 IP 位址以檢測連線狀態</p>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="d-flex gap-3">
                <input type="text" name="target_ip" class="form-control flex-grow-1" placeholder="例如：192.168.1.1" autocomplete="off">
                <button type="submit" class="btn-test">開始檢測</button>
            </div>
        </form>
    </div>

    <?php if ($output): ?>
    <div class="result-card">
        <div class="result-header">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            <h5>檢測結果</h5>
        </div>
        <div class="result-content"><?php echo htmlspecialchars($output); ?></div>
    </div>
    <?php endif; ?>

</div>

</body>
</html>
