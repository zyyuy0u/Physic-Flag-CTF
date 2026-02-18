<?php
session_start();

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: index.php');
    exit;
}

$user = htmlspecialchars($_SESSION['user'] ?? 'admin');
?>
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>商品管理 - SmartHome IoT Hub</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0F172A;
            --bg-card: #1E293B;
            --bg-card-hover: #243247;
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
            --warning: #F59E0B;
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

        /* Stat Cards */
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
            cursor: default;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
            border-color: var(--accent);
        }
        .stat-card .stat-number {
            font-family: 'Fira Code', monospace;
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
            line-height: 1.2;
        }
        .stat-card .stat-label {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 4px;
            font-weight: 500;
        }
        .stat-card .stat-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .stat-card .stat-icon svg {
            width: 22px;
            height: 22px;
        }
        .stat-icon-green { background: var(--accent-glow); color: var(--accent); }
        .stat-icon-cyan { background: var(--cyan-glow); color: var(--cyan); }
        .stat-icon-amber { background: rgba(245, 158, 11, 0.15); color: var(--warning); }

        /* Product Cards */
        .product-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
            height: 100%;
            display: flex;
            flex-direction: column;
        }
        .product-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
            border-color: rgba(34, 197, 94, 0.3);
        }
        .product-icon-wrap {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--accent-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
        }
        .product-icon-wrap svg {
            width: 24px;
            height: 24px;
            color: var(--accent);
        }
        .product-card h5 {
            color: var(--text-primary);
            font-weight: 600;
            font-size: 1.05rem;
            margin-bottom: 8px;
        }
        .product-card .desc {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-bottom: 20px;
            flex-grow: 1;
            line-height: 1.6;
        }
        .badge-published {
            background: rgba(34, 197, 94, 0.12);
            color: var(--accent);
            border: 1px solid rgba(34, 197, 94, 0.25);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.02em;
        }
        .badge-draft {
            background: rgba(245, 158, 11, 0.12);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.25);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.02em;
        }
        .btn-edit {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 6px 16px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-edit:hover {
            background: var(--accent-glow);
            border-color: var(--accent);
            color: var(--accent);
        }

        /* Section Title */
        .section-title {
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 20px;
        }

        /* Modal */
        .modal-content {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
        }
        .modal-header {
            border-bottom: 1px solid var(--border);
            padding: 20px 24px;
        }
        .modal-body { padding: 24px; }
        .modal-footer {
            border-top: 1px solid var(--border);
            padding: 16px 24px;
        }
        .modal .form-control,
        .modal .form-select {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            font-family: 'Fira Sans', sans-serif;
            padding: 10px 14px;
            border-radius: 8px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .modal .form-control:focus,
        .modal .form-select:focus {
            background: var(--bg-primary);
            border-color: var(--accent);
            color: var(--text-primary);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .modal .form-label {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.85rem;
            margin-bottom: 6px;
        }
        .modal .btn-close {
            filter: invert(1) grayscale(100%) brightness(200%);
        }
        .btn-save {
            background: var(--accent);
            border: none;
            color: #fff;
            padding: 8px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.875rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-save:hover {
            background: var(--accent-hover);
            color: #fff;
        }
        .btn-cancel {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 8px 24px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-cancel:hover {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
        }
        .form-check-input:checked {
            background-color: var(--accent);
            border-color: var(--accent);
        }
        .form-check-input:focus {
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        /* Toast */
        .toast-container {
            position: fixed;
            top: 80px;
            right: 20px;
            z-index: 9999;
        }
        .toast-success {
            background: var(--bg-card);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 10px;
            color: var(--text-primary);
            padding: 14px 24px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
            display: none;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
        }
        .toast-success.show {
            display: flex;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from { transform: translateX(60px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
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
            <a class="nav-link" href="#stats">儀表板</a>
            <a class="nav-link active" href="#products">商品管理</a>
            <a class="nav-link" href="network.php">網路診斷</a>
        </div>
        <div class="user-section">
            <span>歡迎，<span class="username"><?php echo $user; ?></span></span>
            <a href="logout.php" class="btn-logout">登出</a>
        </div>
    </div>
</nav>

<div class="container mt-4 pb-5">

    <!-- 統計摘要 -->
    <div class="row g-3 mb-4" id="stats">
        <div class="col-md-3 col-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <div class="stat-number">6</div>
                        <div class="stat-label">商品總數</div>
                    </div>
                    <div class="stat-icon stat-icon-green">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <div class="stat-number">6</div>
                        <div class="stat-label">已上架</div>
                    </div>
                    <div class="stat-icon stat-icon-green">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <div class="stat-number">2.4K</div>
                        <div class="stat-label">本月瀏覽</div>
                    </div>
                    <div class="stat-icon stat-icon-cyan">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-3 col-6">
            <div class="stat-card">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <div class="stat-number">47</div>
                        <div class="stat-label">已連線裝置</div>
                    </div>
                    <div class="stat-icon stat-icon-amber">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" x2="12.01" y1="20" y2="20"/></svg>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 商品列表 -->
    <div class="section-title" id="products">商品管理</div>
    <div class="row g-3">
        <div class="col-md-4 col-sm-6">
            <div class="product-card" id="product-0" data-icon="thermometer">
                <div class="product-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4v10.54a4 4 0 1 1-4 0V4a2 2 0 0 1 4 0Z"/></svg>
                </div>
                <h5>溫度控制</h5>
                <p class="desc">即時監控所有區域的 24 個溫度感測器。整合自動化 HVAC 系統，搭配機器學習預測功能。</p>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge-published">已上架</span>
                    <button class="btn-edit" onclick="openEditModal(0)">編輯</button>
                </div>
            </div>
        </div>
        <div class="col-md-4 col-sm-6">
            <div class="product-card" id="product-1" data-icon="shield">
                <div class="product-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                </div>
                <h5>安全防護系統</h5>
                <p class="desc">128 位元加密門鎖、動態感測器與 4K 攝影機串流。入侵偵測即時推播手機警示。</p>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge-published">已上架</span>
                    <button class="btn-edit" onclick="openEditModal(1)">編輯</button>
                </div>
            </div>
        </div>
        <div class="col-md-4 col-sm-6">
            <div class="product-card" id="product-2" data-icon="zap">
                <div class="product-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                </div>
                <h5>能源管理</h5>
                <p class="desc">智慧電網整合與太陽能板最佳化。透過 AI 排程，最高可降低 40% 能源成本。</p>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge-published">已上架</span>
                    <button class="btn-edit" onclick="openEditModal(2)">編輯</button>
                </div>
            </div>
        </div>
        <div class="col-md-4 col-sm-6">
            <div class="product-card" id="product-3" data-icon="droplets">
                <div class="product-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 16.3c2.2 0 4-1.83 4-4.05 0-1.16-.57-2.26-1.71-3.19S7.29 6.75 7 5.3c-.29 1.45-1.14 2.84-2.29 3.76S3 11.1 3 12.25c0 2.22 1.8 4.05 4 4.05z"/><path d="M12.56 14.69c1.47 0 2.66-1.22 2.66-2.7 0-.77-.38-1.51-1.14-2.13S12.76 8.5 12.56 7.7c-.19.97-.76 1.9-1.53 2.51s-.89 1.36-.89 2.13 1.19 2.7 2.66 2.7z" transform="translate(3.5,-1.5)"/></svg>
                </div>
                <h5>水資源監控</h5>
                <p class="desc">漏水偵測搭配自動關閉閥門。用水量分析與節水建議。</p>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge-published">已上架</span>
                    <button class="btn-edit" onclick="openEditModal(3)">編輯</button>
                </div>
            </div>
        </div>
        <div class="col-md-4 col-sm-6">
            <div class="product-card" id="product-4" data-icon="wifi">
                <div class="product-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" x2="12.01" y1="20" y2="20"/></svg>
                </div>
                <h5>網路健康度</h5>
                <p class="desc">具備自我修復能力的 Mesh 網路拓撲。所有連網裝置保證 99.97% 正常運行時間。</p>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge-published">已上架</span>
                    <button class="btn-edit" onclick="openEditModal(4)">編輯</button>
                </div>
            </div>
        </div>
        <div class="col-md-4 col-sm-6">
            <div class="product-card" id="product-5" data-icon="cpu">
                <div class="product-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>
                </div>
                <h5>自動化引擎</h5>
                <p class="desc">透過視覺化流程編輯器建立複雜排程。支援 IFTTT、Zigbee、Z-Wave 及 Matter 協定。</p>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge-published">已上架</span>
                    <button class="btn-edit" onclick="openEditModal(5)">編輯</button>
                </div>
            </div>
        </div>
    </div>

</div>

<!-- 編輯 Modal -->
<div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="editModalLabel" style="font-weight:700;">編輯商品</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="關閉"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label" for="editTitle">標題</label>
                    <input type="text" class="form-control" id="editTitle">
                </div>
                <div class="mb-3">
                    <label class="form-label" for="editDesc">描述</label>
                    <textarea class="form-control" id="editDesc" rows="3"></textarea>
                </div>
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="editStatus" checked>
                    <label class="form-check-label" for="editStatus">已上架</label>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" data-bs-dismiss="modal">取消</button>
                <button type="button" class="btn-save" onclick="saveProduct()">儲存變更</button>
            </div>
        </div>
    </div>
</div>

<!-- Toast -->
<div class="toast-container">
    <div class="toast-success" id="toastSuccess">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        <span>儲存成功</span>
    </div>
</div>

<script src="js/bootstrap.bundle.min.js"></script>
<script>
    let editModal;
    let currentEditId = null;

    document.addEventListener('DOMContentLoaded', function () {
        editModal = new bootstrap.Modal(document.getElementById('editModal'));
    });

    function openEditModal(id) {
        currentEditId = id;
        const card = document.getElementById('product-' + id);
        document.getElementById('editTitle').value = card.querySelector('h5').textContent.trim();
        document.getElementById('editDesc').value = card.querySelector('.desc').textContent.trim();
        const badge = card.querySelector('.badge-published, .badge-draft');
        document.getElementById('editStatus').checked = badge.classList.contains('badge-published');
        editModal.show();
    }

    function saveProduct() {
        if (currentEditId === null) return;
        const card = document.getElementById('product-' + currentEditId);
        card.querySelector('h5').textContent = document.getElementById('editTitle').value;
        card.querySelector('.desc').textContent = document.getElementById('editDesc').value;

        const badge = card.querySelector('.badge-published, .badge-draft');
        const isPublished = document.getElementById('editStatus').checked;
        badge.className = isPublished ? 'badge-published' : 'badge-draft';
        badge.textContent = isPublished ? '已上架' : '草稿';

        editModal.hide();
        currentEditId = null;

        const toast = document.getElementById('toastSuccess');
        toast.classList.add('show');
        setTimeout(function () { toast.classList.remove('show'); }, 2500);
    }
</script>

</body>
</html>
