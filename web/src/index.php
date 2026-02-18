<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmartHome IoT Hub - 掌控您的智慧家庭</title>
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
            --accent-glow: rgba(34, 197, 94, 0.15);
            --cyan: #06B6D4;
            --cyan-glow: rgba(6, 182, 212, 0.15);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Fira Sans', -apple-system, BlinkMacSystemFont, sans-serif;
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

        /* Hero */
        .hero {
            padding: 100px 0 60px;
            text-align: center;
        }
        .hero h1 {
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--accent), var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1.2;
        }
        .hero p {
            font-size: 1.15rem;
            color: var(--text-secondary);
            max-width: 600px;
            margin: 20px auto;
            line-height: 1.7;
        }
        .badge-version {
            background: var(--accent-glow);
            color: var(--accent);
            border: 1px solid rgba(34, 197, 94, 0.25);
            padding: 5px 14px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .badge-status {
            background: var(--cyan-glow);
            color: var(--cyan);
            border: 1px solid rgba(6, 182, 212, 0.25);
            padding: 5px 14px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        /* Feature Cards */
        .feature-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 28px;
            transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
            cursor: default;
            height: 100%;
        }
        .feature-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
            border-color: rgba(34, 197, 94, 0.3);
        }
        .feature-icon-wrap {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--accent-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
        }
        .feature-icon-wrap svg {
            width: 24px;
            height: 24px;
            color: var(--accent);
        }
        .feature-card h4 {
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 10px;
        }
        .feature-card p {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-bottom: 0;
            line-height: 1.6;
        }

        /* Stats */
        .stats-section {
            background: var(--bg-card);
            border-top: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
            padding: 48px 0;
            margin: 48px 0;
        }
        .stat-number {
            font-family: 'Fira Code', monospace;
            font-size: 2.2rem;
            font-weight: 700;
            color: var(--accent);
            line-height: 1.2;
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 4px;
        }

        /* About */
        .about-section h3 {
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 16px;
        }
        .about-section p {
            color: var(--text-secondary);
            font-size: 0.95rem;
            line-height: 1.7;
        }
        .about-section .tech-info {
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 16px;
        }

        /* Footer */
        footer {
            background: var(--bg-card);
            border-top: 1px solid var(--border);
            padding: 28px 0;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
        }
        footer small {
            font-family: 'Fira Code', monospace;
            font-size: 0.72rem;
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
        <span class="navbar-brand">SmartHome IoT Hub</span>
        <div class="navbar-nav ms-auto">
            <a class="nav-link" href="#features">功能特色</a>
            <a class="nav-link" href="#stats">系統狀態</a>
            <a class="nav-link" href="#about">關於我們</a>
        </div>
    </div>
</nav>

<section class="hero">
    <div class="container">
        <h1>掌控您的智慧家庭</h1>
        <p>新一代 IoT 管理平台。即時監控感測器、自動化排程、保護您的連網裝置 — 全部在同一個儀表板完成。</p>
        <div class="mt-4 d-flex justify-content-center gap-2">
            <span class="badge-version">v2.4.1</span>
            <span class="badge-status">所有系統運作正常</span>
        </div>
    </div>
</section>

<section id="features" class="container">
    <div class="row g-3">
        <div class="col-md-4">
            <div class="feature-card">
                <div class="feature-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4v10.54a4 4 0 1 1-4 0V4a2 2 0 0 1 4 0Z"/></svg>
                </div>
                <h4>溫度控制</h4>
                <p>即時監控所有區域的 24 個溫度感測器。整合自動化 HVAC 系統，搭配機器學習預測功能。</p>
            </div>
        </div>
        <div class="col-md-4">
            <div class="feature-card">
                <div class="feature-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                </div>
                <h4>安全防護系統</h4>
                <p>128 位元加密門鎖、動態感測器與 4K 攝影機串流。入侵偵測即時推播手機警示。</p>
            </div>
        </div>
        <div class="col-md-4">
            <div class="feature-card">
                <div class="feature-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                </div>
                <h4>能源管理</h4>
                <p>智慧電網整合與太陽能板最佳化。透過 AI 排程，最高可降低 40% 能源成本。</p>
            </div>
        </div>
    </div>
    <div class="row g-3 mt-0">
        <div class="col-md-4">
            <div class="feature-card">
                <div class="feature-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 16.3c2.2 0 4-1.83 4-4.05 0-1.16-.57-2.26-1.71-3.19S7.29 6.75 7 5.3c-.29 1.45-1.14 2.84-2.29 3.76S3 11.1 3 12.25c0 2.22 1.8 4.05 4 4.05z"/><path d="M12.56 14.69c1.47 0 2.66-1.22 2.66-2.7 0-.77-.38-1.51-1.14-2.13S12.76 8.5 12.56 7.7c-.19.97-.76 1.9-1.53 2.51s-.89 1.36-.89 2.13 1.19 2.7 2.66 2.7z" transform="translate(3.5,-1.5)"/></svg>
                </div>
                <h4>水資源監控</h4>
                <p>漏水偵測搭配自動關閉閥門。用水量分析與節水建議。</p>
            </div>
        </div>
        <div class="col-md-4">
            <div class="feature-card">
                <div class="feature-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" x2="12.01" y1="20" y2="20"/></svg>
                </div>
                <h4>網路健康度</h4>
                <p>具備自我修復能力的 Mesh 網路拓撲。所有連網裝置保證 99.97% 正常運行時間。</p>
            </div>
        </div>
        <div class="col-md-4">
            <div class="feature-card">
                <div class="feature-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>
                </div>
                <h4>自動化引擎</h4>
                <p>透過視覺化流程編輯器建立複雜排程。支援 IFTTT、Zigbee、Z-Wave 及 Matter 協定。</p>
            </div>
        </div>
    </div>
</section>

<section id="stats" class="stats-section">
    <div class="container">
        <div class="row text-center">
            <div class="col-md-3 col-6">
                <div class="stat-number">47</div>
                <div class="stat-label">已連線裝置</div>
            </div>
            <div class="col-md-3 col-6">
                <div class="stat-number">99.9%</div>
                <div class="stat-label">正常運行率</div>
            </div>
            <div class="col-md-3 col-6 mt-3 mt-md-0">
                <div class="stat-number">2.4K</div>
                <div class="stat-label">今日事件數</div>
            </div>
            <div class="col-md-3 col-6 mt-3 mt-md-0">
                <div class="stat-number">12</div>
                <div class="stat-label">啟用區域</div>
            </div>
        </div>
    </div>
</section>

<section id="about" class="container py-5 about-section">
    <div class="text-center">
        <h3>關於 SmartHome IoT Hub</h3>
        <p style="max-width:700px;margin:auto;">
            專為現代智慧家庭打造。我們的平台整合超過 500 種 IoT 裝置，
            為住宅與商業環境提供企業級安全防護。
        </p>
        <div class="tech-info">
            韌體版本：2.4.1-stable | 核心：5.15.84-v8+ | ARM64
        </div>
    </div>
</section>

<footer>
    <div class="container">
        &copy; 2024 SmartHome IoT Hub &mdash; 僅供內部使用<br>
        <small>Raspberry Pi 閘道節點 &bull; 型號：RPi4-8GB &bull; 序號：SH-00A4F2E8</small>
    </div>
</footer>

</body>
</html>
