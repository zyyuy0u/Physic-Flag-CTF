# IoT Honeypot — 智慧家庭蜜罐系統 (物理標靶版)

基於 Raspberry Pi 的 IoT 蜜罐系統，模擬一個存在漏洞的智慧家庭管理平台（SmartHome IoT Hub）。本系統不僅透過 LED 警示，更整合了 **SG90 伺服馬達** 作為實體標靶，當偵測到關鍵攻擊行為時，會執行物理擊倒動作。

> **警告：本專案包含故意設計的安全漏洞（SQL Injection、Command Injection），僅供資安教育與研究用途。請勿部署於公開網路環境。**

## 系統架構

```
                         攻擊者
                           │
                  Wi-Fi / Ethernet
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
│               ┌────────────┼────────────┐           │
│               ▼            ▼            ▼           │
│            系統正常       系統警報      物理標靶      │
│            (綠燈)        (蜂鳴器)      (SG90 馬達)   │
│            GPIO 22       GPIO 24       GPIO 18      │
│          (啟動亮起)     (攻擊嗶嗶)     (攻擊擊倒)    │
└─────────────────────────────────────────────────────┘
```

## 硬體展示邏輯

本系統採用「物理化」的偵測回饋，具備以下三種硬體狀態：

1. **系統就緒 (Normal)**：綠燈亮、蜂鳴器靜默，馬達位於 0 度（標靶立起）。
2. **攻擊觸發 (Triggered)**：偵測到 `/admin` 探測時綠燈亮起；偵測到 SQLi/auth 繞過時蜂鳴器嗶嗶嗶 3 聲（每聲 100 ms，間隔 100 ms）；偵測到 Reverse Shell 時馬達轉至 90 度（標靶擊倒）。
3. **安全復位 (Safe Shutdown)**：當執行 `docker compose down` 時，系統會自動將標靶立起，等待 1 秒物理運動後關閉 PWM，防止馬達卡死發熱。

## 三大偵測機制

### 1. 路徑探測偵測 (Apache Logs)
監控 Web 容器日誌，偵測對 `/admin` 敏感路徑的非法存取。

### 2. SQL Injection 繞過偵測 (Apache Logs)
監控 `dashboard.php` 是否回傳 HTTP 200。正常情況下未登入存取會被重導（302），若回傳 200 則判定為驗證繞過。

### 3. Reverse Shell 即時偵測 (eBPF)
在核心監控 `web-app` 容器的 TCP `SYN_SENT` 事件，排除 loopback、link-local 與實際 Docker 子網後，偵測非白名單的外連嘗試。此機制不綁定有線或無線網卡。

## 環境需求

- Raspberry Pi (建議 Pi 4 或 Pi 5)
- **pigpiod 守護行程** (必須執行 `sudo pigpiod`)
- 硬體元件：
    - 綠色 LED x1, 紅色 LED x1 (接 GPIO 22, 24)
    - SG90 伺服馬達 x1 (接 GPIO 18, 建議外部供電)
    - 220Ω 電阻與麵包板

## 快速部署

```bash
# 1. Clone 專案（在樹莓派上）
git clone https://github.com/zyyuy0u/Physic-Flag-CTF.git
cd Physic-Flag-CTF

# 2. 啟動所有服務（馬達連線在背景重試，不會阻擋 LED/蜂鳴器監控）
docker compose up -d

# 3. 確認服務狀態
docker compose ps
```

馬達需要宿主機的 pigpiod 允許防禦容器連入。**`-n` 是用戶端 IP 允許清單，
不是監聽位址；舊版說明中的 `-n 0.0.0.0` 有誤。**
若尚未啟動 pigpiod，可在 Docker 已啟動後執行：

```bash
DEFENSE_ID=$(docker compose ps -q defense-system)
DEFENSE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DEFENSE_ID")
sudo pigpiod -n localhost -n "$DEFENSE_IP"
```

若既有 pigpiod 已由 systemd 管理，應更新該服務的設定並重新啟動，勿另開第二個 daemon。
容器 IP 改變後須同步更新 pigpiod 的允許清單與學生模式防火牆；完整步驟見
[GPIO 與 pigpiod 排錯](docs/gpio-troubleshooting.md)。

## 改用同一個 Wi-Fi 存取

網站明確發布在 Pi 的所有 IPv4 介面 `0.0.0.0:8080`，可供同一區網的電腦／手機存取。
先將實體開關切到教師模式，透過原有網路線或本機螢幕，在 **Pi 的專案目錄**執行：

```bash
sudo python3 host/network/wifi.py connect --ssid '你的 Wi-Fi 名稱'
docker compose up -d
sudo python3 host/network/wifi.py status
```

Wi-Fi 密碼由 NetworkManager 互動詢問；若已連上 Wi-Fi 可跳過第一行。
`status` 會列出 `http://<Pi 的 Wi-Fi IP>:8080`，並檢查 IPv4、實際發布埠、Docker 網段衝突與本機 HTTP。
電腦／手機連上相同 Wi-Fi 後開啟該網址，確認成功再拔掉直連網路線重試。

Wi-Fi 須允許裝置彼此互通，AP／Client Isolation 或訪客隔離可能阻擋連線。
學生模式仍可瀏覽網站，但阻擋新的 SSH；本次補上 DHCP 回覆規則，已安裝模式切換服務者須更新其 `/opt` 副本並重啟服務。
完整的升級、驗證與排錯步驟見 [Wi-Fi 使用說明](host/network/README.md)。

## 技術棧

| 元件 | 技術 |
|------|------|
| 蜜罐網站 | PHP 8.2、Apache、Bootstrap 5 |
| 資料庫 | MariaDB 10.6 |
| 防禦監控 | Python 3.9、RPi.GPIO、**pigpio** |
| 容器化 | Docker、Docker Compose |
| 物理作動 | SG90 Servo (PWM 控制) |

## GPIO 接線圖 (BCM 模式)

```
Raspberry Pi GPIO
─────────────────────────────────────────────────────────────
GPIO 22 (Pin 15) ──── 220Ω ──── 綠 LED (正常)  ──── GND
GPIO 24 (Pin 18) ───────────── 蜂鳴器模組 Signal (3.3V active buzzer)
3.3V    (Pin 1)  ───────────── 蜂鳴器模組 VCC
GND     (Pin 9)  ───────────── 蜂鳴器模組 GND
GPIO 18 (Pin 12) ────────────── SG90 訊號線 (橘)
5V      (Pin 2/4) ───────────── SG90 電源線 (紅)
GND     (Pin 6)   ───────────── SG90 接地線 (棕)
```

## 注意事項

- **PWM 穩定性**：本專案使用 `pigpio` 提供硬體級 PWM，徹底解決 RPi.GPIO 控制馬達時常見的抖動問題。
- **優雅降落**：程式具備 `SIGTERM` 捕捉機制，執行 `docker compose down` 時標靶會自動復位，確保硬體壽命。
- **區網存取**：支援有線直連或同一個 Wi-Fi；已部署的靶場核心功能可離線運行，實驗設備間須能互通。
- 預設管理員帳號：`admin` / `sm@rtH0me2024!`
