# IoT Honeypot — 智慧家庭蜜罐系統 (物理標靶版)

基於 Raspberry Pi 的 IoT 蜜罐系統，模擬一個存在漏洞的智慧家庭管理平台（SmartHome IoT Hub）。本系統不僅透過 LED 警示，更整合了 **SG90 伺服馬達** 作為實體標靶，當偵測到關鍵攻擊行為時，會執行物理擊倒動作。

> **警告：本專案包含故意設計的安全漏洞（SQL Injection、Command Injection），僅供資安教育與研究用途。請勿部署於公開網路環境。**

## 系統架構

```
                         攻擊者
                           │
                      Port 9090
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
│            (綠燈)         (紅燈)       (SG90 馬達)   │
│            GPIO 22       GPIO 24       GPIO 18      │
│          (啟動亮起)     (攻擊觸發)     (攻擊擊倒)    │
└─────────────────────────────────────────────────────┘
```

## 硬體展示邏輯

本系統採用「物理化」的偵測回饋，具備以下三種硬體狀態：

1. **系統就緒 (Normal)**：綠燈亮、紅燈滅，馬達位於 0 度（標靶立起）。
2. **攻擊觸發 (Triggered)**：一旦偵測到 `/admin` 探測、SQLi 繞過或 Reverse Shell，綠燈熄滅、紅燈亮起，馬達轉至 90 度（標靶擊倒）。
3. **安全復位 (Safe Shutdown)**：當執行 `docker compose down` 時，系統會自動將標靶立起，等待 1 秒物理運動後關閉 PWM，防止馬達卡死發熱。

## 三大偵測機制

### 1. 路徑探測偵測 (Apache Logs)
監控 Web 容器日誌，偵測對 `/admin` 敏感路徑的非法存取。

### 2. SQL Injection 繞過偵測 (Apache Logs)
監控 `dashboard.php` 是否回傳 HTTP 200。正常情況下未登入存取會被重導（302），若回傳 200 則判定為驗證繞過。

### 3. Reverse Shell 即時偵測 (Netstat Snapshot)
在容器內持續監控連線狀態，過濾掉正常 HTTP (80) 與 Docker 內部網段，偵測任何異常的外連行為。

## 環境需求

- Raspberry Pi (建議 Pi 4 或 Pi 5)
- **pigpiod 守護行程** (必須執行 `sudo pigpiod`)
- 硬體元件：
    - 綠色 LED x1, 紅色 LED x1 (接 GPIO 22, 24)
    - SG90 伺服馬達 x1 (接 GPIO 18, 建議外部供電)
    - 220Ω 電阻與麵包板

## 快速部署

```bash
# 1. 啟動宿主機 pigpio 守護行程
sudo pigpiod

# 2. Clone 專案
git clone https://github.com/<your-username>/iot-honeypot.git
cd iot-honeypot

# 3. 啟動所有服務 (系統會自動初始化資料庫)
docker compose up -d

# 4. 確認服務狀態
docker compose ps
```

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
GPIO 22 (Pin 15) ──── 220Ω ──── 綠燈 (正常) ──── GND
GPIO 24 (Pin 18) ──── 220Ω ──── 紅燈 (警報) ──── GND
GPIO 18 (Pin 12) ────────────── SG90 訊號線 (橘)
5V      (Pin 2/4) ───────────── SG90 電源線 (紅)
GND     (Pin 6)   ───────────── SG90 接地線 (棕)
```

## 注意事項

- **PWM 穩定性**：本專案使用 `pigpio` 提供硬體級 PWM，徹底解決 RPi.GPIO 控制馬達時常見的抖動問題。
- **優雅降落**：程式具備 `SIGTERM` 捕捉機制，執行 `docker compose down` 時標靶會自動復位，確保硬體壽命。
- **點對點環境**：本系統支援完全離線運行，只要攻擊者與 Pi 位處同一區域網即可偵測。
- 預設管理員帳號：`admin` / `sm@rtH0me2024!`
