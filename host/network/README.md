# 使用同一個 Wi-Fi 存取靶場

電腦、手機與 Raspberry Pi 連上允許裝置互通的展示 Wi-Fi 後，使用
`http://<Pi 的 Wi-Fi IPv4>:8080` 開啟網站。Wi-Fi 基地台不需要接上 Internet。
網站、資料庫、eBPF 與硬體控制仍全部在 Pi 上執行。

## 第一次設定

以下命令都在 **Pi 上的專案目錄**執行。需求為 Raspberry Pi OS Bookworm 或更新版本、
Python 3.10+、NetworkManager（`nmcli`）、`iproute2` 與既有 Docker / pigpiod 環境。
先切到教師模式，透過原有網路線 SSH 或本機鍵盤螢幕操作。

```bash
# 連上 Wi-Fi；密碼由 nmcli 詢問，不必寫入專案或命令列
sudo python3 host/network/wifi.py connect --ssid '你的 Wi-Fi 名稱'

# 套用網站的 IPv4 埠設定；既有資料庫資料會保留
docker compose up -d

# 顯示 Wi-Fi 網址、檢查 Docker 子網與本機 HTTP
sudo python3 host/network/wifi.py status
```

若 Pi 已經連上 Wi-Fi，可跳過 `connect`。若有多張無線網卡，兩個子命令都可加
`--interface wlan0`（換成實際名稱）。工具不會把 Pi 設成熱點。
`connect` 適用於一般展示／家用 Wi-Fi；校園 802.1X、隱藏 SSID 或特殊 IP 設定，
請先用 NetworkManager 設定連線，再執行 `status`。

工具會檢查無線網卡是否已連線並取得 IPv4，排除 `169.254.x.x` 的臨時位址。
網址使用 Docker 實際發布的埠，只綁定 localhost 或舊有線 IP 時會回報失敗。
`status` 回傳 0 表示本機檢查通過，1 表示有錯誤；它無法由 Pi 本機證明基地台允許其他設備存取。

在電腦／手機連上相同 Wi-Fi，開啟工具顯示的網址。成功後拔掉電腦與 Pi 的直連網路線再試一次。
最後切回學生模式，確認網站仍可用。建議在路由器為 Pi 的 Wi-Fi MAC 設定 DHCP 位址保留，
使網址固定。不要沿用原本 Ethernet 的 IP 或 Docker 容器的 `172.x.x.x` 位址。

## 已安裝模式切換服務的 Pi

本次學生模式新增實體網卡上的 DHCP 回覆規則：IPv4 UDP 67 → 68、IPv6 UDP 547 → 546。
這讓取得／更新 IP 的 UDP 流量有明確通路。新的 SSH 連線仍被阻擋，pigpiod:8888 仍只允許
防禦容器從 Docker bridge 連入。網站發布流量經 Docker 的 FORWARD 規則，模式切換不修改它。

若之前已安裝並啟用模式切換服務，必須更新 `/opt` 中的副本並重新載入程式。
在**實體開關位於教師模式、Docker 已啟動**時執行：

```bash
sudo bash host/mode-switch/install.sh
sudo systemctl restart mode-switch.service
sudo python3 /opt/honeypot/mode-switch/mode_switch.py --show
```

尚未使用此服務的 Pi 不必為了 Wi-Fi 安裝它。既有服務在 Docker 容器重建、IP 改變後，
需要在 Docker 啟動完成時重新套用學生模式（切換開關，或重啟服務），以更新防禦容器的 pigpiod 規則。
開機後也應確認此規則存在；目前服務不會自動追蹤容器的 IP。
插入新的 USB 網卡後同樣需重套模式，才會加入該網卡的 DHCP 規則。

## 驗證實體回饋

先從另一台 Wi-Fi 設備確認網頁可開啟，再在 Pi 的專案目錄執行：

```bash
BASE_URL=http://<Pi的Wi-Fi-IP>:8080 \
REVERSE_TARGET_IP=<電腦的Wi-Fi-IP> \
bash tests/smoke_test.sh
```

將兩個 `<...>` 換成實際 IPv4。這會測試 `/admin` → LED、登入繞過 → 蜂鳴器，
以及容器向指定電腦發起 TCP 連線 → 馬達。第三項在 `SYN_SENT` 即可偵測，
不需要電腦啟動 listener，也不代表反向 shell 已成功建立。執行時會觸發實體元件。
這個測試仍須在 Pi 上讀取 Docker 日誌；不要只把 `BASE_URL` 換掉就移到電腦執行。
正式反向 shell 示範則需使用電腦的 Wi-Fi IP、啟動 listener 並允許該埠連入。

## 連不上時

| 狀況 | 處理方式 |
|---|---|
| 本機 HTTP 正常，其他設備連不上 | 確認基地台沒有 AP／Client Isolation、訪客隔離或 VLAN 阻擋，再檢查 Pi 的其他防火牆規則 |
| `docker inspect` 失敗 | 確認 Docker 與 web-app 已啟動；使用上面的 `sudo ... status` 取得 Docker 查詢權限 |
| HTTP 失敗 | 檢查 `docker compose ps`、`docker compose logs --tail 50 web-app`；容器剛啟動時稍候再試 |
| 網站正常，SSH 失敗 | 學生模式會阻擋新的 SSH；切到教師模式後確認 SSH 服務與原有防火牆 |
| 有偵測日誌但馬達不動 | 檢查 pigpiod、GPIO 供電與防禦容器 IP 的防火牆規則 |
| 顯示 Docker／Wi-Fi 子網重疊 | 依下列方式換一個不重疊的子網 |

子網衝突時，可以調整展示路由器的 LAN，或在 `docker-compose.yml` 的 `honeypot-net`
加入 `ipam`。例如以下 **僅為範例**，先確認 `10.203.0.0/24` 不與 Wi-Fi、其他網卡、VPN
及 Docker 網路重疊：

```yaml
networks:
  honeypot-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.203.0.0/24
```

修改後在教師模式下執行 `docker compose down`、`docker compose up -d` 重建網路；
`down` 不加 `-v`，保留資料庫 volume。再執行 `status`，並重新套用模式切換規則。
不要把 Wi-Fi 網段加入 `defense/monitor.py` 的白名單，這會漏掉回連到學生電腦的事件。

靶場含刻意設計的漏洞，請使用與日常設備隔離、但允許實驗設備彼此互通的展示網路。
多人瀏覽共用網站與同一套 LED／蜂鳴器／馬達；目前沒有每人獨立的實體進度。

## 開發驗證

不需 Pi 硬體即可執行的網路工具與防火牆回歸測試：

```bash
python3 -m unittest discover -s tests -p 'test_wifi*.py' -v
docker compose config --quiet
bash -n tests/smoke_test.sh
```

設定方式參考 [NetworkManager nmcli](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html)
及 [Docker Compose 網路文件](https://docs.docker.com/compose/how-tos/networking/)。
