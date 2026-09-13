# GPIO 與 pigpiod 排錯

LED 使用 RPi.GPIO 的 **BCM22（實體第15腳）**，蜂鳴器使用 BCM24，馬達透過
宿主機的 pigpiod 控制 BCM18。Wi-Fi 網站可連線不代表馬達 daemon 可連線。

## 網站有 /admin，但 LED 沒亮

舊版 `hardware_setup()` 先等待 pigpiod 連線，之後才啟動日誌監控，且只讀新日誌。
例如 13:15:17 開始連 pigpiod，13:17:31 才啟動監控，中間的掃描就不會被偵測。
新版將馬達連線放到背景，首次讀取自本次監控啟動時間起的日誌，並將直接 GPIO 的鎖
與馬達通訊的鎖分開。pigpio 套件缺失也不再使 LED 進入模擬模式。

在 Pi 的專案目錄更新並重啟監控。先結束你手動點燈的程式，避免它同時修改 GPIO：

```bash
git pull --ff-only
docker compose restart defense-system
curl -sS --max-time 10 -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:8080/admin
sleep 2
docker compose logs --no-color --tail 50 defense-system
```

`defense` 原始碼以 volume 掛載，這次 Python 修改只需要重啟，不需重建映像。

| 日誌 | 意義 |
|---|---|
| `[LED1] 命中 /admin` | 確認事件命中，不能單憑它判斷燈已亮 |
| `[GPIO] ... 已寫入 HIGH ... 讀回電位=1` | BCM22 讀回高電位；仍需確認接線、LED 極性及手動程式的腳位編號 |
| `[GPIO] ... 讀回電位=0` | 需檢查腳位方向、其他程式或接線是否把電位拉低 |
| `[GPIO] ... 模擬模式` | 容器內 RPi.GPIO 無法使用，查啟動日誌中的錯誤 |
| `[GPIO] ... 輸出／讀回失敗` | 查後續 traceback；GPIO 操作錯誤會被記錄，不會中斷後續日誌偵測 |
| `[PIGPIO] ... 連線失敗` | 馬達連線有問題；新版 LED/蜂鳴器監控仍會運行 |

如果手動 Python 使用 `GPIO.BOARD`、gpiozero 或其他套件，請確認實際腳位對應。
手動程式的 `GPIO.cleanup()` 可能改變監控程式正在使用的腳位方向；測試結束後重啟
`defense-system` 再發一次 `/admin`。系統不會從電位讀回推斷實體燈泡一定已亮。

## pigpiod 連不上

先在 Pi 確認 daemon 與容器地址：

```bash
sudo systemctl status pigpiod --no-pager
pgrep -a pigpiod
sudo ss -lntp 'sport = :8888'
DEFENSE_ID=$(docker compose ps -q defense-system)
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DEFENSE_ID"
sudo python3 host/mode-switch/mode_switch.py --show
```

[`pigpiod -n`](https://github.com/joan2937/pigpio/blob/master/pigpiod.1) 指定**允許連入的用戶端 IP**。
`0.0.0.0` 不代表允許所有用戶端；舊版 README 的指令有誤。
`-l` 限制本機存取、`-k` 關閉 socket，均不適合目前的容器連線方式。

若沒有現存 daemon，可依 README 使用 `sudo pigpiod -n localhost -n "$DEFENSE_IP"`
啟動，`DEFENSE_IP` 必須是上述 defense-system 的實際 IPv4。

若已有 systemd 服務，先用 `sudo systemctl cat pigpiod` 檢查既有設定，再以
`sudo systemctl edit pigpiod` 更新 ExecStart。例如 daemon 位於 `/usr/bin/pigpiod` 時：

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/pigpiod -n localhost -n <defense-system的實際IPv4>
```

將 `<...>` 換成實際 IP，保留你需要的其他硬體參數，並沿用原服務所需的前景／背景模式。
然後執行 `sudo systemctl daemon-reload`、`sudo systemctl restart pigpiod`。
這個允許清單不會自動追蹤 Docker IP；容器重建或 IP 改變後需更新設定。

學生模式另有一層防火牆，只允許防禦容器的來源 IP 從 Docker bridge 存取 8888。
Docker 啟動後切到教師模式、再切回學生模式，可更新該來源 IP；只換 daemon 設定
不會更新防火牆。新版監控會背景重試尚未成功的馬達連線。
若是原本已成功的連線中途斷線，修好 daemon／規則後再重啟 `defense-system`。
