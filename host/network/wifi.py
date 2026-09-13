#!/usr/bin/env python3
"""在 Raspberry Pi 上設定 Wi-Fi，或檢查本專案的 IPv4 網站存取。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request


MODE_FILE = Path("/run/honeypot-mode")


def run(command: list[str], *, interactive: bool = False) -> str:
    """Use argv, never a shell; let nmcli prompt for secrets directly."""
    try:
        result = subprocess.run(
            command, check=True, text=True, capture_output=not interactive,
            timeout=None if interactive else 10,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"找不到 {command[0]}，請在已安裝 NetworkManager、iproute2、Docker 的 Pi 上執行。") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{command[0]} 查詢逾時，請確認服務狀態。") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise RuntimeError(f"{command[0]} 執行失敗（{exc.returncode}）。{detail}") from exc
    return result.stdout or ""


def wifi_interface(requested: str | None) -> str:
    output = run(["nmcli", "--terse", "--escape", "no", "--fields", "DEVICE,TYPE", "device", "status"])
    interfaces = [line.rsplit(":", 1)[0] for line in output.splitlines() if line.endswith(":wifi")]
    if requested:
        if requested not in interfaces:
            raise RuntimeError(f"{requested} 不是 NetworkManager 列出的 Wi-Fi 網卡。可選：{', '.join(interfaces) or '無'}")
        return requested
    if not interfaces:
        raise RuntimeError("找不到 Wi-Fi 網卡，請確認無線硬體、驅動與 NetworkManager 已啟用。")
    if len(interfaces) > 1:
        raise RuntimeError(f"有多張 Wi-Fi 網卡，請加 --interface 指定：{', '.join(interfaces)}")
    return interfaces[0]


def wifi_addresses(interface: str) -> list[ipaddress.IPv4Interface]:
    devices = json.loads(run(["ip", "-j", "-4", "address", "show", "dev", interface]))
    addresses = []
    for device in devices:
        if "UP" not in device.get("flags", []) or device.get("operstate") != "UP":
            continue
        for info in device.get("addr_info", []):
            if info.get("family") != "inet" or info.get("scope") != "global":
                continue
            address = ipaddress.IPv4Interface(f"{info['local']}/{info['prefixlen']}")
            if not address.ip.is_link_local and not address.ip.is_loopback:
                addresses.append(address)
    return addresses


def inspect_web() -> dict:
    # Inspect only network settings, never the container environment / secrets.
    raw = run(["docker", "inspect", "web-app", "--format", "{{json .NetworkSettings}}"])
    settings = json.loads(raw)
    if not isinstance(settings, dict):
        raise RuntimeError("web-app 沒有可讀取的網路設定，請確認容器已啟動。")
    return settings


def access_urls(addresses: list[ipaddress.IPv4Interface], settings: dict) -> list[str]:
    bindings = (settings.get("Ports") or {}).get("80/tcp") or []
    return sorted({
        f"http://{address.ip}:{binding['HostPort']}"
        for address in addresses for binding in bindings
        if binding.get("HostIp") in ("0.0.0.0", str(address.ip)) and binding.get("HostPort")
    })


def subnet_conflicts(addresses: list[ipaddress.IPv4Interface], settings: dict) -> list[str]:
    conflicts = []
    for name, network in (settings.get("Networks") or {}).items():
        if not network.get("IPAddress"):
            continue
        docker_subnet = ipaddress.IPv4Network(
            f"{network['IPAddress']}/{network['IPPrefixLen']}", strict=False,
        )
        for address in addresses:
            if address.network.overlaps(docker_subnet):
                conflicts.append(f"Wi-Fi {address.network} 與 Docker {name} ({docker_subnet}) 重疊")
    return conflicts


def check_http(url: str) -> None:
    # A host HTTP check must not accidentally succeed via an HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url + "/", timeout=3) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        # HTTPError owns a response stream even when open() raises before
        # entering the context manager. Close it before reporting failure.
        exc.close()
        raise


def show_status(interface: str) -> int:
    addresses = wifi_addresses(interface)
    if not addresses:
        raise RuntimeError(f"{interface} 尚未連線或未取得可用 IPv4。請檢查 Wi-Fi 密碼、訊號及 DHCP。")
    print(f"Wi-Fi 網卡：{interface}")
    print("IPv4：" + ", ".join(str(address) for address in addresses))
    settings = inspect_web()
    conflicts = subnet_conflicts(addresses, settings)
    if conflicts:
        for conflict in conflicts:
            print(f"[FAIL] {conflict}")
        print("請調整展示路由器的 LAN 網段，或依 host/network/README.md 設定不重疊的 Docker 子網。")
        return 1
    urls = access_urls(addresses, settings)
    if not urls:
        raise RuntimeError("web-app 沒有發布可從 Wi-Fi IPv4 存取的 80/tcp；請在專案目錄執行 docker compose up -d。")
    failed = False
    for url in urls:
        print(f"\n其他設備的瀏覽器網址：{url}")
        try:
            check_http(url)
            print("[PASS] 樹莓派本機 HTTP 回應正常。")
        except (OSError, urllib.error.URLError, RuntimeError) as exc:
            print(f"[FAIL] 本機 HTTP 檢查失敗：{exc}")
            failed = True
    mode = MODE_FILE.read_text().strip() if MODE_FILE.exists() else "unknown"
    print(f"\n模式紀錄：{mode}（student 會阻擋新的 SSH 連線）")
    print("請在同 Wi-Fi 的另一台設備開啟上述網址，再拔掉直連網路線重試。")
    print("本機檢查無法驗證基地台的用戶端隔離；其他設備連不上時請檢查 AP Isolation／訪客網路。")
    return int(failed)


def connect(interface: str, ssid: str) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("設定 Wi-Fi 請使用 sudo python3 host/network/wifi.py connect --ssid 'Wi-Fi 名稱'。")
    print(f"將 {interface} 連上 {ssid}；密碼由 NetworkManager 互動詢問。", flush=True)
    run(["nmcli", "radio", "wifi", "on"])
    run(["nmcli", "--ask", "--wait", "45", "device", "wifi", "connect", ssid, "ifname", interface], interactive=True)
    addresses = wifi_addresses(interface)
    if not addresses:
        raise RuntimeError("Wi-Fi 已啟用，但尚未取得可用 IPv4；請檢查路由器 DHCP 或既有 NetworkManager 設定。")
    print("Wi-Fi IPv4：" + ", ".join(str(address) for address in addresses))
    print("連線設定由 NetworkManager 管理。請在專案目錄執行 docker compose up -d，再執行本工具 status。")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("connect", help="連上一般家用／展示 Wi-Fi；由 nmcli 互動詢問密碼")
    setup.add_argument("--ssid", required=True, help="Wi-Fi 名稱")
    setup.add_argument("--interface", help="Wi-Fi 網卡；僅有一張時自動選擇")
    status = commands.add_parser("status", help="查詢存取網址、Docker 網段衝突與本機 HTTP 回應")
    status.add_argument("--interface", help="Wi-Fi 網卡；僅有一張時自動選擇")
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        print("[FAIL] 請把專案放到 Raspberry Pi，在 Pi 的 Linux 終端機執行此工具。", file=sys.stderr)
        return 1
    try:
        interface = wifi_interface(args.interface)
        if args.command == "connect":
            connect(interface, args.ssid)
            return 0
        return show_status(interface)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
