"""Wi-Fi CLI regression tests. System queries are fixtures; HTTP uses localhost."""

import contextlib
from copy import deepcopy
import importlib.util
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wifi", ROOT / "host/network/wifi.py")
wifi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wifi)

ADDRESSES = [{
    "ifname": "wlan0", "flags": ["UP", "LOWER_UP"], "operstate": "UP",
    "addr_info": [{"family": "inet", "scope": "global", "local": "192.168.50.20", "prefixlen": 24}],
}]
SETTINGS = {
    "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
    "Networks": {"honeypot-net": {"IPAddress": "172.20.0.2", "IPPrefixLen": 16}},
}


class WifiStatusTests(unittest.TestCase):
    def setUp(self):
        self.addresses = deepcopy(ADDRESSES)
        self.settings = deepcopy(SETTINGS)
        self.devices = "lo:loopback\neth0:ethernet\nwlan0:wifi\np2p-dev-wlan0:wifi-p2p\n"
        self.commands = []

        def system_query(command, **kwargs):
            self.commands.append(command)
            if command[0] == "nmcli":
                return self.devices
            if command[0] == "ip":
                return json.dumps(self.addresses)
            if command[0] == "docker":
                return json.dumps(self.settings)
            self.fail(f"Unexpected command: {command}")

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        mode_file = Path(self.temp.name) / "mode"
        mode_file.write_text("student\n")
        for target, value in (("run", system_query), ("MODE_FILE", mode_file)):
            patcher = patch.object(wifi, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        platform = patch.object(wifi.sys, "platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)

    def status(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = wifi.main(["status"])
        return code, out.getvalue()

    @patch.object(wifi, "check_http")
    def test_status_reports_wifi_url_and_limits_of_local_check(self, http):
        code, output = self.status()
        self.assertEqual(code, 0, output)
        self.assertIn("http://192.168.50.20:8080", output)
        self.assertIn("student", output)
        self.assertIn("本機檢查無法驗證", output)
        http.assert_called_once_with("http://192.168.50.20:8080")

    @patch.object(wifi, "check_http")
    def test_loopback_or_old_ethernet_binding_is_not_advertised(self, http):
        for bind_ip in ("127.0.0.1", "192.168.10.20", "::1"):
            with self.subTest(bind_ip=bind_ip):
                self.settings["Ports"]["80/tcp"][0]["HostIp"] = bind_ip
                code, output = self.status()
                self.assertEqual(code, 1, output)
                self.assertNotIn("其他設備的瀏覽器網址", output)
        http.assert_not_called()

    @patch.object(wifi, "check_http")
    def test_actual_wifi_binding_and_published_port_are_used(self, http):
        self.settings["Ports"]["80/tcp"] = [{"HostIp": "192.168.50.20", "HostPort": "9090"}]
        code, output = self.status()
        self.assertEqual(code, 0, output)
        http.assert_called_once_with("http://192.168.50.20:9090")

    @patch.object(wifi, "check_http")
    def test_phone_hotspot_subnet_overlap_fails_before_http(self, http):
        self.addresses[0]["addr_info"][0]["local"] = "172.20.10.2"
        code, output = self.status()
        self.assertEqual(code, 1, output)
        self.assertIn("重疊", output)
        http.assert_not_called()

    def test_unconnected_or_link_local_wifi_has_no_access_url(self):
        for update in ("down", "no_address", "link_local"):
            with self.subTest(update=update):
                self.addresses = deepcopy(ADDRESSES)
                if update == "down":
                    self.addresses[0]["operstate"] = "DOWN"
                elif update == "no_address":
                    self.addresses[0]["addr_info"] = []
                else:
                    self.addresses[0]["addr_info"][0]["local"] = "169.254.1.2"
                code, output = self.status()
                self.assertEqual(code, 1, output)
                self.assertNotIn("其他設備的瀏覽器網址", output)

    def test_no_ports_or_invalid_inspect_result_fails_cleanly(self):
        for settings in ({"Ports": None}, None):
            with self.subTest(settings=settings):
                self.settings = settings
                code, output = self.status()
                self.assertEqual(code, 1, output)
                self.assertIn("[FAIL]", output)

    @patch.object(wifi, "check_http", side_effect=OSError("connection refused"))
    def test_unreachable_http_is_a_failure(self, http):
        code, output = self.status()
        self.assertEqual(code, 1, output)
        self.assertIn("connection refused", output)

    def test_multiple_wifi_interfaces_require_explicit_choice(self):
        self.devices += "wlx001122334455:wifi\n"
        code, output = self.status()
        self.assertEqual(code, 1, output)
        self.assertIn("--interface", output)
        self.assertEqual(wifi.wifi_interface("wlx001122334455"), "wlx001122334455")
        with self.assertRaises(RuntimeError):
            wifi.wifi_interface("eth0")


class WifiConnectTests(unittest.TestCase):
    @patch.object(wifi.os, "geteuid", return_value=0)
    def test_ssid_is_one_argument_and_password_prompt_is_not_captured(self, root):
        # Spaces and shell metacharacters must reach nmcli unchanged.
        ssid = "Lab Wi-Fi $(not-a-command); `literal`"

        def process(command, **kwargs):
            self.assertFalse(kwargs.get("shell", False))
            return subprocess.CompletedProcess(command, 0, json.dumps(ADDRESSES) if command[0] == "ip" else "")

        with patch.object(wifi.subprocess, "run", side_effect=process) as run, contextlib.redirect_stdout(io.StringIO()):
            wifi.connect("wlan0", ssid)
        interactive = [call for call in run.call_args_list if "--ask" in call.args[0]]
        self.assertEqual(len(interactive), 1)
        self.assertIn(ssid, interactive[0].args[0])
        self.assertFalse(interactive[0].kwargs["capture_output"])
        self.assertNotIn("password", interactive[0].args[0])

    @patch.object(wifi.os, "geteuid", return_value=1000)
    @patch.object(wifi, "run")
    def test_connect_without_root_does_not_change_network(self, run, uid):
        with self.assertRaisesRegex(RuntimeError, "sudo"):
            wifi.connect("wlan0", "Lab")
        run.assert_not_called()

    @patch.object(wifi.os, "geteuid", return_value=0)
    @patch.object(wifi, "run", side_effect=RuntimeError("nmcli failed"))
    def test_failed_connect_does_not_print_success(self, run, uid):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(RuntimeError):
            wifi.connect("wlan0", "Lab")
        self.assertNotIn("Wi-Fi IPv4", out.getvalue())

    def test_command_errors_are_actionable(self):
        errors = [FileNotFoundError(), subprocess.TimeoutExpired("nmcli", 10),
                  subprocess.CalledProcessError(1, "docker", stderr="permission denied")]
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.object(wifi.subprocess, "run", side_effect=error):
                with self.assertRaises(RuntimeError):
                    wifi.run(["docker", "inspect", "web-app"])


class HttpCheckTests(unittest.TestCase):
    def test_local_http_probe_ignores_proxy_and_rejects_http_error(self):
        class Handler(BaseHTTPRequestHandler):
            response_code = 200

            def do_GET(self):
                self.send_response(self.response_code)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            with patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "no_proxy": ""}):
                wifi.check_http(url)
                Handler.response_code = 503
                with self.assertRaises(urllib.error.HTTPError):
                    wifi.check_http(url)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
