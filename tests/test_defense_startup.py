"""Detection must run while the optional pigpio connection is unavailable."""

import atexit
import importlib.util
import io
from pathlib import Path
import signal
import sys
import threading
import types
import unittest
from unittest.mock import MagicMock, patch, mock_open


ROOT = Path(__file__).resolve().parents[1]


def load_monitor(*, missing_gpio=False, missing_pigpio=False):
    gpio = types.ModuleType("RPi.GPIO")
    gpio.BCM, gpio.OUT, gpio.LOW, gpio.HIGH = 11, 0, 0, 1
    for name in ("setwarnings", "setmode", "setup", "output", "input", "cleanup"):
        setattr(gpio, name, MagicMock())
    gpio.input.return_value = gpio.HIGH
    rpi = types.ModuleType("RPi")
    rpi.GPIO = gpio
    pigpio = types.ModuleType("pigpio")
    pigpio.pi = MagicMock()
    bpf = types.ModuleType("bpf_loader")
    bpf.BpfReverseShellProbe = MagicMock()
    bpf.ParsedEvent = object
    modules = {"RPi": rpi, "RPi.GPIO": None if missing_gpio else gpio,
               "pigpio": None if missing_pigpio else pigpio, "bpf_loader": bpf}
    spec = importlib.util.spec_from_file_location("defense_startup_test", ROOT / "defense/monitor.py")
    monitor = importlib.util.module_from_spec(spec)
    # Import without changing the test runner's signal handlers / exit hooks.
    with patch.dict(sys.modules, modules), patch.object(signal, "signal"), patch.object(atexit, "register"), patch("logging.warning"):
        spec.loader.exec_module(monitor)
    return monitor, gpio


class DefenseStartupTests(unittest.TestCase):
    def setUp(self):
        self.monitor, self.gpio = load_monitor()

    def test_admin_and_bpf_run_while_motor_connection_is_blocked(self):
        m = self.monitor
        connecting, release, lit, bpf_started, boot_done = [threading.Event() for _ in range(5)]
        workers, errors = [], []

        def blocked_connection():
            connecting.set()
            release.wait(4)
            return None

        def log_lines():
            yield '172.20.10.2 - - [13/Sep/2026:13:16:00 +0000] "GET /admin HTTP/1.1" 200 5388'
            m.shutdown_event.wait(4)

        def output(pin, level):
            if pin == m.PIN_GREEN and level == self.gpio.HIGH:
                lit.set()

        def bpf_consumer(whitelist):
            bpf_started.set()
            m.shutdown_event.wait(4)

        def boot():
            try:
                m.hardware_setup()
                workers.extend(m.start_workers([], "2026-09-13T13:15:17+00:00"))
                boot_done.set()
            except Exception as exc:
                errors.append(exc)

        proc = MagicMock()
        proc.stdout = log_lines()
        self.gpio.output.side_effect = output
        with patch.object(m, "connect_pigpio", side_effect=blocked_connection), \
                patch.object(m, "bpf_event_consumer", side_effect=bpf_consumer), \
                patch.object(m.subprocess, "Popen", return_value=proc), \
                self.assertLogs(m.log, level="INFO"):
            bootstrap = threading.Thread(target=boot, daemon=True)
            bootstrap.start()
            try:
                self.assertTrue(connecting.wait(1), errors)
                self.assertTrue(boot_done.wait(1), errors)
                self.assertTrue(lit.wait(1), "LED waited for pigpio to connect")
                self.assertTrue(bpf_started.wait(1), "eBPF waited for pigpio to connect")
                self.assertFalse(release.is_set())
            finally:
                m.shutdown_event.set()
                release.set()
                bootstrap.join(timeout=2)
                for worker in workers:
                    if worker is not None:
                        worker.join(timeout=2)
            self.assertFalse(errors)

    def test_missing_pigpio_does_not_disable_direct_gpio(self):
        m, gpio = load_monitor(missing_pigpio=True)
        self.assertTrue(m.GPIO_AVAILABLE)
        self.assertFalse(m.PIGPIO_AVAILABLE)
        m.hardware_setup()
        with self.assertLogs(m.log, level="INFO") as messages:
            m.trigger_led()
        gpio.output.assert_called_once_with(22, gpio.HIGH)
        self.assertEqual(sum("[LED1]" in line for line in messages.output), 1)
        self.assertTrue(any("讀回電位=1" in line for line in messages.output))

    def test_led_and_buzzer_do_not_wait_for_motor_io_lock(self):
        m = self.monitor
        done = threading.Event()

        def drive_gpio():
            m.trigger_led()
            m._gpio_buzz_safe(self.gpio.HIGH)
            done.set()

        with self.assertLogs(m.log):
            worker = threading.Thread(target=drive_gpio, daemon=True)
            try:
                with m.motor_lock:
                    worker.start()
                    self.assertTrue(done.wait(1), "Direct GPIO waited for a motor socket operation")
            finally:
                worker.join(timeout=2)
        self.assertEqual(self.gpio.output.call_count, 2)

    def test_no_gpio_write_after_shutdown(self):
        m = self.monitor
        m.shutdown_event.set()
        with self.assertLogs(m.log):
            m.trigger_led()
            self.assertFalse(m._gpio_buzz_safe(self.gpio.HIGH))
        self.gpio.output.assert_not_called()

    def test_gpio_error_is_reported_without_stopping_next_detection(self):
        self.gpio.output.side_effect = [RuntimeError("GPIO was reset"), None]
        with self.assertLogs(self.monitor.log, level="INFO") as messages:
            self.monitor.trigger_led()
            self.monitor.trigger_led()
        self.assertEqual(self.gpio.output.call_count, 2)
        self.assertTrue(any("輸出／讀回失敗" in line for line in messages.output))
        self.assertEqual(sum("[LED1]" in line for line in messages.output), 2)

    def test_simulation_never_claims_a_gpio_write(self):
        self.monitor.GPIO_AVAILABLE = False
        with self.assertLogs(self.monitor.log, level="INFO") as messages:
            self.monitor.trigger_led()
        self.gpio.output.assert_not_called()
        self.assertTrue(any("未送出實體 GPIO 指令" in line for line in messages.output))
        self.assertFalse(any("已寫入 HIGH" in line for line in messages.output))

    def test_motor_connection_finishing_after_shutdown_cannot_move_servo(self):
        m = self.monitor
        candidate = MagicMock()

        def late_connection():
            m.shutdown_event.set()
            return candidate

        with patch.object(m, "connect_pigpio", side_effect=late_connection):
            m.motor_setup_worker()
        candidate.set_servo_pulsewidth.assert_not_called()
        candidate.stop.assert_called_once()
        self.assertIsNone(m.pi)

    def test_failed_motor_connection_retries_and_initialises_once(self):
        m = self.monitor
        candidate = MagicMock()
        with patch.object(m, "connect_pigpio", side_effect=[None, candidate]) as connect, \
                patch.object(m.shutdown_event, "wait", return_value=False), patch.object(m.time, "sleep"):
            m.motor_setup_worker()
        self.assertEqual(connect.call_count, 2)
        candidate.set_servo_pulsewidth.assert_called_once_with(m.PIN_SERVO, m.SERVO_UP)
        self.assertIs(m.pi, candidate)
        candidate.stop.assert_not_called()

    def test_servo_cleanup_still_runs_when_gpio_module_is_unavailable(self):
        m = self.monitor
        m.GPIO_AVAILABLE = False
        m.pi = MagicMock(connected=True)
        actions = []
        m.pi.set_servo_pulsewidth.side_effect = lambda pin, width: actions.append(("pulse", width))
        m.pi.stop.side_effect = lambda: actions.append(("stop",))
        with patch.object(m.signal, "signal"), patch.object(m.time, "sleep", side_effect=lambda duration: actions.append(("sleep", duration))):
            m._cleanup_hardware()
        self.assertEqual(actions, [("pulse", 500), ("sleep", 1), ("pulse", 0), ("stop",)])
        self.assertTrue(m.shutdown_event.is_set())
        self.gpio.cleanup.assert_not_called()

    def test_initial_log_subscription_includes_startup_window(self):
        m = self.monitor
        proc = MagicMock()
        proc.stdout = io.StringIO('host - - [date] "GET /admin HTTP/1.1" 200 100\n')
        proc.wait.side_effect = m.shutdown_event.set
        started_at = "2026-09-13T13:15:17+00:00"
        with patch.object(m.subprocess, "Popen", return_value=proc) as popen, self.assertLogs(m.log):
            m.docker_log_monitor(started_at)
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("--since") + 1], started_at)
        self.assertNotIn("--tail", command)
        self.gpio.output.assert_called_once_with(22, self.gpio.HIGH)

    def test_gateway_is_found_without_iproute2(self):
        routes = "Iface Destination Gateway Flags\neth0 00000000 010012AC 0003\n"
        with patch.object(self.monitor.subprocess, "run", side_effect=FileNotFoundError), \
                patch("builtins.open", mock_open(read_data=routes)):
            self.assertEqual(self.monitor.get_host_gateway_ip(), "172.18.0.1")

    def test_unreachable_pigpiod_candidate_is_skipped_before_library_connect(self):
        m = self.monitor
        m.PIGPIO_HOST = "host.docker.internal"
        candidate = MagicMock(connected=True)
        m.pigpio.pi.return_value = candidate
        with patch.object(m, "get_host_gateway_ip", return_value=None), \
                patch.object(m.socket, "create_connection", side_effect=[TimeoutError(), MagicMock()]), \
                self.assertLogs(m.log):
            self.assertIs(m.connect_pigpio(), candidate)
        m.pigpio.pi.assert_called_once_with("localhost", 8888, show_errors=False)


if __name__ == "__main__":
    unittest.main()
