#!/usr/bin/env python3
"""IoT Honeypot mode switch — runs on the Raspberry Pi host.

Reads a two-position toggle switch on GPIO 27 and applies one of two
iptables INPUT-chain rule sets:

  student mode (switch open, GPIO held high by internal pull-up)
    INPUT default DROP. Only loopback, ESTABLISHED/RELATED, ICMP, and
    pigpiod (8888/tcp) arriving on a Docker bridge interface
    (docker0 / br-*) are allowed. External SSH to the Pi is dropped.

  teacher mode (switch closed, GPIO grounded)
    INPUT chain flushed, default ACCEPT. Normal Pi access.

Container traffic is unaffected: only the filter/INPUT chain is
modified, so Docker's FORWARD/DOCKER/DOCKER-USER chains and all
nat-table chains stay intact.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

SWITCH_GPIO = 27
PIGPIOD_PORT = 8888
# iptables wildcard: br-+ matches user-defined docker bridges (br-XXXXXX).
# Constraining by interface (rather than source CIDR) prevents same-LAN
# hosts on 172.16/12 from reaching pigpiod.
DOCKER_BRIDGES = ("docker0", "br-+")
STATE_FILE = Path("/run/honeypot-mode")
IPTABLES_LOCK_WAIT = "5"  # seconds; -w avoids xtables-lock races with Docker

LOG = logging.getLogger("mode-switch")
APPLY_LOCK = threading.Lock()  # serialise concurrent edge callbacks


class _Iptables:
    """Wrapper that probes availability lazily and uses -w on every call."""

    def __init__(self, family: str) -> None:
        self.family = family
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            try:
                subprocess.run(
                    [self.family, "-w", IPTABLES_LOCK_WAIT, "-S", "INPUT"],
                    check=True, capture_output=True,
                )
                self._available = True
            except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                LOG.warning("%s unavailable; that family will not be enforced: %s",
                            self.family, exc)
                self._available = False
        return self._available

    def __call__(self, *args: str) -> None:
        if not self.available:
            return
        cmd = [self.family, "-w", IPTABLES_LOCK_WAIT, *args]
        LOG.debug("$ %s", " ".join(cmd))
        subprocess.run(cmd, check=True, capture_output=True, text=True)


_v4 = _Iptables("iptables")
_v6 = _Iptables("ip6tables")


def _rebuild_input(ipt: _Iptables, rules: list[list[str]], policy: str) -> None:
    """Lockout-safe INPUT-chain rebuild.

    Set policy ACCEPT first so flushing cannot leave the chain in
    'DROP + no ESTABLISHED rule' state if a later step fails. Final
    policy is set last.
    """
    if not ipt.available:
        return
    ipt("-P", "INPUT", "ACCEPT")
    ipt("-F", "INPUT")
    for rule in rules:
        ipt(*rule)
    ipt("-P", "INPUT", policy)


def apply_student() -> None:
    v4_rules: list[list[str]] = [
        ["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        ["-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
    ]
    for bridge in DOCKER_BRIDGES:
        v4_rules.append([
            "-A", "INPUT", "-i", bridge, "-p", "tcp",
            "--dport", str(PIGPIOD_PORT), "-j", "ACCEPT",
        ])
    v6_rules: list[list[str]] = [
        ["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        ["-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["-A", "INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT"],
    ]
    _rebuild_input(_v4, v4_rules, "DROP")
    _rebuild_input(_v6, v6_rules, "DROP")


def apply_teacher() -> None:
    _rebuild_input(_v4, [], "ACCEPT")
    _rebuild_input(_v6, [], "ACCEPT")


MODES = {
    "student": apply_student,
    "teacher": apply_teacher,
}


def set_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError(f"unknown mode: {mode}")
    with APPLY_LOCK:
        LOG.info("[MODE] -> %s", mode)
        MODES[mode]()
        try:
            STATE_FILE.write_text(mode + "\n")
        except OSError as exc:
            LOG.warning("state file write failed: %s", exc)
        LOG.info("[MODE] active: %s", mode)


def daemon_loop() -> None:
    from gpiozero import Button

    sw = Button(SWITCH_GPIO, pull_up=True, bounce_time=0.05)

    def current_mode() -> str:
        # pull_up=True: switch closed (to GND) -> is_pressed=True -> teacher
        return "teacher" if sw.is_pressed else "student"

    last: str | None = None

    def on_change() -> None:
        nonlocal last
        m = current_mode()
        if m == last:
            return
        try:
            set_mode(m)
            last = m
        except subprocess.CalledProcessError as exc:
            LOG.error("mode apply failed: %s\n%s", exc, exc.stderr)

    sw.when_pressed = on_change
    sw.when_released = on_change
    on_change()  # apply initial state

    LOG.info("[DAEMON] watching GPIO %d (pull_up=True)", SWITCH_GPIO)
    signal.pause()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--mode", choices=list(MODES),
                   help="set mode once and exit (no GPIO needed)")
    p.add_argument("--daemon", action="store_true",
                   help=f"watch GPIO {SWITCH_GPIO} and apply on change")
    p.add_argument("--show", action="store_true",
                   help="print current iptables INPUT policy and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.show:
        for family in ("iptables", "ip6tables"):
            print(f"=== {family} INPUT ===")
            r = subprocess.run(
                [family, "-L", "INPUT", "-n", "--line-numbers"],
                check=False, capture_output=True, text=True,
            )
            print(r.stdout, end="")
        if STATE_FILE.exists():
            print(f"=== last applied: {STATE_FILE.read_text().strip()} ===")
        return 0

    if os.geteuid() != 0:
        LOG.error("must run as root (need iptables / GPIO)")
        return 2

    if args.mode:
        set_mode(args.mode)
        return 0

    if args.daemon:
        daemon_loop()
        return 0

    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
