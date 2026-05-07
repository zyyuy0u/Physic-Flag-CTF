#!/usr/bin/env python3
"""IoT Honeypot mode switch — runs on the Raspberry Pi host.

Reads a two-position toggle switch on GPIO 27 and applies one of two
firewall modes via a dedicated HONEYPOT-INPUT chain.

We own *only* our chain plus a single jump from INPUT (position 1).
Other rules in INPUT and all of FORWARD/DOCKER/nat are untouched, so
operators with their own host firewall keep their rules in both modes.

  student mode (switch open, GPIO held high by internal pull-up)
    HONEYPOT-INPUT terminates with DROP. Allows only loopback,
    ESTABLISHED/RELATED, ICMP, and pigpiod (8888/tcp) from the
    defense-system container's exact source IP arriving on a Docker
    bridge interface (docker0 / br-+). External SSH is dropped, the
    web-app container cannot reach pigpiod even with RCE.

  teacher mode (switch closed, GPIO grounded)
    Jump removed from INPUT. Pi behaves as if the daemon weren't
    installed; INPUT's own policy/rules apply unchanged.
"""

from __future__ import annotations

import argparse
import fcntl
import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

SWITCH_GPIO = 27
PIGPIOD_PORT = 8888
DOCKER_BRIDGES = ("docker0", "br-+")  # iptables interface wildcards
HP_CHAIN = "HONEYPOT-INPUT"
DEFENSE_LABEL = "com.docker.compose.service=defense-system"
# Optional: scope defense container lookup to a specific compose project
# when multiple compose stacks share the service name. Set via env in
# the systemd unit if needed.
DEFENSE_PROJECT = os.environ.get("HONEYPOT_COMPOSE_PROJECT")
# tmpfs by design: state is re-derived from GPIO on every boot, so a
# missing file just means "fresh boot" and is not an error.
STATE_FILE = Path("/run/honeypot-mode")
# Cross-process lock so daemon + manual `--mode X` cannot race on
# iptables. threading.Lock alone is process-local.
LOCK_FILE = Path("/run/honeypot-mode.lock")
IPTABLES_LOCK_WAIT = "5"

LOG = logging.getLogger("mode-switch")
APPLY_LOCK = threading.Lock()

# IPv6 fail-closed: if the kernel has IPv6 enabled (/proc/net/if_inet6
# exists), ip6tables MUST work — silently skipping it would leave
# IPv6 SSH reachable in student mode. If IPv6 is genuinely disabled
# at the kernel level, ip6tables is skipped without complaint.
_IPV6_REQUIRED = Path("/proc/net/if_inet6").exists()
_FAMILIES: list[str] = ["iptables"]
if _IPV6_REQUIRED:
    _FAMILIES.append("ip6tables")


def _iptables(family: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [family, "-w", IPTABLES_LOCK_WAIT, *args]
    LOG.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def _defense_container_ip() -> str | None:
    """Resolve the defense-system container's IP via the compose label.

    Returns None when Docker isn't running or the container isn't up;
    caller logs a warning and the pigpiod allow rule is omitted, so
    the servo will not actuate until the operator brings the stack up
    and re-applies student mode.
    """
    cmd = ["docker", "ps", "-q", "--filter", f"label={DEFENSE_LABEL}"]
    if DEFENSE_PROJECT:
        cmd += ["--filter", f"label=com.docker.compose.project={DEFENSE_PROJECT}"]
    try:
        ps = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=True)
        cids = ps.stdout.strip().splitlines()
        if not cids:
            return None
        if len(cids) > 1:
            LOG.warning(
                "[STUDENT] %d defense-system containers match; using the first. "
                "Set HONEYPOT_COMPOSE_PROJECT to disambiguate.", len(cids),
            )
        ipq = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
             cids[0]],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return ipq.stdout.strip() or None
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        LOG.debug("defense container lookup failed: %s", exc)
        return None


def _atomic_rebuild_chain(family: str, rules: list[list[str]]) -> None:
    """Atomic flush + repopulate of HONEYPOT-INPUT via iptables-restore -n.

    Built so that even if INPUT is already jumping into HONEYPOT-INPUT,
    in-flight packets never see the chain in a half-built state: the
    kernel commits the entire *filter block as one transaction.

    With -n (noflush), only the operations listed in the input run; we
    don't touch any other chain. The ":HONEYPOT-INPUT - [0:0]" header
    creates the chain on first use; -F flushes it; -A appends the new
    rules; COMMIT applies them atomically.
    """
    restore = f"{family}-restore"
    lines = ["*filter", f":{HP_CHAIN} - [0:0]", f"-F {HP_CHAIN}"]
    lines.extend(" ".join(r) for r in rules)
    lines.append("COMMIT")
    payload = "\n".join(lines) + "\n"
    LOG.debug("piping to %s -n:\n%s", restore, payload)
    subprocess.run(
        [restore, "-n", "-w", IPTABLES_LOCK_WAIT],
        input=payload, check=True, capture_output=True, text=True,
    )


def _remove_jump(family: str) -> None:
    """Remove every INPUT->HONEYPOT-INPUT jump (idempotent)."""
    while _iptables(family, "-D", "INPUT", "-j", HP_CHAIN, check=False).returncode == 0:
        pass


def _ensure_jump(family: str) -> None:
    """Put '-j HONEYPOT-INPUT' at INPUT position 1 with no enforcement gap.

    Insert FIRST (so a jump is always present), then list and remove any
    duplicates at lines > 1, deleting from the highest line number down
    so our own deletes don't shift the remaining numbers. Finally
    verify a jump still exists; if a concurrent INPUT-chain writer
    (Docker is not one — it doesn't touch INPUT — but a hand-run
    `iptables -I INPUT` or firewalld could) raced us into deleting our
    own jump, re-insert it.

    The mode-switch's own multi-writer races are blocked by `LOCK_FILE`;
    this fallback handles only outside writers, which are unsupported
    but degraded gracefully rather than silently bypassed.
    """
    _iptables(family, "-I", "INPUT", "1", "-j", HP_CHAIN)

    listing = subprocess.run(
        [family, "-w", IPTABLES_LOCK_WAIT, "-L", "INPUT", "--line-numbers", "-n"],
        check=True, capture_output=True, text=True,
    ).stdout
    extras: list[int] = []
    for line in listing.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[1] == HP_CHAIN:
            try:
                num = int(parts[0])
            except ValueError:
                continue
            if num > 1:
                extras.append(num)
    for num in sorted(extras, reverse=True):
        _iptables(family, "-D", "INPUT", str(num))

    save_out = subprocess.run(
        [family, "-w", IPTABLES_LOCK_WAIT, "-S", "INPUT"],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"-A INPUT -j {HP_CHAIN}" not in save_out:
        LOG.warning(
            "[%s] HONEYPOT-INPUT jump missing after cleanup (concurrent INPUT "
            "writer?); re-inserting at position 1.", family,
        )
        _iptables(family, "-I", "INPUT", "1", "-j", HP_CHAIN)


def _student_rules(family: str) -> list[list[str]]:
    rules: list[list[str]] = [
        ["-A", HP_CHAIN, "-i", "lo", "-j", "ACCEPT"],
        ["-A", HP_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    if family == "iptables":
        rules.append(["-A", HP_CHAIN, "-p", "icmp", "-j", "ACCEPT"])
        defense_ip = _defense_container_ip()
        if defense_ip:
            for bridge in DOCKER_BRIDGES:
                rules.append([
                    "-A", HP_CHAIN, "-i", bridge, "-s", defense_ip,
                    "-p", "tcp", "--dport", str(PIGPIOD_PORT), "-j", "ACCEPT",
                ])
            LOG.info("[STUDENT] pigpiod %d/tcp scoped to defense-system @ %s",
                     PIGPIOD_PORT, defense_ip)
        else:
            LOG.warning(
                "[STUDENT] defense-system container not found; pigpiod allow "
                "rule SKIPPED. Servo will not actuate until the docker stack "
                "is up — then re-run --mode student or restart the daemon."
            )
    else:  # ip6tables
        rules.append(["-A", HP_CHAIN, "-p", "ipv6-icmp", "-j", "ACCEPT"])
    rules.append(["-A", HP_CHAIN, "-j", "DROP"])
    return rules


def apply_student() -> None:
    for family in _FAMILIES:
        _atomic_rebuild_chain(family, _student_rules(family))
        _ensure_jump(family)


def apply_teacher() -> None:
    for family in _FAMILIES:
        _remove_jump(family)
        # Empty the chain (atomically) so a later --show looks clean
        # and a re-entry to student is fast.
        _atomic_rebuild_chain(family, [])


MODES = {"student": apply_student, "teacher": apply_teacher}


def set_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError(f"unknown mode: {mode}")
    with APPLY_LOCK:
        # Cross-process exclusion: blocks daemon vs. manual `--mode`
        # collisions on the same host. flock auto-releases on close.
        with open(LOCK_FILE, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
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
            LOG.error("mode apply failed: rc=%d cmd=%s\nstderr: %s",
                      exc.returncode, exc.cmd, exc.stderr)

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
                   help="print current INPUT + HONEYPOT-INPUT chains and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.show:
        for family in _FAMILIES:
            for chain in ("INPUT", HP_CHAIN):
                print(f"=== {family} {chain} ===")
                r = subprocess.run(
                    [family, "-L", chain, "-n", "--line-numbers"],
                    check=False, capture_output=True, text=True,
                )
                print(r.stdout if r.returncode == 0 else f"(chain absent)\n", end="")
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
