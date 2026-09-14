# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Educational IoT honeypot for Raspberry Pi. A deliberately-vulnerable PHP/MariaDB "smart-home" web app runs alongside a Python defense monitor that drives physical hardware (two LEDs and an SG90 servo) to visualise three attack categories. Do not deploy on a public network.

Default admin credential seeded by `web/src/setup_db.php`: `admin` / `sm@rtH0me2024!`. Web app is exposed on host port **8080**.

## Common commands

```bash
# Host prerequisite for the servo: pigpiod must allow the defense container
# at host:8888. -n is a CLIENT allowlist, not a bind address. See
# docs/gpio-troubleshooting.md for startup / systemd configuration.

# Build + start all three services (db, web-app, defense-system)
docker compose up -d --build

# Tail the defense monitor (the only "interesting" log stream)
docker compose logs -f defense-system

# Rebuild a single service after code change
docker compose up -d --build defense-system
docker compose up -d --build web-app

# Reset DB (the volume `db_data` persists between runs)
docker compose down -v && docker compose up -d
```

Host-side mode switch (student / teacher) — see `host/mode-switch/`:

```bash
# Install (does NOT enable or start the service — by design)
sudo ./host/mode-switch/install.sh
# Enable + start when ready (prompts for confirmation):
sudo ./host/mode-switch/install.sh --start

# Force a mode without flipping the physical switch (testing)
sudo /opt/honeypot/mode-switch/mode_switch.py --mode student
sudo /opt/honeypot/mode-switch/mode_switch.py --mode teacher

# Inspect current INPUT + HONEYPOT-INPUT chains + last applied mode
sudo /opt/honeypot/mode-switch/mode_switch.py --show
```

Wi-Fi setup (run on the Pi; see `host/network/README.md`):

```bash
sudo python3 host/network/wifi.py connect --ssid 'Demo Wi-Fi'
docker compose up -d
sudo python3 host/network/wifi.py status
```

The helper uses NetworkManager's interactive password prompt. Status checks
the Wi-Fi IPv4, actual Docker port bindings, subnet overlap, and local HTTP.
It cannot check AP/client isolation from the Pi itself. Compose explicitly
publishes `0.0.0.0:8080:80` for Wi-Fi and Ethernet IPv4 access.

Automated detection tests (run on the Pi with Python + `requests`, against a running stack; Docker logs are read locally):

```bash
# BASE_URL defaults to http://localhost:8080, matching the compose port.
# Override via env: BASE_URL=http://<pi_ip>:8080 python3 tests/...
python3 tests/test_led1_path_probe.py --start 1 --batch 100   # /admin probe → green LED
python3 tests/test_led2_sqli.py                               # SQLi bypass → buzzer (3 beeps)
```

The tests scrape the defense-system container's `docker logs` for `[LED1]` / `[BUZZER]` markers. They find it by the compose label `com.docker.compose.service=defense-system` (override with `DEFENSE_CONTAINER=<name>`), so the checkout directory name doesn't matter.

Wi-Fi CLI and firewall regression tests run without Pi hardware:
`python3 -m unittest discover -s tests -p 'test_wifi*.py' -v`.
Firewall tests evaluate traffic against generated rules; live kernel and GPIO
validation still requires the Pi. The LED/SQLi scripts are end-to-end
detection-rate experiments, not unit tests. `tests/smoke_test.sh` accepts
`REVERSE_TARGET_IP` for an offline LAN TCP probe; no listener is required.

## Architecture

Three containers on a single bridge network `honeypot-net`, defined in `docker-compose.yml`:

1. **db** — MariaDB 10.6, credentials from `.env`. Schema + seed data created on first boot by `web/src/setup_db.php`, invoked from `web/entrypoint.sh` after the DB becomes reachable.
2. **web-app** — PHP 8.2 + Apache. The Dockerfile intentionally installs `netcat-traditional`, `python3`, `perl`, `socat`, `curl` so attackers who land an RCE have tools to spawn a reverse shell — that is the whole point. (`net-tools` was previously installed for the old netstat-based detection; it remains installed but is no longer relied on by the defense system.)
3. **defense-system** — Debian Bookworm + Python 3.11 + bcc (eBPF), `privileged: true`, `pid: host`, mounts `/var/run/docker.sock`, `/sys/kernel/debug`, `/sys/fs/bpf`, `/sys/fs/cgroup`, `/lib/modules`, `/usr/src`. It has no GPIO of its own; instead it talks to **pigpiod on the host** over TCP (`PIGPIO_HOST=host.docker.internal`, port 8888) for servo PWM, and uses `RPi.GPIO` via the privileged bind for the two LEDs. The host gateway is wired in via `extra_hosts: host.docker.internal:host-gateway`.

### The single source of truth for detection logic: `defense/monitor.py` + `defense/bpf_loader.py` + `defense/bpf_probe.c`

Everything the honeypot "does" lives in two threads launched from `main()`:

- **Thread A — `docker_log_monitor`**: streams `docker logs -f web-app` (initial subscription uses `--since` this monitor's startup timestamp) and matches each line against two regexes:
  - `ADMIN_PATTERN` (`(?:GET|HEAD|POST) /admin[\s/?]`) → green LED on (GPIO 22), logged as `[LED1]`. Case-sensitive on purpose — Apache won't serve `/Admin` so adding `IGNORECASE` would only count noise.
  - `DASHBOARD_PATTERN` (`"GET /dashboard.php..." 200`) → buzzer 3-beep alarm (GPIO 24), logged as `[BUZZER]`. Detection assumes unauthenticated access to `dashboard.php` normally returns 302; a 200 means session was forged or auth was bypassed (any path — SQLi, credential stuffing, session forging, etc., not only SQLi). The alarm is rate-limited by `BUZZER_COOLDOWN_S` so back-to-back hits don't pile up audibly; the `[BUZZER]` log line still fires for every detection so detection-rate stats stay accurate.
- **Thread B — `bpf_event_consumer`** *(eBPF-based, replaces the old netstat polling)*: loads `bpf_probe.c` via bcc, which hooks `tracepoint:sock:inet_sock_set_state` and emits ringbuf events for outbound `TCP_SYN_SENT` transitions originating from the **web-app cgroup only** (kernel-side filter via `BPF_HASH(cgroup_filter)` populated at startup with web-app's cgroup id resolved from `/sys/fs/cgroup/system.slice/docker-<id>.scope`). A background polling thread re-resolves web-app's cgroup id every 5 s and updates the BPF filter map if it changed — restarting web-app yields a new cgroup id, so without this the probe would silently match nothing after the first `docker compose restart web-app`. (Polling instead of `docker events` because subscribing to events has missed-event windows during reconnect; polling is miss-proof and the 5 s blind window is acceptable since web-app isn't accepting requests during its own restart.) User-space (`bpf_loader.py`) drains events through a `queue.Queue` (filled by the bcc poll callback thread) and applies the IP whitelist (loopback, link-local, and the precise Docker subnets returned by `docker inspect`; the old `172.16.0.0/12` RFC1918 catchall was removed because it masked LAN-side attackers in the same range, and `build_whitelist()` now fail-closes if `docker inspect` errors so the probe never runs with a broken whitelist). Any non-whitelist destination fires the servo (GPIO 18, pulse 500 → 1250), logged as `[MOTOR]`. Subsequent triggers are suppressed for `MOTOR_COOLDOWN = 5s` via `motor_lock` + `motor_triggered` flag. Three latency markers are emitted per detection: `[LATENCY] kernel→user=Xµs`, `user→pigpio_return=Yµs`, `total kernel→pigpio_return=Zµs`. Labels reflect what's actually measured — the time at which `pigpio.set_servo_pulsewidth()` returns to user space, not the time the SG90 finishes its physical rotation (which adds another ~100–300 ms).

#### Why eBPF here
- Detection latency drops from ~1s (netstat snapshot polling) to sub-millisecond (kernel hook fires at SYN_SENT).
- Short-lived shells that close between netstat snapshots are no longer missed.
- Filtering by cgroup id is a structured kernel-side check (replaces fragile text parsing of netstat output).

#### eBPF prerequisites (host)
- Linux kernel ≥ 5.8 (ringbuf support). Pi OS Bookworm 64-bit ships 6.x — verified compatible.
- BTF-enabled kernel preferred; otherwise bcc compiles against `/lib/modules/$(uname -r)/build` headers (mounted into the container).
- `bcc` is installed inside the container via `apt install bpfcc-tools python3-bpfcc` in `defense/Dockerfile`.

### Hardware lifecycle invariants

- **Connect order**: `hardware_setup()` only initialises direct GPIO. `start_workers()` starts log detection, optional BPF detection, and a separate `motor_setup_worker`. The motor worker tries `PIGPIO_HOST` → Docker gateway → `localhost`, preflights TCP with a 2 s timeout, then calls pigpio (whose own handshake can still block). Failed initial connection rounds retry after 5 s. GPIO and pigpio imports are independent. `gpio_lock` protects direct GPIO separately from `motor_lock`, so LED/buzzer never wait on motor network I/O. A successful connection arriving after shutdown is closed without servo actuation. An established connection lost later still requires restarting defense-system; this is not a general reconnect supervisor. A servo command that fails on such a dead connection is caught and logged (`pigpio 指令失敗`) so Thread B keeps detecting — letting it raise would end reverse-shell detection entirely.
- **LED diagnostics**: `[LED1]` appears once per detection. Separate `[GPIO]` messages report BCM22 (physical pin 15) output/readback or errors; an input level is not proof that the LED physically lit. Regression tests: `python3 -m unittest discover -s tests -p 'test_defense*.py' -v`.
- **Shutdown invariant** (`shutdown_handler`): on `SIGTERM`/`SIGINT` the monitor must (a) turn LEDs off, (b) drive the servo back to `SERVO_UP=500` and sleep 1s for the physical motion, (c) `set_servo_pulsewidth(..., 0)` to stop PWM (otherwise the SG90 buzzes/heats), then `pi.stop()` and `GPIO.cleanup()`. Don't reorder these steps; the 1s delay is load-bearing.
- Pin map (BCM): green LED=22, buzzer=24, servo=18, mode-switch=27 (input, pull-up). GPIO 24 drives an active-buzzer module (HIGH=on, LOW=off); pulse widths: standing=500µs, knocked-down=1250µs. These constants and the log markers (`[LED1]`, `[BUZZER]`, `[MOTOR]`) are the contract the test scripts rely on — changing them breaks `tests/`.

### Host-side mode switch (`host/mode-switch/`)

Independent of the docker stack — a Python systemd daemon that watches
a two-position toggle switch on **GPIO 27** (pull-up enabled, switch
closes to GND) and toggles a **dedicated `HONEYPOT-INPUT` chain** via
a single jump from `INPUT`:

- **student mode** (switch open) — `INPUT` jumps to `HONEYPOT-INPUT`
  which allows only loopback, `ESTABLISHED,RELATED`, ICMP,
  DHCP replies on physical interfaces (UDP 67 -> 68 / 547 -> 546), and
  `pigpiod:8888/tcp` from the defense-system container's exact source
  IP arriving on a Docker bridge interface (`-i docker0` / `-i br-+`),
  then terminates with `DROP`. The intentionally RCE-able web-app
  container cannot reach pigpiod even with code execution because its
  source IP differs.
- **teacher mode** (switch closed to GND) — jump removed from `INPUT`.
  The daemon's active footprint is zero rules; `INPUT`'s own
  policy/rules apply unchanged.

We never flush or re-policy `INPUT` itself, so operators with their
own host firewall rules keep them in both modes. Docker's
`nat/PREROUTING`, `filter/FORWARD`, `DOCKER`, `DOCKER-USER`, and
`DOCKER-ISOLATION-*` chains are also untouched.

Defense-container IP is resolved at apply time via
`docker ps --filter label=com.docker.compose.service=defense-system`.
If the stack isn't up when student mode applies, the pigpiod rule is
omitted (logged as `WARNING`) and the servo will not actuate — bring
docker up, then re-apply or restart the daemon.

Two layers keep the pigpiod rule valid across `defense-system`
rebuilds without manual re-apply: `docker-compose.yml` pins its IP
(`172.28.55.10` on `honeypot-net`), so a recreated container keeps the
same address the existing rule already whitelists; and when the
`--daemon` systemd service is running, a background thread
(`_docker_events_watcher`) subscribes to `docker events` for that
container's start events and calls `set_mode()` again on every one, as
defense-in-depth for cases the IP pin doesn't cover (network
recreated with a different subnet, compose project renamed). A
one-shot `--mode student` invocation has no watcher — only `--daemon`
does — so after a rebuild while the daemon isn't running, still
re-apply by hand.

`mode_switch.py` exposes a CLI (`--mode student|teacher`, `--show`)
for testing without the physical switch. Last applied mode lives at
`/run/honeypot-mode` (tmpfs, cleared on reboot — GPIO is the boot-time
source of truth). IPv6 enforcement is **fail-closed**: if the kernel
has IPv6 enabled (`/proc/net/if_inet6` exists), `ip6tables` errors
abort the apply rather than silently leaving IPv6 SSH reachable.

**iptables rules do not survive a reboot on a stock Pi OS image** — there
is no `iptables-persistent`/`netfilter-persistent` here, so `HONEYPOT-INPUT`
and its `INPUT` jump live in kernel memory only. Without the systemd
daemon installed and enabled, a reboot silently drops back to whatever
`INPUT`'s own policy is (commonly `ACCEPT`, i.e. *no* restriction at all —
not a fail-closed state) until someone reapplies a mode by hand. Installing
with `sudo ./host/mode-switch/install.sh --start` closes this gap: the
unit is `enabled`, so it re-derives the mode from GPIO 27 and reapplies it
on every boot, in addition to the GPIO-change and `docker events` triggers
covered above. Before enabling on a box you only reach remotely, confirm
your remote-access path survives student mode — SSH accepted here (`22/tcp`)
is a *new inbound* connection and gets dropped in student mode; a tunnel
your side originates outbound (e.g. Raspberry Pi Connect's `rpi-connectd`)
is unaffected since return traffic on an outbound-initiated flow matches
`ESTABLISHED,RELATED`, which student mode always allows.

### Web app

`web/src/` is intentionally vulnerable — `admin_login_v2.php` carries the SQLi sink, `network.php` carries the command-injection sink. `setup_db.php` seeds tables and the admin user. Treat the deliberate vulnerabilities as fixtures, not bugs to fix.
