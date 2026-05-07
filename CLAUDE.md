# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Educational IoT honeypot for Raspberry Pi. A deliberately-vulnerable PHP/MariaDB "smart-home" web app runs alongside a Python defense monitor that drives physical hardware (two LEDs and an SG90 servo) to visualise three attack categories. Do not deploy on a public network.

Default admin credential seeded by `web/src/setup_db.php`: `admin` / `sm@rtH0me2024!`. Web app is exposed on host port **8080**.

## Common commands

```bash
# Host prerequisite (must run on the Pi BEFORE docker compose up — the
# defense container connects to pigpiod over the network at host:8888):
sudo pigpiod -n 0.0.0.0

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

Automated detection tests (run from a host with Python + `requests`, against a running stack):

```bash
# BASE_URL defaults to http://localhost:8080, matching the compose port.
# Override via env: BASE_URL=http://<pi_ip>:8080 python3 tests/...
python3 tests/test_led1_path_probe.py --start 1 --batch 100   # /admin probe → green LED
python3 tests/test_led2_sqli.py                               # SQLi bypass → red LED
```

The tests scrape `docker logs iot-honeypot-defense-system-1` for `[LED1]` / `[LED2]` markers — the container name must match Docker Compose's default (`<project>-<service>-1`), so don't rename the project directory without also updating `CONTAINER` in both test files.

There is no lint, type-check, or unit-test suite. The two scripts in `tests/` are end-to-end detection-rate experiments, not unit tests.

## Architecture

Three containers on a single bridge network `honeypot-net`, defined in `docker-compose.yml`:

1. **db** — MariaDB 10.6, credentials from `.env`. Schema + seed data created on first boot by `web/src/setup_db.php`, invoked from `web/entrypoint.sh` after the DB becomes reachable.
2. **web-app** — PHP 8.2 + Apache. The Dockerfile intentionally installs `netcat-traditional`, `python3`, `perl`, `socat`, `curl` so attackers who land an RCE have tools to spawn a reverse shell — that is the whole point. (`net-tools` was previously installed for the old netstat-based detection; it remains installed but is no longer relied on by the defense system.)
3. **defense-system** — Debian Bookworm + Python 3.11 + bcc (eBPF), `privileged: true`, `pid: host`, mounts `/var/run/docker.sock`, `/sys/kernel/debug`, `/sys/fs/bpf`, `/sys/fs/cgroup`, `/lib/modules`, `/usr/src`. It has no GPIO of its own; instead it talks to **pigpiod on the host** over TCP (`PIGPIO_HOST=host.docker.internal`, port 8888) for servo PWM, and uses `RPi.GPIO` via the privileged bind for the two LEDs. The host gateway is wired in via `extra_hosts: host.docker.internal:host-gateway`.

### The single source of truth for detection logic: `defense/monitor.py` + `defense/bpf_loader.py` + `defense/bpf_probe.c`

Everything the honeypot "does" lives in two threads launched from `main()`:

- **Thread A — `docker_log_monitor`**: streams `docker logs -f web-app` and matches each line against two regexes:
  - `ADMIN_PATTERN` (`GET /admin[\s/?]`) → green LED on (GPIO 22), logged as `[LED1]`.
  - `DASHBOARD_PATTERN` (`"GET /dashboard.php..." 200`) → red LED on (GPIO 24), logged as `[LED2]`. The detection assumes unauthenticated access to `dashboard.php` normally returns 302; a 200 means session was forged or auth was bypassed.
- **Thread B — `bpf_event_consumer`** *(eBPF-based, replaces the old netstat polling)*: loads `bpf_probe.c` via bcc, which hooks `tracepoint:sock:inet_sock_set_state` and emits ringbuf events for outbound `TCP_SYN_SENT` transitions originating from the **web-app cgroup only** (kernel-side filter via `BPF_HASH(cgroup_filter)` populated at startup with web-app's cgroup id resolved from `/sys/fs/cgroup/system.slice/docker-<id>.scope`). User-space (`bpf_loader.py`) drains events through a `queue.Queue` (filled by the bcc poll callback thread) and applies the IP whitelist (loopback, link-local, Docker bridge subnet from `docker inspect`, and `172.16.0.0/12` catchall). Any non-whitelist destination fires the servo (GPIO 18, pulse 500 → 1500), logged as `[MOTOR]`. Subsequent triggers are suppressed for `MOTOR_COOLDOWN = 5s` via `motor_lock` + `motor_triggered` flag. Three latency markers are emitted per detection: `[LATENCY] kernel→user=Xµs`, `user→pigpio_return=Yµs`, `total kernel→pigpio_return=Zµs`. Labels reflect what's actually measured — the time at which `pigpio.set_servo_pulsewidth()` returns to user space, not the time the SG90 finishes its physical rotation (which adds another ~100–300 ms).

#### Why eBPF here
- Detection latency drops from ~1s (netstat snapshot polling) to sub-millisecond (kernel hook fires at SYN_SENT).
- Short-lived shells that close between netstat snapshots are no longer missed.
- Filtering by cgroup id is a structured kernel-side check (replaces fragile text parsing of netstat output).

#### eBPF prerequisites (host)
- Linux kernel ≥ 5.8 (ringbuf support). Pi OS Bookworm 64-bit ships 6.x — verified compatible.
- BTF-enabled kernel preferred; otherwise bcc compiles against `/lib/modules/$(uname -r)/build` headers (mounted into the container).
- `bcc` is installed inside the container via `apt install bpfcc-tools python3-bpfcc` in `defense/Dockerfile`.

### Hardware lifecycle invariants

- **Connect order**: `hardware_setup()` initialises `RPi.GPIO` first, then calls `connect_pigpio()` which tries `PIGPIO_HOST` env var → Docker default-route gateway → `localhost`. If pigpiod is unreachable, the LED threads still run but the motor is dead — look for `[PIGPIO] 所有連線嘗試均失敗` in the logs.
- **Shutdown invariant** (`shutdown_handler`): on `SIGTERM`/`SIGINT` the monitor must (a) turn LEDs off, (b) drive the servo back to `SERVO_UP=500` and sleep 1s for the physical motion, (c) `set_servo_pulsewidth(..., 0)` to stop PWM (otherwise the SG90 buzzes/heats), then `pi.stop()` and `GPIO.cleanup()`. Don't reorder these steps; the 1s delay is load-bearing.
- Pin map (BCM): green=22, red=24, servo=18, mode-switch=27 (input, pull-up). Pulse widths: standing=500µs, knocked-down=1500µs. These constants and the LED/motor log markers (`[LED1]`, `[LED2]`, `[MOTOR]`) are the contract the test scripts rely on — changing them breaks `tests/`.

### Host-side mode switch (`host/mode-switch/`)

Independent of the docker stack — a Python systemd daemon that watches
a two-position toggle switch on **GPIO 27** (pull-up enabled, switch
closes to GND) and toggles a **dedicated `HONEYPOT-INPUT` chain** via
a single jump from `INPUT`:

- **student mode** (switch open) — `INPUT` jumps to `HONEYPOT-INPUT`
  which allows only loopback, `ESTABLISHED,RELATED`, ICMP, and
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
docker up, then re-apply or restart the daemon. The daemon does NOT
auto-refresh on container restart; plan a Docker events watcher if
the stack churns often.

`mode_switch.py` exposes a CLI (`--mode student|teacher`, `--show`)
for testing without the physical switch. Last applied mode lives at
`/run/honeypot-mode` (tmpfs, cleared on reboot — GPIO is the boot-time
source of truth). IPv6 enforcement is **fail-closed**: if the kernel
has IPv6 enabled (`/proc/net/if_inet6` exists), `ip6tables` errors
abort the apply rather than silently leaving IPv6 SSH reachable.

### Web app

`web/src/` is intentionally vulnerable — `admin_login_v2.php` carries the SQLi sink, `network.php` carries the command-injection sink. `setup_db.php` seeds tables and the admin user. Treat the deliberate vulnerabilities as fixtures, not bugs to fix.
