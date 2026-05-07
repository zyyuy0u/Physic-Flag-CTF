# Mode Switch — Student / Teacher

Host-side daemon that watches a two-position toggle switch on **GPIO 27**
and toggles a dedicated `HONEYPOT-INPUT` iptables chain via a single
jump from `INPUT`:

| Switch position | Mode    | Effect                               | External SSH | Web container :8080 |
|-----------------|---------|--------------------------------------|--------------|---------------------|
| Open (default)  | student | `INPUT` jumps to `HONEYPOT-INPUT`, which terminates with `DROP` | blocked | reachable |
| Closed (to GND) | teacher | jump removed                         | normal       | reachable           |

### Why a dedicated chain?

We never flush or re-policy the `INPUT` chain itself, so if the
operator has their own host firewall rules, the daemon doesn't
clobber them. In teacher mode the daemon's footprint is **zero
active rules** — `INPUT` behaves exactly as if the daemon weren't
installed.

Container traffic is unaffected because Docker's
`PREROUTING` / `FORWARD` / `DOCKER` / `DOCKER-USER` chains and the
`nat` table are never touched.

### How pigpiod stays reachable from the defense container

Student mode whitelists `8888/tcp` only when **all** of the following
match:

- ingress on a Docker bridge interface (`docker0` or `br-+`)
- source IP equals the defense-system container's exact IP, looked
  up via the compose label `com.docker.compose.service=defense-system`

The intentionally RCE-able `web-app` container has a *different*
source IP, so it can no longer reach pigpiod even if compromised.
The same-LAN spoofing risk (someone on `172.16/12` reaching pigpiod)
is also eliminated because we filter by ingress interface, not just
source CIDR.

If the defense container isn't running when student mode is applied,
the rule is omitted (the daemon logs a `WARNING`) and the servo will
not actuate. Bring the docker stack up, then `--mode student` again
or restart the daemon to refresh the rule. **The daemon does not
auto-refresh on container restart yet** (would require a Docker
events watcher); plan for it if you tear the stack down often.

## Wiring

Two-position toggle switch (SPST / SPDT, either works):

```
   GPIO 27 ────┐
               │
              (switch)
               │
       GND  ───┘
```

- Internal pull-up enabled in software, so the switch only needs to
  connect GPIO 27 to GND when "closed".
- Software debounce is 50 ms (`bounce_time=0.05`).
- For SPDT (3 legs), use the centre pin + either side; leave the
  third leg unconnected.
- **Do not connect to 3.3 V or 5 V** — only GPIO + GND.

## Install on the Pi

The default install **does not enable or start** the service. This is
deliberate: starting the daemon with the switch unwired would apply
student mode and immediately drop your SSH session.

```bash
# from the repo root, on the Pi
sudo ./host/mode-switch/install.sh           # install files only

# enable for next boot (prompts for confirmation)
sudo ./host/mode-switch/install.sh --enable

# enable + start now (prompts for confirmation)
sudo ./host/mode-switch/install.sh --start

# or do it manually any time after install
sudo systemctl enable mode-switch.service
sudo systemctl start  mode-switch.service
```

## Manual / testing use (no switch wired)

```bash
# Force a mode without GPIO
sudo /opt/honeypot/mode-switch/mode_switch.py --mode student
sudo /opt/honeypot/mode-switch/mode_switch.py --mode teacher

# Inspect INPUT + HONEYPOT-INPUT chains and last applied mode
sudo /opt/honeypot/mode-switch/mode_switch.py --show
```

`--mode` and `--show` do not require GPIO — useful for exercising
the rules before the physical switch arrives.

The "last applied" state lives at `/run/honeypot-mode`, which is
tmpfs and clears on reboot — by design. After every boot the GPIO
state is the source of truth and the daemon re-derives the mode.

## Recovery if you lock yourself out

If a bad rule somehow blocks SSH, recover via:

1. Flip the switch to teacher (closed) — daemon removes its INPUT
   jump within ~50 ms. SSH is restored as long as the operator's
   own pre-existing INPUT rules permit it.
2. Or attach keyboard + monitor to the Pi and run
   `sudo iptables -D INPUT -j HONEYPOT-INPUT` (repeat until it errors).
3. Or `sudo systemctl stop mode-switch && sudo iptables -F HONEYPOT-INPUT`.

## Service management

```bash
systemctl status  mode-switch
systemctl restart mode-switch
journalctl -u mode-switch -f
```

## Why a host service, not a container?

iptables and GPIO are **host resources**. Putting this in a container
would require `--network host --privileged --cap-add=NET_ADMIN` plus
mounting `/sys/class/gpio` — at which point you have a "container"
that is functionally a host-side script with extra steps. Keeping it
as a plain systemd unit is simpler and easier to reason about for a
security control.
