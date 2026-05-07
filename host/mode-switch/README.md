# Mode Switch — Student / Teacher

Host-side daemon that watches a two-position toggle switch on **GPIO 27**
and rebuilds the Pi's `iptables` INPUT chain accordingly:

| Switch position | Mode    | INPUT policy | External SSH | Web container :8080 |
|-----------------|---------|--------------|--------------|---------------------|
| Open (default)  | student | `DROP`       | blocked      | reachable           |
| Closed (to GND) | teacher | `ACCEPT`     | normal       | reachable           |

Container traffic is unaffected because Docker's `PREROUTING` / `FORWARD`
/ `DOCKER-USER` chains are never touched — we only own the host's INPUT
chain. The defense container can still reach `pigpiod` on the host
because student mode whitelists `8888/tcp` *arriving on a Docker bridge
interface* (`docker0` and `br-+` wildcard). The rule matches by
ingress interface rather than source CIDR, so same-LAN hosts on
`172.16/12` cannot reach pigpiod just by spoofing a docker-looking IP.

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

```bash
# from the repo root, on the Pi
sudo ./host/mode-switch/install.sh           # install + enable, do NOT start
sudo systemctl start mode-switch.service     # start when you're ready

# or, install + start in one go (prompts for confirmation):
sudo ./host/mode-switch/install.sh --start
```

The default install does **not** auto-start the service. This is
deliberate: if the toggle switch is unwired, starting the daemon
would immediately apply student mode and drop your SSH session. Wire
up the switch (or have local console access) before starting.

## Manual / testing use (no switch wired)

```bash
# Force a mode without GPIO
sudo /opt/honeypot/mode-switch/mode_switch.py --mode student
sudo /opt/honeypot/mode-switch/mode_switch.py --mode teacher

# Inspect current INPUT chain + last applied mode
sudo /opt/honeypot/mode-switch/mode_switch.py --show
```

`--mode` and `--show` do not need GPIO and run on any host. Useful for
exercising the rules before the physical switch arrives.

## Recovery if you lock yourself out

If a bad rule somehow locks SSH, recover via:

1. Flip the switch to teacher (closed) — daemon flushes INPUT and sets
   policy ACCEPT within 50 ms.
2. Or attach keyboard + monitor to the Pi and run
   `sudo iptables -F INPUT && sudo iptables -P INPUT ACCEPT`.
3. Or unplug the Pi and boot — student mode is reapplied on boot, so
   the rules will be the documented set above (not whatever broken
   state was in memory).

## Service management

```bash
systemctl status  mode-switch
systemctl restart mode-switch
journalctl -u mode-switch -f
```

## Why a host service, not a container?

iptables and GPIO are **host resources**. Putting this in a container
would require `--network host --privileged --cap-add=NET_ADMIN` plus
mounting `/sys/class/gpio` — at which point you have a "container" that
is functionally a host-side script with extra steps. Keeping it as a
plain systemd unit is simpler and easier to reason about for a security
control.
