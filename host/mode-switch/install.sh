#!/usr/bin/env bash
# Install the mode-switch daemon onto a Raspberry Pi host.
# Usage:
#   sudo ./host/mode-switch/install.sh           # install files only, do NOT start
#   sudo ./host/mode-switch/install.sh --start   # install AND start (with confirmation)
set -euo pipefail

INSTALL_DIR=/opt/honeypot/mode-switch
SERVICE=mode-switch.service
HERE="$(cd "$(dirname "$0")" && pwd)"

START_SERVICE=0
for arg in "$@"; do
    case "$arg" in
        --start) START_SERVICE=1 ;;
        -h|--help)
            sed -n '2,5p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0" >&2
    exit 1
fi

echo "[1/4] installing apt packages"
apt-get update
apt-get install -y python3-gpiozero python3-rpi.gpio iptables

echo "[2/4] copying files to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
install -m 755 "$HERE/mode_switch.py" "$INSTALL_DIR/mode_switch.py"
install -m 644 "$HERE/README.md"      "$INSTALL_DIR/README.md"

echo "[3/4] installing systemd unit (enabled but not started)"
install -m 644 "$HERE/$SERVICE" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable "$SERVICE"

echo "[4/4] start"
if [[ $START_SERVICE -eq 1 ]]; then
    cat <<'WARN'

================================================================
  WARNING — about to start mode-switch.service.
  If the GPIO 27 toggle switch is OPEN or NOT WIRED, the daemon
  will apply STUDENT mode immediately and DROP all external SSH
  to this Pi.

  Make sure you have local console (keyboard+HDMI) access OR a
  way to flip the switch closed before continuing.
================================================================
WARN
    read -rp 'Type CONTINUE to start the service now: ' ans
    if [[ "$ans" == "CONTINUE" ]]; then
        systemctl restart "$SERVICE"
        systemctl --no-pager status "$SERVICE" || true
    else
        echo "Aborted. Run 'sudo systemctl start $SERVICE' when ready."
    fi
else
    cat <<EOF

Files installed and unit enabled, but the service was NOT started.

To start it (this will apply student mode immediately if the switch
is open/unwired):

  sudo systemctl start $SERVICE

Or re-run with --start to be prompted now.
EOF
fi
