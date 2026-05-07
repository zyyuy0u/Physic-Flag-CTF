#!/usr/bin/env bash
# Install the mode-switch daemon onto a Raspberry Pi host.
#
# Usage:
#   sudo ./host/mode-switch/install.sh           # install files only — NOT enabled, NOT started
#   sudo ./host/mode-switch/install.sh --enable  # install + enable (will start on next boot)
#   sudo ./host/mode-switch/install.sh --start   # install + enable + start now (with confirmation)
set -euo pipefail

INSTALL_DIR=/opt/honeypot/mode-switch
SERVICE=mode-switch.service
HERE="$(cd "$(dirname "$0")" && pwd)"

ENABLE=0
START=0
for arg in "$@"; do
    case "$arg" in
        --enable) ENABLE=1 ;;
        --start)  ENABLE=1; START=1 ;;
        -h|--help)
            sed -n '2,7p' "$0"
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

echo "[3/4] installing systemd unit (NOT enabled by default)"
install -m 644 "$HERE/$SERVICE" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload

# Surface upgrade-path surprises: a prior install may have enabled the
# unit; running this installer with no flags should not silently leave
# auto-start active without telling the operator.
if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
    PREVIOUSLY_ENABLED=1
else
    PREVIOUSLY_ENABLED=0
fi

if [[ $ENABLE -eq 1 ]]; then
    cat <<'WARN'

================================================================
  WARNING — about to ENABLE mode-switch.service.
  Once enabled, the daemon will start on EVERY boot. If the GPIO 27
  toggle switch is open or unwired at boot, student mode applies and
  external SSH to this Pi is dropped.

  Make sure the toggle switch is wired up before continuing.
================================================================
WARN
    read -rp 'Type CONTINUE to enable: ' ans
    if [[ "$ans" == "CONTINUE" ]]; then
        systemctl enable "$SERVICE"
    else
        echo "Aborted enable. Files installed but unit is not enabled."
        exit 0
    fi
fi

echo "[4/4] start"
if [[ $START -eq 1 ]]; then
    cat <<'WARN'

================================================================
  WARNING — about to START mode-switch.service NOW.
  If the toggle switch is open/unwired, student mode is applied
  immediately and external SSH to this Pi is dropped within ~50 ms.

  Have local console access ready before continuing.
================================================================
WARN
    read -rp 'Type CONTINUE to start: ' ans
    if [[ "$ans" == "CONTINUE" ]]; then
        systemctl restart "$SERVICE"
        systemctl --no-pager status "$SERVICE" || true
    else
        echo "Aborted start. Service is enabled but not running."
    fi
else
    cat <<EOF

Files installed. Service was NOT enabled or started by this run.

  Enable for next boot:  sudo systemctl enable  $SERVICE
  Start now:             sudo systemctl start   $SERVICE
  Or re-run installer:   sudo $0 --enable | --start
EOF
    if [[ $PREVIOUSLY_ENABLED -eq 1 ]]; then
        cat <<EOF

================================================================
  NOTE — $SERVICE was ALREADY enabled before this install.
  It will still auto-start on the next boot. To disable:
      sudo systemctl disable $SERVICE
================================================================
EOF
    fi
fi
