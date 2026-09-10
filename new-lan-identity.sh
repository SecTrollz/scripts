#!/usr/bin/env bash
#
# new-identity.sh — regenerate the network-facing identity of this host
# Works on: Termux (rooted Android), Debian, Ubuntu
#
# Usage: ./new-identity.sh [interface]
#   interface defaults to the first non-loopback interface found.

set -euo pipefail

# --- environment detection -------------------------------------------------
IS_TERMUX=0
if [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d /data/data/com.termux ]]; then
    IS_TERMUX=1
fi

as_root() {
    if [[ $IS_TERMUX -eq 1 ]]; then
        su -c "$*"
    elif [[ $EUID -eq 0 ]]; then
        bash -c "$*"
    else
        sudo bash -c "$*"
    fi
}

if [[ $IS_TERMUX -eq 0 && $EUID -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    echo "Need root privileges (sudo not found)." >&2
    exit 1
fi

# --- interface ---------------------------------------------------------
IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
    IFACE=$(as_root "ip -o link show" | awk -F': ' '$2 != "lo" {print $2; exit}')
fi

if [[ -z "$IFACE" ]]; then
    echo "Could not determine a network interface. Pass one explicitly." >&2
    exit 1
fi

echo "Target interface: $IFACE"

# --- 1. Randomize MAC address -----------------------------------------
random_mac() {
    # Locally administered, unicast (second hex digit: 2/6/A/E)
    printf '02:%02x:%02x:%02x:%02x:%02x\n' \
        $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) \
        $((RANDOM % 256)) $((RANDOM % 256))
}

echo "[*] Randomizing MAC address on $IFACE..."
if command -v macchanger >/dev/null 2>&1 && [[ $IS_TERMUX -eq 0 ]]; then
    as_root "ip link set dev $IFACE down"
    as_root "macchanger -r $IFACE"
    as_root "ip link set dev $IFACE up"
else
    NEW_MAC=$(random_mac)
    as_root "ip link set dev $IFACE down"
    as_root "ip link set dev $IFACE address $NEW_MAC"
    as_root "ip link set dev $IFACE up"
fi

# --- 2. Randomize hostname ----------------------------------------------
NEW_HOSTNAME="host-$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
echo "[*] Setting hostname to $NEW_HOSTNAME..."

if [[ $IS_TERMUX -eq 1 ]]; then
    as_root "setprop net.hostname $NEW_HOSTNAME" 2>/dev/null || true
    as_root "settings put global device_name $NEW_HOSTNAME" 2>/dev/null || true
else
    if command -v hostnamectl >/dev/null 2>&1; then
        as_root "hostnamectl set-hostname $NEW_HOSTNAME"
    else
        as_root "hostname $NEW_HOSTNAME"
        as_root "echo $NEW_HOSTNAME > /etc/hostname"
    fi
    as_root "sed -i 's/127\\.0\\.1\\.1.*/127.0.1.1\\t$NEW_HOSTNAME/' /etc/hosts" 2>/dev/null || true
fi

# --- 3. Regenerate machine-id (Debian/Ubuntu) --------------------------
if [[ $IS_TERMUX -eq 0 ]]; then
    echo "[*] Regenerating machine-id..."
    as_root "rm -f /etc/machine-id"
    as_root "systemd-machine-id-setup" >/dev/null 2>&1 || as_root "dbus-uuidgen --ensure=/etc/machine-id"
    as_root "rm -f /var/lib/dbus/machine-id"
    as_root "ln -sf /etc/machine-id /var/lib/dbus/machine-id" 2>/dev/null || true
fi

# --- 4. DHCP client identifier + lease renewal --------------------------
echo "[*] Renewing DHCP lease..."
if [[ $IS_TERMUX -eq 1 ]]; then
    as_root "svc wifi disable" 2>/dev/null || true
    sleep 2
    as_root "svc wifi enable" 2>/dev/null || true
else
    DHCLIENT_CONF="/etc/dhcp/dhclient.conf"
    NEW_CLIENTID="$(tr -dc 'a-f0-9' </dev/urandom | head -c 12)"
    if [[ -f "$DHCLIENT_CONF" ]]; then
        as_root "sed -i '/^send dhcp-client-identifier/d' $DHCLIENT_CONF"
        as_root "sh -c \"echo 'send dhcp-client-identifier $NEW_CLIENTID;' >> $DHCLIENT_CONF\""
    fi
    if command -v dhclient >/dev/null 2>&1; then
        as_root "dhclient -r $IFACE" 2>/dev/null || true
        as_root "dhclient $IFACE"
    elif command -v nmcli >/dev/null 2>&1; then
        as_root "nmcli device disconnect $IFACE" || true
        as_root "nmcli device connect $IFACE" || true
    fi
fi

echo
echo "Done."
echo "  Interface:  $IFACE"
echo "  Hostname:   $NEW_HOSTNAME"
