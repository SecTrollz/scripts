#!/data/data/com.termux/files/usr/bin/bash
# sysreport.sh — single-file system/kernel/USB diagnostic dump
# Writes everything to one log in Termux home storage (not /sdcard).

OUT="$HOME/sysreport_$(date +%Y%m%d_%H%M%S).log"

section() {
    echo "" >> "$OUT"
    echo "===================================================================" >> "$OUT"
    echo "== $1" >> "$OUT"
    echo "===================================================================" >> "$OUT"
}

run() {
    # $1 = label, rest = command to eval
    echo "" >> "$OUT"
    echo "--- $1 ---" >> "$OUT"
    eval "$2" >> "$OUT" 2>&1
}

echo "System report started: $(date)" > "$OUT"
echo "Device: $(getprop ro.product.model 2>/dev/null)" >> "$OUT"

# ---------------------------------------------------------------
section "BOOT / VERIFIED BOOT STATE"
run "boot reason"            "getprop ro.boot.bootreason; getprop persist.sys.boot.reason"
run "verified boot state"    "getprop ro.boot.verifiedbootstate"
run "veritymode"             "getprop ro.boot.veritymode"
run "boot flow / warranty"   "getprop ro.boot.flash.locked; getprop ro.boot.warranty_bit; getprop ro.boot.vbmeta.device_state"
run "build fingerprint"      "getprop ro.build.fingerprint"
run "security patch level"   "getprop ro.build.version.security_patch"

# ---------------------------------------------------------------
section "KERNEL / MODULES / TAINT"
run "uname"                  "uname -a"
run "kernel taint flags"     "cat /proc/sys/kernel/tainted 2>/dev/null"
run "lsmod"                  "su -c 'lsmod' 2>/dev/null || lsmod 2>/dev/null"
run "proc modules"           "su -c 'cat /proc/modules' 2>/dev/null"
run "module taint per-module" "su -c 'for m in /sys/module/*/taint; do echo \"\$m: \$(cat \$m 2>/dev/null)\"; done' 2>/dev/null"
run "dmesg tail (500)"       "su -c 'dmesg | tail -500' 2>/dev/null"

# ---------------------------------------------------------------
section "PSTORE / LAST PANIC"
run "pstore listing"         "su -c 'ls -la /sys/fs/pstore/' 2>/dev/null"
run "console-ramoops-0"      "su -c 'cat /sys/fs/pstore/console-ramoops-0' 2>/dev/null"

# ---------------------------------------------------------------
section "USB / TYPEC / GADGET STATE"
run "udc state"              "su -c 'cat /sys/class/udc/*/state' 2>/dev/null"
run "usb debugfs listing"    "su -c 'ls /sys/kernel/debug/usb/' 2>/dev/null"
run "typec power role"       "su -c 'cat /sys/class/typec/*/power_role' 2>/dev/null"
run "typec data role"        "su -c 'cat /sys/class/typec/*/data_role' 2>/dev/null"
run "power_supply usb"       "su -c 'cat /sys/class/power_supply/usb/uevent' 2>/dev/null"
run "usb device tree"        "su -c 'lsusb' 2>/dev/null; su -c 'cat /sys/kernel/debug/usb/devices' 2>/dev/null"

# ---------------------------------------------------------------
section "STORAGE / MOUNTS / FS HEALTH"
run "mount table"            "mount"
run "df -h"                  "df -h"
run "dmesg storage errors"   "su -c 'dmesg | grep -iE \"mmc|sdcard|EXT4-fs error|I/O error|fuse\"' 2>/dev/null"
run "write/read test (home)" "echo test_\$(date +%s) > \$HOME/.wtest && cat \$HOME/.wtest && rm \$HOME/.wtest"

# ---------------------------------------------------------------
section "NETWORK / SOCKETS"
run "ip addr"                "su -c 'ip addr' 2>/dev/null || ip addr 2>/dev/null"
run "active sockets"         "su -c 'ss -tunap' 2>/dev/null"
run "dns / resolv"           "getprop net.dns1; getprop net.dns2"
run "iptables (if avail)"    "su -c 'iptables -L -n -v' 2>/dev/null"

# ---------------------------------------------------------------
section "PROCESSES"
run "ps full"                "su -c 'ps -A -o pid,ppid,user,comm' 2>/dev/null || ps -A"
run "top snapshot"           "su -c 'top -b -n 1 | head -40' 2>/dev/null"

# ---------------------------------------------------------------
section "PACKAGE / APP INTEGRITY (high level)"
run "installed packages count" "pm list packages 2>/dev/null | wc -l"
run "packages with SYSTEM/root perms (sample)" "su -c 'dumpsys package | grep -i \"granted=true\" | head -50' 2>/dev/null"

echo "" >> "$OUT"
echo "System report finished: $(date)" >> "$OUT"
echo "Wrote: $OUT"
wc -l "$OUT"
