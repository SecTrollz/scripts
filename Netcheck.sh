#!/data/data/com.termux/files/usr/bin/bash
# netcheck.sh — pulls whatever historical wifi/network evidence still exists
# for the 7/31 18:00-19:00 window, all into one file, one run.

OUT="$HOME/netcheck_$(date +%Y%m%d_%H%M%S).log"

section() {
    echo "" >> "$OUT"
    echo "===================================================================" >> "$OUT"
    echo "== $1" >> "$OUT"
    echo "===================================================================" >> "$OUT"
}

run() {
    echo "" >> "$OUT"
    echo "--- $1 ---" >> "$OUT"
    eval "$2" >> "$OUT" 2>&1
}

echo "Netcheck started: $(date)" > "$OUT"

section "TARGET IPs — CONFIRM OWNERSHIP"
run "whois 174.111.192.115"  "whois 174.111.192.115"
run "whois 76.36.174.224"    "whois 76.36.174.224"
run "current public IP"      "curl -s https://ifconfig.me/"

section "WIFI CONFIG / KNOWN NETWORKS"
run "wifi config dir listing"  "su -c 'ls -la /data/misc/wifi/'"
run "WifiConfigStore.xml"      "su -c 'cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null'"
run "wpa_supplicant.conf"      "su -c 'cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null'"

section "DHCP / LEASE RECORDS"
run "find dhcp/lease files"    "su -c 'find /data/misc -iname \"*dhcp*\" -o -iname \"*lease*\" 2>/dev/null'"

section "BATTERYSTATS HISTORY — network/wifi transitions around 7/31"
run "batterystats grep 7/31 + wifi"  "su -c 'dumpsys batterystats --history 2>/dev/null' | grep -i -E '2026-07-31|wifi|CONNECTED|DISCONNECTED'"

section "CURRENT WIFI STATE (live, for reference)"
run "dumpsys wifi summary"     "su -c 'dumpsys wifi' 2>/dev/null | head -100"
run "current wlan0 addr"       "su -c 'ip addr show wlan0'"

section "LOGCAT — WHATEVER HISTORY REMAINS (likely rotated past 7/31, checked anyway)"
run "logcat main buffer, wifi-filtered"  "su -c 'logcat -d -b all -v time' | grep -i -E 'wlan0|CONNECTED|DISCONNECTED|DhcpClient' | tail -200"

echo "" >> "$OUT"
echo "Netcheck finished: $(date)" >> "$OUT"
echo "Wrote: $OUT"
wc -l "$OUT"
