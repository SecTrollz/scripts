#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${YELLOW}=== Fastboot → ADB Bootloop Fix ===${NC}"

# Use termux-fastboot if present, otherwise fallback to fastboot
FB="termux-fastboot"
if ! command -v $FB >/dev/null; then
    echo -e "${YELLOW}termux-fastboot not found, using fastboot${NC}"
    FB="fastboot"
    command -v $FB >/dev/null || { echo -e "${RED}No fastboot binary${NC}"; exit 1; }
fi

# Check termux-adb
command -v termux-adb >/dev/null || { echo -e "${RED}Install termux-adb${NC}"; exit 1; }

# Fastboot device?
$FB devices >/dev/null 2>&1 || { echo -e "${RED}No fastboot device${NC}"; exit 1; }
echo -e "${GREEN}Fastboot device found.${NC}"

# Reboot to system
echo -e "${YELLOW}Rebooting to system...${NC}"
$FB reboot
sleep 5

# Catch ADB during boot (30s)
echo -e "${YELLOW}Waiting for ADB (30s)...${NC}"
for i in {1..30}; do
    if [ "$(termux-adb get-state 2>/dev/null)" = "device" ]; then
        echo -e "${GREEN}ADB connected – re‑enabling packages...${NC}"
        termux-adb shell pm list packages -d 2>/dev/null | cut -d':' -f2 | while read pkg; do
            [ -n "$pkg" ] && termux-adb shell pm enable "$pkg" 2>/dev/null
        done
        termux-adb reboot
        echo -e "${GREEN}Done! Device should boot normally. 🎯${NC}"
        exit 0
    fi
    sleep 1
done

# Fallback
echo -e "${RED}ADB never appeared.${NC}"
echo -e "${YELLOW}Try Safe Mode (hold Vol Down during boot) then rerun.${NC}"
echo -e "${YELLOW}Or factory reset: $FB -w && $FB reboot${NC}"
exit 1
