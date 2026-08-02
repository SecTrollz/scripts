#!/system/bin/sh
# =============================================================================
#  SAFE BANKING APP COMPATIBILITY SETUP
#  Moto G 5G (2022) – MediaTek Dimensity 700
#  Uses Magisk modules + DenyList (NO hardware identifier changes)
# =============================================================================
set -e

# ----- Colors -----
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
NC='\033[0m'

echo "${B}=============================================="
echo "  SAFE BANKING APP COMPATIBILITY SETUP"
echo "==============================================${NC}"
echo ""

# ----- Root check -----
if [ "$(id -u)" -ne 0 ]; then
    echo "${R}❌ Root required. Run 'su' first.${NC}"
    exit 1
fi

# ----- Magisk check -----
if ! command -v magisk >/dev/null 2>&1; then
    echo "${R}❌ Magisk not found. Please install Magisk first.${NC}"
    exit 1
fi

MAGISK_VER=$(magisk -v 2>/dev/null | cut -d: -f1)
echo "${G}✅ Magisk version: $MAGISK_VER${NC}"

# ----- Check Zygisk -----
ZYGISK_ENABLED=$(resetprop persist.zygisk.enabled 2>/dev/null)
if [ "$ZYGISK_ENABLED" != "1" ]; then
    echo "${Y}⚠️  Zygisk is not enabled. Enabling now...${NC}"
    resetprop persist.zygisk.enabled 1
    echo "${Y}⚠️  Zygisk enabled. Please reboot and run this script again.${NC}"
    exit 0
fi
echo "${G}✅ Zygisk is enabled${NC}"

# ----- Module status check -----
echo ""
echo "${B}--- Checking required modules ---${NC}"

MODULES_DIR="/data/adb/modules"
PIF_MODULE=""
SHAMIKO_MODULE=""

if [ -d "$MODULES_DIR/playintegrityfix" ] || [ -d "$MODULES_DIR/PlayIntegrityFix" ] || [ -d "$MODULES_DIR/playintegrityfork" ]; then
    PIF_MODULE="found"
    echo "${G}✅ Play Integrity Fix module found${NC}"
else
    echo "${R}❌ Play Integrity Fix module NOT found${NC}"
    echo "   Download: https://github.com/osm0sis/PlayIntegrityFork/releases[reference:0]"
    echo "   Install via Magisk → Modules → Install from storage"
fi

if [ -d "$MODULES_DIR/shamiko" ]; then
    SHAMIKO_MODULE="found"
    echo "${G}✅ Shamiko module found${NC}"
else
    echo "${Y}⚠️  Shamiko NOT found (recommended for aggressive root detection)${NC}"
    echo "   Download: https://github.com/LSPosed/LSPosed.github.io/releases[reference:1]"
fi

echo ""

# ----- Check if Enforce DenyList is enabled -----
DENYLIST_ENFORCED=$(resetprop magisk.denylist.enforce 2>/dev/null)
if [ "$DENYLIST_ENFORCED" = "1" ]; then
    echo "${Y}⚠️  Enforce DenyList is ON.${NC}"
    echo "   If using Shamiko, this should be OFF (Shamiko reads DenyList directly)[reference:2]"
    echo "   If NOT using Shamiko, this should be ON[reference:3]"
    echo ""
fi

# ----- Configure DenyList -----
echo "${B}--- Configuring DenyList ---${NC}"
echo "Add these apps to Magisk DenyList (Settings → Configure DenyList):[reference:4]"
echo ""
echo "  ${G}ESSENTIAL:${NC}"
echo "    • Google Play Services (com.google.android.gms) - ALL checkboxes"
echo "    • Google Play Store (com.android.vending)"
echo "    • Google Services Framework (com.google.android.gsf)"
echo ""
echo "  ${G}BANKING APPS:${NC}"
echo "    • Add EVERY banking/payment app you use"
echo "    • Expand each and check ALL components"
echo ""
echo "  ${Y}IMPORTANT:${NC} Check EVERY single checkbox for each app, not just the main one.[reference:5]"
echo ""

# ----- Instructions for Magisk app hiding -----
echo "${B}--- Hide Magisk App ---${NC}"
echo "Some apps detect the Magisk Manager app itself.[reference:6]"
echo "1. Open Magisk → Settings (gear icon)"
echo "2. Tap 'Hide the Magisk app'[reference:7]"
echo "3. Enter any name (e.g., 'Settings', 'Manager')[reference:8]"
echo ""

# ----- Clear app data instructions -----
echo "${B}--- Clear App Data ---${NC}"
echo "After configuring DenyList and hiding Magisk:[reference:9]"
echo ""
echo "1. Settings → Apps → [each banking app] → Storage → Clear Data"
echo "2. Settings → Apps → Google Play Services → Storage → Clear Data"
echo "3. Settings → Apps → Google Play Store → Storage → Clear Data"
echo "4. Reboot your device"
echo ""

# ----- Verification instructions -----
echo "${B}--- Verify Play Integrity ---${NC}"
echo "Download 'Play Integrity API Checker' from Play Store[reference:10][reference:11]"
echo "Expected result: MEETS_DEVICE_INTEGRITY[reference:12]"
echo ""
echo "If you fail DEVICE integrity:"
echo "  • Update Play Integrity Fix module to latest version"
echo "  • Try Play Integrity Fork: https://github.com/osm0sis/PlayIntegrityFork[reference:13]"
echo ""

# ----- Interactive module installer -----
echo "${B}=============================================="
echo "  OPTIONAL: INSTALL MISSING MODULES"
echo "==============================================${NC}"
echo ""

if [ -z "$PIF_MODULE" ]; then
    echo "${Y}Play Integrity Fix is MISSING. Banking apps will NOT work without it.${NC}"
    echo ""
    printf "Download and install Play Integrity Fork now? (y/N): "
    read -r install_pif
    if [ "$install_pif" = "y" ] || [ "$install_pif" = "Y" ]; then
        echo "${B}Downloading Play Integrity Fork...${NC}"
        # Get latest release URL
        LATEST=$(curl -s https://api.github.com/repos/osm0sis/PlayIntegrityFork/releases/latest | grep -o '"browser_download_url": "[^"]*\.zip"' | head -1 | cut -d'"' -f4)
        if [ -n "$LATEST" ]; then
            curl -L -o /sdcard/Download/PlayIntegrityFork.zip "$LATEST"
            echo "${G}✅ Downloaded to /sdcard/Download/PlayIntegrityFork.zip${NC}"
            echo "Install via Magisk → Modules → Install from storage"
        else
            echo "${R}❌ Failed to get download URL. Please install manually:${NC}"
            echo "   https://github.com/osm0sis/PlayIntegrityFork/releases[reference:14]"
        fi
    fi
fi

if [ -z "$SHAMIKO_MODULE" ]; then
    echo ""
    echo "${Y}Shamiko is recommended for apps with aggressive root detection.${NC}"
    printf "Download and install Shamiko now? (y/N): "
    read -r install_shamiko
    if [ "$install_shamiko" = "y" ] || [ "$install_shamiko" = "Y" ]; then
        echo "${B}Downloading Shamiko...${NC}"
        LATEST=$(curl -s https://api.github.com/repos/LSPosed/LSPosed.github.io/releases | grep -o '"browser_download_url": "[^"]*Shamiko[^"]*\.zip"' | head -1 | cut -d'"' -f4)
        if [ -n "$LATEST" ]; then
            curl -L -o /sdcard/Download/Shamiko.zip "$LATEST"
            echo "${G}✅ Downloaded to /sdcard/Download/Shamiko.zip${NC}"
            echo "Install via Magisk → Modules → Install from storage"
        else
            echo "${R}❌ Failed to get download URL. Please install manually:${NC}"
            echo "   https://github.com/LSPosed/LSPosed.github.io/releases[reference:15]"
        fi
    fi
fi

# ----- Final summary -----
echo ""
echo "${G}=============================================="
echo "  ✅ SETUP COMPLETE"
echo "=============================================="
echo ""
echo "${B}Summary of what to do:${NC}"
echo ""
echo "  1. ${G}Install missing modules${NC} (if not already done)"
echo "  2. ${G}Configure DenyList${NC} with ALL banking apps + Google Play Services[reference:16]"
echo "  3. ${G}Hide Magisk app${NC} (Settings → Hide the Magisk app)[reference:17]"
echo "  4. ${G}Clear data${NC} for banking apps and Google Play Services[reference:18]"
echo "  5. ${G}Reboot${NC} your device"
echo "  6. ${G}Test${NC} with Play Integrity API Checker[reference:19]"
echo ""
echo "${Y}If you still have issues:${NC}"
echo "  • Install Zygisk Assistant: https://github.com/snake-4/Zygisk-Assistant[reference:20]"
echo "  • Install HideMyApplist (LSPosed module): https://github.com/Dr-TSNG/Hide-My-Applist[reference:21]"
echo "  • Check XDA forums for Moto G 5G (2022) specific guidance[reference:22]"
echo ""
echo "${G}🎉 Done! No hardware identifiers were changed. Your device is safe.${NC}"
