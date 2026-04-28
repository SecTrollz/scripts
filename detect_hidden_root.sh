#!/bin/bash

# Title: Detect Hidden Root Access (ADB)
# Usage: adb push detect_hidden_root.sh /data/local/tmp && adb shell chmod +x /data/local/tmp/detect_hidden_root.sh && adb shell /data/local/tmp/detect_hidden_root.sh

echo "===== [Hidden Root Detection Script] ====="

# --- Part 1: Check for 'su' Binaries ---
echo -e "\n[1] Checking for 'su' binaries..."
SU_PATHS=(
  "/system/bin/su"
  "/system/xbin/su"
  "/sbin/su"
  "/vendor/bin/su"
  "/data/local/su"
  "/data/local/bin/su"
  "/data/local/xbin/su"
  "/system/app/Superuser.apk"
  "/system/priv-app/Superuser.apk"
)

for path in "${SU_PATHS[@]}"; do
  if [ -e "$path" ]; then
    echo "⚠️  Found 'su' binary or Superuser APK: $path"
    ls -l "$path"
  fi
done

# --- Part 2: Inspect Zygote Process ---
echo -e "\n[2] Inspecting Zygote process..."
ZYGOTE_PID=$(pidof zygote)
if [ -z "$ZYGOTE_PID" ]; then
  echo "❌ Zygote process not found!"
else
  echo "ℹ️  Zygote PID: $ZYGOTE_PID"

  # Check Zygote's loaded libraries
  echo -e "\n--- Zygote Loaded Libraries ---"
  cat /proc/$ZYGOTE_PID/maps | grep -E "\.so|/data/|/vendor/" | head -20

  # Check Zygote's environment
  echo -e "\n--- Zygote Environment ---"
  cat /proc/$ZYGOTE_PID/environ | tr '\0' '\n' | grep -iE "root|su|debug|ld_preload"

  # Check Zygote's command line
  echo -e "\n--- Zygote Command Line ---"
  cat /proc/$ZYGOTE_PID/cmdline | tr '\0' ' '

  # Check if Zygote is running as root
  echo -e "\n--- Zygote User ---"
  ps -o USER,UID -p $ZYGOTE_PID
fi

# --- Part 3: Audit Suspicious Services ---
echo -e "\n[3] Auditing suspicious services..."
SUSPICIOUS_SERVICES=(
  "adb"
  "oem_lock"
  "remote_provisioning"
  "intrusion_detection"
  "vendor.google.radio_ext"
  "vendor.samsung_slsi"
  "testharness"
  "persistent_data_block"
)

for service in "${SUSPICIOUS_SERVICES[@]}"; do
  if service list | grep -q "$service"; then
    echo "⚠️  Suspicious service found: $service"
    dumpsys "$service" 2>/dev/null | head -5
  fi
done

# --- Bonus: Check for Writable System ---
echo -e "\n[Bonus] Checking if /system is writable..."
mount | grep -E "system|vendor" | grep -i "rw"

# --- Bonus: Check ADB Root Status ---
echo -e "\n[Bonus] Checking ADB root status..."
if adb root 2>&1 | grep -q "adbd cannot run as root"; then
  echo "✅ ADB root is disabled."
else
  echo "⚠️  ADB root is ENABLED!"
fi

echo -e "\n===== [Detection Complete] ====="
