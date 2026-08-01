#!/usr/bin/env python3
"""
TEGU RECLAMATION SCRIPT v2
Device: Google Pixel 9a
Owner: Evan Saurage
Date: June 2026

All-in-one device hardening with full verification,
validation, network transparency, and audit logging.

Requirements:
    Python 3.7+
    adb in your system PATH
    (No pip installs needed)

Run from PC with device connected via USB or Wireless ADB.
"""

import subprocess
import datetime
import json
import sys
import time
import os
import shutil

# -----------------------------------------------
# CONFIGURATION
# -----------------------------------------------

LOG_FILE = (
    f"tegu_reclamation_"
    f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
BASELINE_FILE = "tegu_baseline.json"

PACKAGES_TO_DISABLE = [
    # Enterprise MDM Layer — CloudDPC
    "com.google.android.apps.work.clouddpc",
    # SIM/eSIM/Bootloader Control — OOBConfig
    "com.google.android.apps.work.oobconfig",
    # OMA-DM Carrier Remote Management
    "com.google.omadm.trigger",
    # CBRS Persistent Location Monitor
    "com.google.android.apps.cbrsnetworkmonitor",
    # Device Lock Controller
    "com.google.android.devicelockcontroller",
    # System-Wide Dump Capability
    "com.google.android.turboadapter",
    # Retail Demo Infrastructure
    "com.google.android.retaildemo",
    "com.google.android.apps.retaildemo.preload",
    # Repair Mode
    "com.google.android.repairmode",
    # Federated Compute
    "com.google.android.federatedcompute",
    # Ad Services
    "com.google.android.adservices.api",
    # On Device Personalization
    "com.google.android.ondevicepersonalization",
    # Location History
    "com.google.android.gms.location.history",
]

APPOPS_TO_DENY = [
    # SCONE — Network Intelligence Engine
    ("com.google.android.apps.scone", "RUN_IN_BACKGROUND"),
    ("com.google.android.apps.scone", "RUN_ANY_IN_BACKGROUND"),
    ("com.google.android.apps.scone", "MONITOR_LOCATION"),
    ("com.google.android.apps.scone", "MONITOR_HIGH_POWER_LOCATION"),
    # Google Play Services — Location
    ("com.google.android.gms", "MONITOR_HIGH_POWER_LOCATION"),
    ("com.google.android.gms", "MONITOR_LOCATION"),
    # CloudDPC
    ("com.google.android.apps.work.clouddpc", "MONITOR_LOCATION"),
    ("com.google.android.apps.work.clouddpc", "READ_PHONE_STATE"),
    ("com.google.android.apps.work.clouddpc", "CAMERA"),
    # OOBConfig
    ("com.google.android.apps.work.oobconfig", "READ_PHONE_STATE"),
    ("com.google.android.apps.work.oobconfig", "MONITOR_LOCATION"),
    # TurboAdapter
    ("com.google.android.turboadapter", "READ_DEVICE_IDENTIFIERS"),
    # Partner Setup
    ("com.google.android.partnersetup", "MONITOR_LOCATION"),
    ("com.google.android.partnersetup", "READ_PHONE_STATE"),
    # Carrier Setup
    ("com.google.android.carriersetup", "READ_PHONE_STATE"),
    ("com.google.android.carriersetup", "MONITOR_LOCATION"),
]

DNS_BLOCK_DOMAINS = [
    # Firebase Cloud Messaging
    "mtalk.google.com",
    "fcm.googleapis.com",
    "fcm-xmpp.googleapis.com",
    "android.googleapis.com",
    # OMA-DM Verizon Endpoints
    "dm.vzwdmserver.com",
    "ommadm.verizonwireless.com",
    "omadm.verizonwireless.com",
    # Google Telemetry
    "app-measurement.com",
    "firebase.googleapis.com",
    "firebaselogging.googleapis.com",
    "firebaseinstallations.googleapis.com",
    "crashlyticsreports-pa.googleapis.com",
    # Remote Key Provisioning
    "remoteprovisioning.googleapis.com",
    # Device Lock
    "devicelock.googleapis.com",
]


# -----------------------------------------------
# LOGGING
# -----------------------------------------------

def log(message, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def section(title):
    divider = "=" * 60
    log(divider)
    log(f"  {title}")
    log(divider)


# -----------------------------------------------
# SAFE INT — HANDLES WHITESPACE AND EMPTY STRINGS
# -----------------------------------------------

def safe_int(value, default=0):
    """
    Safely convert a string to int.
    Handles whitespace, empty strings, and unexpected content.
    wc -l on Android returns strings like ' 172' with leading spaces.
    """
    if not value:
        return default
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


# -----------------------------------------------
# ADB WRAPPER
# FIX: All shell commands wrapped in quotes so pipes
# run on Android shell, not local PC shell.
# FIX: Always capture output, handle None safely.
# FIX: adb binary checked before first use.
# -----------------------------------------------

def adb(command):
    """
    Execute a command on the Android device via adb shell.

    CRITICAL FIX: Command is wrapped in double quotes so that
    any pipes, greps, or wc commands run on the Android device,
    not on the local PC shell.

    Every command printed before execution.
    Every response printed after.
    Nothing hidden.
    """
    # Escape any double quotes in the command itself
    escaped = command.replace('"', '\\"')
    full_command = f'adb shell "{escaped}"'
    log(f"EXECUTING: {full_command}", "CMD")

    try:
        result = subprocess.run(
            full_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        # FIX: Safe access — stdout/stderr always exist
        # when capture_output=True, but strip safely
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        if stdout:
            log(f"RESPONSE: {stdout}", "OUT")
        if stderr:
            log(f"STDERR: {stderr}", "ERR")

        return stdout, stderr, result.returncode

    except subprocess.TimeoutExpired:
        log(f"TIMEOUT: {full_command}", "ERR")
        return "", "TIMEOUT", 1
    except Exception as e:
        log(f"EXCEPTION: {str(e)}", "ERR")
        return "", str(e), 1


def adb_raw(command):
    """
    Execute an adb-level command (not adb shell).
    Used for: adb devices, adb start-server, etc.
    """
    full_command = f"adb {command}"
    log(f"EXECUTING: {full_command}", "CMD")
    try:
        result = subprocess.run(
            full_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if stdout:
            log(f"RESPONSE: {stdout}", "OUT")
        if stderr:
            log(f"STDERR: {stderr}", "ERR")
        return stdout, stderr, result.returncode
    except Exception as e:
        log(f"EXCEPTION: {str(e)}", "ERR")
        return "", str(e), 1


# -----------------------------------------------
# PREREQUISITE CHECK
# FIX: Verify adb exists before touching anything
# -----------------------------------------------

def check_prerequisites():
    section("PREREQUISITE CHECK")

    # Check adb binary exists
    adb_path = shutil.which("adb")
    if not adb_path:
        log("adb NOT FOUND in PATH.", "ERR")
        log("Install Android Platform Tools:", "ERR")
        log("  https://developer.android.com/tools/releases/platform-tools",
            "ERR")
        log("  Then add the folder to your PATH.", "ERR")
        sys.exit(1)

    log(f"adb found at: {adb_path}", "OK")

    # Check Python version
    major, minor = sys.version_info[:2]
    log(f"Python version: {major}.{minor}")
    if major < 3 or (major == 3 and minor < 7):
        log("Python 3.7+ required.", "ERR")
        sys.exit(1)
    log("Python version OK", "OK")

    # Start adb server
    log("Starting adb server...")
    adb_raw("start-server")
    time.sleep(1)


# -----------------------------------------------
# PHASE 0 — DEVICE VERIFICATION
# FIX: Stricter device detection — look for tab+device
# not just the word "device" in the header
# -----------------------------------------------

def verify_device():
    section("PHASE 0 — DEVICE VERIFICATION")

    log("Checking for connected devices...")
    stdout, stderr, code = adb_raw("devices")

    # FIX: "\tdevice" is the pattern for an authorized device
    # The header line "List of devices attached" contains no tab
    lines = stdout.split("\n")
    authorized = [l for l in lines if "\tdevice" in l]
    unauthorized = [l for l in lines if "\tunauthorized" in l]
    offline = [l for l in lines if "\toffline" in l]

    if unauthorized:
        log("Device found but UNAUTHORIZED.", "ERR")
        log("Check your phone screen and tap 'Allow USB debugging'.", "ERR")
        sys.exit(1)

    if offline:
        log("Device found but OFFLINE.", "ERR")
        log("Try: adb kill-server && adb start-server", "ERR")
        sys.exit(1)

    if not authorized:
        log("NO AUTHORIZED DEVICE FOUND.", "ERR")
        log("Steps to fix:", "ERR")
        log("  1. Connect Pixel 9a via USB", "ERR")
        log("  2. Enable Developer Options (tap Build Number 7 times)", "ERR")
        log("  3. Enable USB Debugging in Developer Options", "ERR")
        log("  4. Accept the authorization prompt on your phone screen", "ERR")
        sys.exit(1)

    log(f"Authorized device found: {authorized[0].split(chr(9))[0]}", "OK")

    # Read device properties
    model, _, _ = adb("getprop ro.product.model")
    codename, _, _ = adb("getprop ro.product.device")
    build, _, _ = adb("getprop ro.build.display.id")
    serial, _, _ = adb("getprop ro.serialno")
    android_ver, _, _ = adb("getprop ro.build.version.release")
    sdk, _, _ = adb("getprop ro.build.version.sdk")
    fingerprint, _, _ = adb("getprop ro.build.fingerprint")

    log(f"Model:       {model}")
    log(f"Codename:    {codename}")
    log(f"Build:       {build}")
    log(f"Serial:      {serial}")
    log(f"Android:     {android_ver}")
    log(f"SDK:         {sdk}")
    log(f"Fingerprint: {fingerprint}")

    # Verify this is the Tegu
    if "tegu" not in codename.lower() and "pixel 9a" not in model.lower():
        log("WARNING: This does not appear to be a Pixel 9a (Tegu).", "WARN")
        confirm = input("Continue anyway? Type YES to proceed: ")
        if confirm.strip() != "YES":
            log("Aborted by user.", "INFO")
            sys.exit(0)

    log("Device verified.", "OK")

    return {
        "model": model,
        "codename": codename,
        "build": build,
        "serial": serial,
        "android": android_ver,
        "sdk": sdk,
        "fingerprint": fingerprint,
        "timestamp": datetime.datetime.now().isoformat()
    }


# -----------------------------------------------
# PHASE 1 — BASELINE CAPTURE
# FIX: safe_int() on all numeric conversions
# FIX: Proper pipe quoting runs on Android device
# -----------------------------------------------

def capture_baseline():
    section("PHASE 1 — BASELINE CAPTURE")

    baseline = {}

    log("Capturing all installed packages...")
    packages, _, _ = adb("pm list packages")
    baseline["all_packages"] = [
        p.strip() for p in packages.split("\n") if p.strip()
    ]
    log(f"  Total packages: {len(baseline['all_packages'])}")

    log("Capturing disabled packages...")
    disabled, _, _ = adb("pm list packages -d")
    baseline["disabled_packages"] = [
        p.strip() for p in disabled.split("\n") if p.strip()
    ]
    log(f"  Currently disabled: {len(baseline['disabled_packages'])}")

    log("Capturing active network request count...")
    # FIX: Quoted so grep/wc run on Android, not PC
    net_count, _, _ = adb(
        "dumpsys connectivity | grep -c NetworkRequest"
    )
    baseline["network_request_count"] = safe_int(net_count)
    log(f"  Network requests: {baseline['network_request_count']}")

    log("Capturing FCM receiver count...")
    fcm, _, _ = adb(
        "dumpsys package | grep -c firebase.MESSAGING_EVENT"
    )
    baseline["fcm_receivers"] = safe_int(fcm)
    log(f"  FCM receivers: {baseline['fcm_receivers']}")

    log("Capturing boot receiver count...")
    boot, _, _ = adb(
        "dumpsys package | grep -c BOOT_COMPLETED"
    )
    baseline["boot_receivers"] = safe_int(boot)
    log(f"  Boot receivers: {baseline['boot_receivers']}")

    log("Capturing location request count...")
    location, _, _ = adb(
        "dumpsys location | grep -c Request"
    )
    baseline["location_requests"] = safe_int(location)
    log(f"  Location requests: {baseline['location_requests']}")

    log("Capturing wlan0 traffic stats...")
    rx, _, _ = adb("cat /sys/class/net/wlan0/statistics/rx_bytes")
    tx, _, _ = adb("cat /sys/class/net/wlan0/statistics/tx_bytes")
    baseline["wlan0_rx_bytes"] = safe_int(rx)
    baseline["wlan0_tx_bytes"] = safe_int(tx)
    log(f"  RX: {baseline['wlan0_rx_bytes']} bytes")
    log(f"  TX: {baseline['wlan0_tx_bytes']} bytes")

    log("Capturing running service count...")
    services, _, _ = adb(
        "dumpsys activity services | grep -c ServiceRecord"
    )
    baseline["running_services"] = safe_int(services)
    log(f"  Running services: {baseline['running_services']}")

    baseline["captured_at"] = datetime.datetime.now().isoformat()

    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    log(f"Baseline saved to: {BASELINE_FILE}", "OK")
    return baseline


# -----------------------------------------------
# PHASE 2 — PACKAGE DISABLE WITH VERIFICATION
# -----------------------------------------------

def disable_packages():
    section("PHASE 2 — PACKAGE DISABLE")

    results = {}

    for package in PACKAGES_TO_DISABLE:
        log(f"--- Processing: {package}")

        # Check if package exists on device
        check, _, _ = adb(f"pm list packages {package}")
        if not check or package not in check:
            log(f"  NOT FOUND on device — skipping", "WARN")
            results[package] = "NOT_FOUND"
            continue

        # Check if already disabled
        state, _, _ = adb(f"pm list packages -d {package}")
        if state and package in state:
            log(f"  ALREADY DISABLED", "OK")
            results[package] = "ALREADY_DISABLED"
            continue

        # Disable it
        out, err, code = adb(
            f"pm disable-user --user 0 {package}"
        )

        # Wait and verify
        time.sleep(0.5)
        verify, _, _ = adb(f"pm list packages -d {package}")

        if verify and package in verify:
            log(f"  DISABLED AND VERIFIED", "OK")
            results[package] = "DISABLED"
        else:
            log(f"  DISABLE FAILED — response: {out}", "ERR")
            results[package] = "FAILED"

    # Print summary
    log("--- PACKAGE DISABLE SUMMARY ---")
    for pkg, status in results.items():
        marker = "OK" if status in [
            "DISABLED", "ALREADY_DISABLED"
        ] else "ERR"
        log(f"  {status:<22} {pkg}", marker)

    total_ok = sum(
        1 for s in results.values()
        if s in ["DISABLED", "ALREADY_DISABLED"]
    )
    log(f"Result: {total_ok}/{len(PACKAGES_TO_DISABLE)} disabled", "OK")

    return results


# -----------------------------------------------
# PHASE 3 — APPOPS PERMISSION DENIAL
# -----------------------------------------------

def deny_appops():
    section("PHASE 3 — APPOPS PERMISSION DENIAL")

    results = {}

    for package, op in APPOPS_TO_DENY:
        key = f"{package} / {op}"
        log(f"--- Processing: {key}")

        # Read current state before change
        current, _, _ = adb(f"cmd appops get {package} {op}")
        log(f"  Before: {current if current else 'not set'}")

        # Apply denial
        adb(f"cmd appops set {package} {op} deny")

        # Pause and verify
        time.sleep(0.3)
        after, _, _ = adb(f"cmd appops get {package} {op}")
        log(f"  After:  {after if after else 'not set'}")

        if "deny" in after.lower():
            log(f"  DENIED AND VERIFIED", "OK")
            results[key] = "DENIED"
        else:
            log(f"  DENIAL NOT CONFIRMED — manual review needed", "ERR")
            results[key] = "FAILED"

    # Summary
    denied = sum(1 for s in results.values() if s == "DENIED")
    failed = sum(1 for s in results.values() if s == "FAILED")
    log(f"Result: {denied} denied / {failed} failed", "OK")

    return results


# -----------------------------------------------
# PHASE 4 — NETWORK TRANSPARENCY AUDIT
# FIX: Replaced nslookup (not on Android) with getprop
# FIX: Replaced ss/netstat with Android-native commands
# FIX: All pipe commands quoted for Android execution
# -----------------------------------------------

def network_audit():
    section("PHASE 4 — NETWORK TRANSPARENCY AUDIT")

    # DNS configuration — Android native
    log("--- DNS Configuration ---")
    dns1, _, _ = adb("getprop net.dns1")
    dns2, _, _ = adb("getprop net.dns2")
    dns_tls, _, _ = adb("getprop net.dns.tls_hostname")
    private_dns, _, _ = adb("getprop persist.sys.dns_resolver")
    log(f"  DNS1:        {dns1 if dns1 else 'not set'}")
    log(f"  DNS2:        {dns2 if dns2 else 'not set'}")
    log(f"  TLS host:    {dns_tls if dns_tls else 'not set'}")
    log(f"  Private DNS: {private_dns if private_dns else 'not set'}")

    # Network interfaces — ip addr works on Android
    log("--- Network Interfaces ---")
    interfaces, _, _ = adb("ip addr show")
    for line in interfaces.split("\n"):
        if line.strip():
            log(f"  {line.strip()}")

    # Routing table
    log("--- Routing Table ---")
    routes, _, _ = adb("ip route show")
    for line in routes.split("\n"):
        if line.strip():
            log(f"  {line.strip()}")

    # Traffic stats
    log("--- wlan0 Traffic Stats ---")
    rx, _, _ = adb("cat /sys/class/net/wlan0/statistics/rx_bytes")
    tx, _, _ = adb("cat /sys/class/net/wlan0/statistics/tx_bytes")
    rx_int = safe_int(rx)
    tx_int = safe_int(tx)
    log(f"  RX: {rx_int:,} bytes")
    log(f"  TX: {tx_int:,} bytes")

    if rx_int > 0:
        ratio = tx_int / rx_int
        log(f"  TX:RX ratio: {ratio:.1f}:1")
        if ratio > 5:
            log(
                f"  WARNING: High outbound ratio {ratio:.1f}:1 "
                f"— device sending significantly more than receiving",
                "WARN"
            )

    # Active connections via Android proc filesystem
    # FIX: Use /proc/net/tcp instead of ss or netstat
    log("--- Active TCP Connections (/proc/net/tcp) ---")
    tcp, _, _ = adb("cat /proc/net/tcp")
    if tcp:
        lines = tcp.split("\n")
        log(f"  Active TCP entries: {len(lines)}")
        # Show first 10 for visibility
        for line in lines[1:11]:
            if line.strip():
                log(f"  {line.strip()}")
    else:
        log("  /proc/net/tcp not readable", "WARN")

    # Active network requests
    log("--- Active Network Requests (top 20) ---")
    requests, _, _ = adb("dumpsys connectivity | grep NetworkRequest")
    req_lines = [l for l in requests.split("\n") if l.strip()]
    log(f"  Total: {len(req_lines)}")
    for line in req_lines[:20]:
        log(f"  {line.strip()}")

    # Check known telemetry properties
    # FIX: Use getprop and connectivity check instead of nslookup
    log("--- Telemetry Endpoint Connectivity Check ---")
    for domain in DNS_BLOCK_DOMAINS:
        # Use ping -c 1 -W 2 which IS available on Android
        ping_out, _, ping_code = adb(
            f"ping -c 1 -W 2 {domain} 2>&1 | head -2"
        )
        if ping_code == 0 or "bytes from" in ping_out:
            log(f"  REACHABLE: {domain}", "WARN")
        else:
            log(f"  NOT REACHABLE: {domain}", "OK")

    # VPN state
    log("--- VPN State ---")
    vpn, _, _ = adb("dumpsys connectivity | grep -i vpn | head -5")
    if vpn:
        for line in vpn.split("\n"):
            if line.strip():
                log(f"  {line.strip()}")
    else:
        log("  No VPN detected", "WARN")

    # Active UID tracking
    log("--- Tracked UIDs (network activity) ---")
    tracked, _, _ = adb(
        "dumpsys connectivity | grep Tracked | head -10"
    )
    if tracked:
        for line in tracked.split("\n"):
            if line.strip():
                log(f"  {line.strip()}")


# -----------------------------------------------
# PHASE 5 — POST-RECLAMATION VERIFICATION
# FIX: safe_int() on all numeric deltas
# FIX: Proper package check without grep pipe ambiguity
# -----------------------------------------------

def verify_reclamation(baseline):
    section("PHASE 5 — POST-RECLAMATION VERIFICATION")

    report = {}

    # Verify package states
    log("Verifying package disable states...")
    disabled_now, _, _ = adb("pm list packages -d")
    all_now, _, _ = adb("pm list packages")

    for package in PACKAGES_TO_DISABLE:
        pkg_tag = f"package:{package}"
        if pkg_tag in disabled_now:
            log(f"  CONFIRMED DISABLED: {package}", "OK")
            report[package] = "CONFIRMED_DISABLED"
        elif pkg_tag not in all_now:
            log(f"  NOT PRESENT: {package}", "OK")
            report[package] = "NOT_PRESENT"
        else:
            log(f"  STILL ENABLED: {package}", "ERR")
            report[package] = "STILL_ENABLED"

    # Verify AppOps
    log("Verifying AppOps denial states...")
    appops_failures = []
    for package, op in APPOPS_TO_DENY:
        state, _, _ = adb(f"cmd appops get {package} {op}")
        if "deny" in state.lower():
            log(f"  CONFIRMED DENIED: {package} — {op}", "OK")
        else:
            log(
                f"  NOT DENIED: {package} — {op} "
                f"(current: {state.strip()})",
                "ERR"
            )
            appops_failures.append(f"{package}:{op}")

    # Network delta comparison
    log("--- Network Delta vs Baseline ---")

    net_now, _, _ = adb(
        "dumpsys connectivity | grep -c NetworkRequest"
    )
    b_net = baseline.get("network_request_count", 0)
    c_net = safe_int(net_now)
    log(f"  Network requests — Before: {b_net} / After: {c_net} "
        f"/ Delta: {b_net - c_net}")

    fcm_now, _, _ = adb(
        "dumpsys package | grep -c firebase.MESSAGING_EVENT"
    )
    b_fcm = baseline.get("fcm_receivers", 0)
    c_fcm = safe_int(fcm_now)
    log(f"  FCM receivers    — Before: {b_fcm} / After: {c_fcm} "
        f"/ Delta: {b_fcm - c_fcm}")

    boot_now, _, _ = adb(
        "dumpsys package | grep -c BOOT_COMPLETED"
    )
    b_boot = baseline.get("boot_receivers", 0)
    c_boot = safe_int(boot_now)
    log(f"  Boot receivers   — Before: {b_boot} / After: {c_boot} "
        f"/ Delta: {b_boot - c_boot}")

    loc_now, _, _ = adb(
        "dumpsys location | grep -c Request"
    )
    b_loc = baseline.get("location_requests", 0)
    c_loc = safe_int(loc_now)
    log(f"  Location requests — Before: {b_loc} / After: {c_loc} "
        f"/ Delta: {b_loc - c_loc}")

    svc_now, _, _ = adb(
        "dumpsys activity services | grep -c ServiceRecord"
    )
    b_svc = baseline.get("running_services", 0)
    c_svc = safe_int(svc_now)
    log(f"  Running services — Before: {b_svc} / After: {c_svc} "
        f"/ Delta: {b_svc - c_svc}")

    # Traffic delta
    rx_now, _, _ = adb(
        "cat /sys/class/net/wlan0/statistics/rx_bytes"
    )
    tx_now, _, _ = adb(
        "cat /sys/class/net/wlan0/statistics/tx_bytes"
    )
    rx_delta = safe_int(rx_now) - baseline.get("wlan0_rx_bytes", 0)
    tx_delta = safe_int(tx_now) - baseline.get("wlan0_tx_bytes", 0)
    log(f"  wlan0 RX since baseline: +{rx_delta:,} bytes")
    log(f"  wlan0 TX since baseline: +{tx_delta:,} bytes")

    return report, appops_failures


# -----------------------------------------------
# PHASE 6 — FINAL AUDIT DOCUMENT
# -----------------------------------------------

def generate_audit(
        device_info, baseline, disable_results,
        appops_results, verify_report, appops_failures):

    section("PHASE 6 — FINAL AUDIT DOCUMENT")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    audit = {
        "audit_timestamp": datetime.datetime.now().isoformat(),
        "device": device_info,
        "baseline_file": BASELINE_FILE,
        "log_file": LOG_FILE,
        "packages": {
            "processed": len(PACKAGES_TO_DISABLE),
            "disabled": sum(
                1 for s in disable_results.values()
                if s in ["DISABLED", "ALREADY_DISABLED"]
            ),
            "failed": sum(
                1 for s in disable_results.values()
                if s == "FAILED"
            ),
            "not_found": sum(
                1 for s in disable_results.values()
                if s == "NOT_FOUND"
            ),
            "results": disable_results,
        },
        "appops": {
            "processed": len(APPOPS_TO_DENY),
            "denied": sum(
                1 for s in appops_results.values()
                if s == "DENIED"
            ),
            "failed": sum(
                1 for s in appops_results.values()
                if s == "FAILED"
            ),
            "failures": appops_failures,
        },
        "verification": verify_report,
        "dns_block_domains": DNS_BLOCK_DOMAINS,
        "notes": {
            "rethinkdns": (
                "Install RethinkDNS — import tegu_dns_blocklist.txt "
                "under Firewall > Custom Rules"
            ),
            "shizuku": (
                "For AppOps denials that failed: install Shizuku "
                "and App Ops from Play Store for deeper control"
            ),
            "ota_warning": (
                "SYSTEM_FIXED and PERSISTENT packages will re-enable "
                "after OTA updates. Re-run this script after every "
                "system update."
            ),
        }
    }

    audit_file = f"tegu_audit_{timestamp}.json"
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)

    dns_file = "tegu_dns_blocklist.txt"
    with open(dns_file, "w", encoding="utf-8") as f:
        f.write("# TEGU DNS BLOCKLIST\n")
        f.write(
            f"# Generated: {datetime.datetime.now().isoformat()}\n"
        )
        f.write(
            "# Import into RethinkDNS > Firewall > Custom Rules\n\n"
        )
        for domain in DNS_BLOCK_DOMAINS:
            f.write(f"{domain}\n")

    log(f"Audit JSON saved:      {audit_file}", "OK")
    log(f"DNS blocklist saved:   {dns_file}", "OK")
    log(f"Full log saved:        {LOG_FILE}", "OK")

    log("--- FINAL SUMMARY ---")
    log(
        f"Packages:  "
        f"{audit['packages']['disabled']}/"
        f"{audit['packages']['processed']} disabled"
    )
    log(
        f"AppOps:    "
        f"{audit['appops']['denied']}/"
        f"{audit['appops']['processed']} denied"
    )
    if appops_failures:
        log(
            f"AppOps failures ({len(appops_failures)}) — "
            f"use Shizuku for these:",
            "WARN"
        )
        for f_item in appops_failures:
            log(f"  {f_item}", "WARN")

    return audit_file, dns_file


# -----------------------------------------------
# MAIN
# -----------------------------------------------

def main():
    log("=" * 60)
    log("  TEGU RECLAMATION SCRIPT v2")
    log("  Google Pixel 9a — Full Device Hardening")
    log("  All operations verbose, logged, verified")
    log("=" * 60)

    print("\nThis script will:")
    print("  PREREQ  — Verify adb is installed and accessible")
    print("  PHASE 0 — Verify device is Pixel 9a Tegu")
    print("  PHASE 1 — Capture full pre-reclamation baseline")
    print("  PHASE 2 — Disable documented surveillance packages")
    print("  PHASE 3 — Deny AppOps to key system apps")
    print("  PHASE 4 — Full network transparency audit")
    print("  PHASE 5 — Verify every change was applied")
    print("  PHASE 6 — Generate audit JSON + DNS blocklist")
    print(f"\nAll output logged to: {LOG_FILE}")
    print("\nType YES to proceed: ", end="", flush=True)

    confirm = input()
    if confirm.strip() != "YES":
        print("Aborted.")
        sys.exit(0)

    # Run all phases
    check_prerequisites()
    device_info = verify_device()
    baseline = capture_baseline()

    print(
        "\nBaseline captured. "
        "Review above output then press ENTER to begin reclamation..."
    )
    input()

    disable_results = disable_packages()
    appops_results = deny_appops()
    network_audit()

    verify_report, appops_failures = verify_reclamation(baseline)

    audit_file, dns_file = generate_audit(
        device_info, baseline, disable_results,
        appops_results, verify_report, appops_failures
    )

    log("=" * 60)
    log("  RECLAMATION COMPLETE")
    log(f"  Audit:        {audit_file}")
    log(f"  DNS list:     {dns_file}")
    log(f"  Full log:     {LOG_FILE}")
    log("  Next: Import DNS list into RethinkDNS")
    log("  Next: Run again after any OTA update")
    log("  The Tegu reclaims.")
    log("=" * 60)


if __name__ == "__main__":
    main()
