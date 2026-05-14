#!/usr/bin/env python3
import subprocess, os, json, time, re, sys
from datetime import datetime

TS = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT = os.path.expanduser(f"~/repair_evidence_{TS}.txt")
LOG = os.path.expanduser(f"~/repair_chase_{TS}.log")
JSON_OUT = os.path.expanduser(f"~/repair_evidence_{TS}.json")

evidence = {}
chase_queue = []
visited = set()

def log(msg):
    print(f"[REPAIR] {msg}")
    with open(LOG, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def shell(cmd, timeout=20):
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout.strip()
        err = result.stderr.strip()
        return out if out else err
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: {cmd}"
    except Exception as e:
        return f"ERROR: {e}"

def adb(cmd, timeout=20):
    return shell(f"adb shell \"{cmd}\"", timeout=timeout)

def local(cmd, timeout=10):
    return shell(cmd, timeout=timeout)

def save(section, data):
    if not data or data.strip() == "":
        data = "[EMPTY]"
    evidence[section] = data
    with open(OUT, "a") as f:
        f.write(f"\n{'='*60}\n=== {section} ===\n{'='*60}\n{data}\n")
    with open(JSON_OUT, "w") as f:
        json.dump(evidence, f, indent=2)

def extract_and_chase(text):
    if not text or len(text) < 5:
        return

    # chase packages
    packages = re.findall(r'com\.[a-zA-Z0-9_.]{5,}', text)
    for pkg in set(packages):
        interesting = any(kw in pkg.lower() for kw in [
            'work','enterprise','mdm','dpc','policy','enroll',
            'manage','admin','repair','oob','provision','setup',
            'laforge','clouddpc','devicepolicy'
        ])
        if interesting and pkg not in visited:
            chase_queue.append(pkg)

    # chase URLs
    urls = re.findall(r'https?://[^\s\'"<>]{10,}', text)
    for url in set(urls):
        if url not in visited:
            visited.add(url)
            log(f"URL FOUND: {url}")
            result = local(f"curl -sk --max-time 5 '{url}'")
            save(f"URL_HIT_{url[:80].replace('/','_')}", result)
            extract_and_chase(result)

    # extract tokens
    tokens = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
    for t in set(tokens):
        if t not in visited:
            visited.add(t)
            save(f"TOKEN_{t[:30]}", t)

    # extract emails
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    for email in set(emails):
        log(f"EMAIL FOUND: {email}")
        save(f"EMAIL_{email}", email)

    # chase firebase/google domains
    domains = re.findall(
        r'[a-zA-Z0-9.-]+\.(google|firebase|googleapis|android|gstatic|firebaseio)\.com',
        text
    )
    for domain in set(domains):
        if domain not in visited:
            visited.add(domain)
            log(f"DOMAIN: {domain}")
            r1 = local(f"curl -sk --max-time 5 'https://{domain}/.json'")
            save(f"DOMAIN_JSON_{domain}", r1)
            r2 = local(f"curl -sk --max-time 5 'https://{domain}'")
            save(f"DOMAIN_ROOT_{domain}", r2)

def chase(pkg):
    if pkg in visited or '/' in pkg or ' ' in pkg:
        return
    visited.add(pkg)
    log(f"CHASING: {pkg}")

    detail = adb(f"dumpsys package {pkg}")
    save(f"PKG_DETAIL_{pkg}", detail)
    extract_and_chase(detail)

    save(f"PKG_PATH_{pkg}", adb(f"pm path {pkg}"))
    save(f"PKG_PERMS_{pkg}", adb(
        f"dumpsys package {pkg} | grep -iE 'permission|granted|requested'"
    ))
    save(f"PKG_RECEIVERS_{pkg}", adb(
        f"dumpsys package {pkg} | grep -iE 'receiver|service|activity|provider'"
    ))

    # data dir contents
    for subdir in ['', 'shared_prefs', 'databases', 'files', 'cache']:
        path = f"/data/user/0/{pkg}/{subdir}" if subdir else f"/data/user/0/{pkg}"
        listing = adb(f"ls -la {path} 2>/dev/null")
        if listing and '[EMPTY]' not in listing and 'No such file' not in listing:
            save(f"PKG_DIR_{pkg}_{subdir or 'root'}", listing)

    # read shared prefs
    prefs_raw = adb(f"ls /data/user/0/{pkg}/shared_prefs/ 2>/dev/null")
    if prefs_raw and 'No such file' not in prefs_raw:
        for pref in prefs_raw.splitlines():
            pref = pref.strip()
            if pref:
                content = adb(
                    f"cat /data/user/0/{pkg}/shared_prefs/{pref} 2>/dev/null"
                )
                save(f"PREF_{pkg}_{pref}", content)
                extract_and_chase(content)

    # dump databases
    db_raw = adb(f"ls /data/user/0/{pkg}/databases/ 2>/dev/null")
    if db_raw and 'No such file' not in db_raw:
        for db in db_raw.splitlines():
            db = db.strip()
            if db and not db.endswith(('-journal','-wal','-shm')):
                content = adb(
                    f"sqlite3 /data/user/0/{pkg}/databases/{db} .dump 2>/dev/null"
                )
                save(f"DB_{pkg}_{db}", content)
                extract_and_chase(content)

    # device policy for this pkg
    save(f"PKG_POLICY_{pkg}", adb(
        f"dumpsys device_policy | grep -A5 '{pkg}'"
    ))

# ─────────────────────────────────────────────
log("REPAIR MODE BARN. BUILDING.")

# verify adb is alive
adb_check = shell("adb devices")
save("ADB_DEVICES", adb_check)
log(f"ADB STATUS: {adb_check}")

# ─── PHASE 1: DEVICE IDENTITY ────────────────
log("PHASE 1: DEVICE IDENTITY")
save("SERIAL", adb("getprop ro.serialno"))
save("PRODUCT_MODEL", adb("getprop ro.product.model"))
save("PRODUCT_CODENAME", adb("getprop ro.product.device"))
save("BUILD_FINGERPRINT", adb("getprop ro.build.fingerprint"))
save("BUILD_ID", adb("getprop ro.build.id"))
save("ANDROID_VERSION", adb("getprop ro.build.version.release"))
save("SECURITY_PATCH", adb("getprop ro.build.version.security_patch"))
save("BOOTLOADER", adb("getprop ro.boot.flash.locked"))
save("VERIFIED_BOOT", adb("getprop ro.boot.verifiedbootstate"))
save("VBMETA_STATE", adb("getprop ro.boot.vbmeta.device_state"))
save("VBMETA_DIGEST", adb("getprop ro.boot.vbmeta.digest"))
save("SECURE_BOOT", adb("getprop ro.boot.secure_boot"))
save("FRP_PARTITION", adb("getprop ro.frp.pst"))
save("ZUFS_PROVISIONED", adb("getprop ro.boot.zufs_provisioned"))
save("BOOT_REASON_HISTORY", adb("getprop persist.sys.boot.reason.history"))
save("BOOT_REASON", adb("getprop ro.boot.bootreason"))
save("SLOT_SUFFIX", adb("getprop ro.boot.slot_suffix"))
save("ALL_BOOT_PROPS", adb("getprop | grep '^\\[ro.boot'"))
save("ALL_PRODUCT_PROPS", adb("getprop | grep '^\\[ro.product'"))

# ─── PHASE 2: ENTERPRISE FLAGS ───────────────
log("PHASE 2: ENTERPRISE FLAGS")
save("ENTERPRISE_MODE_PROP", adb(
    "getprop ro.setupwizard.enterprise_mode"
))
save("SETUP_WIZARD_MODE", adb("getprop ro.setupwizard.mode"))
save("ORGANIZATION_OWNED", adb("getprop ro.organization_owned"))
save("ZERO_TOUCH_PROPS", adb(
    "getprop | grep -iE 'zero.touch|laforge|afwtest|afw|setup.type|enterprise'"
))
save("ALL_PERSIST_ENTERPRISE", adb(
    "getprop | grep '^\\[persist' | grep -iE "
    "'enterprise|enroll|provision|owner|mdm|dpc|laforge|zero|manage'"
))
save("ALL_RO_ENTERPRISE", adb(
    "getprop | grep -iE "
    "'enterprise|enroll|provision|owner|mdm|dpc|laforge|zero.touch|organization'"
))
save("REMOTE_SIM_SLOT", adb("getprop persist.radio.uim.remote.slot"))
save("MULTISIM_CONFIG", adb("getprop persist.radio.multisim.config"))

# ─── PHASE 3: PROVISIONING STATE ─────────────
log("PHASE 3: PROVISIONING STATE")
save("DEVICE_PROVISIONED", adb("settings get global device_provisioned"))
save("SETUP_WIZARD_RAN", adb("settings get global setup_wizard_has_run"))
save("USER_SETUP_COMPLETE", adb("settings get secure user_setup_complete"))
save("ENTERPRISE_PRIVACY_INIT", adb(
    "settings get global enterprise_privacy_initialized"
))
save("ENROLLMENT_TOKEN", adb("settings get global enrollment_token"))
save("EUICC_PROVISIONED", adb("settings get global euicc_provisioned"))
save("DEVICE_POLICY_CONSTANTS", adb(
    "settings get global device_policy_constants"
))
save("ALL_GLOBAL_SETTINGS", adb("settings list global"))
save("ALL_SECURE_SETTINGS", adb("settings list secure"))
save("ALL_SYSTEM_SETTINGS", adb("settings list system"))

# ─── PHASE 4: DEVICE POLICY FULL ─────────────
log("PHASE 4: DEVICE POLICY")
dp = adb("dumpsys device_policy")
save("DEVICE_POLICY_FULL", dp)
extract_and_chase(dp)

save("DEVICE_POLICY_ENTERPRISE", adb(
    "dumpsys device_policy | grep -iE "
    "'laforge|organization|admin|enroll|tenant|domain|owner|headless|"
    "provisioningState|isOrganizationOwned|setupwizard|enterprise'"
))
save("ACTIVE_RESTRICTIONS", adb(
    "dumpsys device_policy | grep -A3 'Resolved Policy'"
))
save("SUSPENSION_LIST", adb(
    "dumpsys device_policy | grep -A30 'subject to suspension'"
))

# ─── PHASE 5: REPAIR MODE SPECIFIC ───────────
log("PHASE 5: REPAIR MODE INTERNALS")
save("REPAIRMODE_APK_PATH", adb("pm path com.google.android.repairmode"))
save("REPAIRMODE_DUMPSYS", adb(
    "dumpsys activity service com.google.android.repairmode 2>/dev/null"
))
save("REPAIRMODE_DATA", adb(
    "ls -laR /data/user/0/com.google.android.repairmode/ 2>/dev/null"
))
save("REPAIRMODE_PREFS", adb(
    "ls -la /data/user/0/com.google.android.repairmode/shared_prefs/ 2>/dev/null"
))
prefs = adb(
    "ls /data/user/0/com.google.android.repairmode/shared_prefs/ 2>/dev/null"
)
if prefs and 'No such' not in prefs:
    for pref in prefs.splitlines():
        pref = pref.strip()
        if pref:
            content = adb(
                f"cat /data/user/0/com.google.android.repairmode/shared_prefs/{pref} 2>/dev/null"
            )
            save(f"REPAIRMODE_PREF_{pref}", content)
            extract_and_chase(content)

save("REPAIRMODE_DB", adb(
    "ls -la /data/user/0/com.google.android.repairmode/databases/ 2>/dev/null"
))
save("REPAIRMODE_SOURCE_APK", adb(
    "ls -la /system_ext/app/RepairMode/ 2>/dev/null"
))
save("REPAIRMODE_STRINGS", adb(
    "strings /system_ext/app/RepairMode/RepairMode.apk 2>/dev/null | "
    "grep -iE 'https://|enroll|enterprise|org|admin|token|laforge|domain'"
))

# ─── PHASE 6: ACCOUNTS ───────────────────────
log("PHASE 6: ACCOUNTS")
acct = adb("dumpsys account")
save("ACCOUNTS_FULL", acct)
extract_and_chase(acct)
save("ACCOUNTS_ENTERPRISE", adb(
    "dumpsys account | grep -iE "
    "'enterprise|work|managed|domain|org|laforge|enroll'"
))

# ─── PHASE 7: ESIM AND MODEM ─────────────────
log("PHASE 7: ESIM AND MODEM")
save("EUICC_CONTROLLER_FULL", adb("dumpsys euicc_controller 2>/dev/null"))
save("EUICC_CARD_MGR_FULL", adb("dumpsys euicc_card_mgr 2>/dev/null"))
save("ISUB_FULL", adb("dumpsys isub"))
save("ISUB_ENTERPRISE", adb(
    "dumpsys isub | grep -iE "
    "'esim|euicc|profile|iccid|imsi|enroll|enterprise|embedded|remote'"
))
save("TELEPHONY_FULL", adb("dumpsys telephony.registry"))
save("PHONE_INFO", adb("dumpsys iphonesubinfo"))
save("PHYSICAL_CHANNEL_CONFIG", adb(
    "dumpsys telephony.registry | grep -iE 'physical|channel|pci|band|earfcn'"
))
save("SLOT0_DETAIL", adb(
    "dumpsys telephony.registry | grep -A30 'Phone=0'"
))
save("SLOT1_DETAIL", adb(
    "dumpsys telephony.registry | grep -A30 'Phone=1'"
))
save("MODEM_ACTIVITY", adb("dumpsys modem_activity_info 2>/dev/null"))
save("CARRIER_CONFIG", adb("dumpsys carrier_config 2>/dev/null"))
save("CBRS_STATE", adb(
    "dumpsys telephony.registry | grep -iE 'cbrs|citizen|3550|band48'"
))
save("LAST_PROVISIONING_INFO", adb(
    "dumpsys euicc_controller 2>/dev/null | grep -A5 'last.*provision'"
))

# ─── PHASE 8: NETWORK AND VPN ────────────────
log("PHASE 8: NETWORK AND VPN")
save("VPN_FULL", adb("dumpsys vpn"))
save("ALWAYS_ON_VPN_APP", adb("settings get secure always_on_vpn_app"))
save("ALWAYS_ON_VPN_LOCKDOWN", adb(
    "settings get secure always_on_vpn_lockdown"
))
save("NETPOLICY_FULL", adb("dumpsys netpolicy"))
save("NETPOLICY_ENTERPRISE", adb(
    "dumpsys netpolicy | grep -iE "
    "'owner|enterprise|manage|restrict|vpn|always|work'"
))
save("CONNECTIVITY_FULL", adb("dumpsys connectivity"))
save("CONNECTIVITY_VPN", adb(
    "dumpsys connectivity | grep -iE "
    "'vpn|enterprise|manage|restrict|always|tunnel'"
))
save("WIFI_STATE", adb("dumpsys wifi | grep -iE 'ssid|bssid|connect|state'"))
save("DNS_CONFIG", adb("getprop | grep -iE 'net.dns|dhcp.*dns'"))
save("NETWORK_INTERFACES", adb("ip addr show"))
save("ROUTING_TABLE", adb("ip route show"))
save("ACTIVE_CONNECTIONS", adb("ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null"))

# ─── PHASE 9: KEYSTORE AND CERTS ─────────────
log("PHASE 9: KEYSTORE AND CERTS")
save("KEYSTORE_LIST", adb("keystore_cli_v2 list 2>/dev/null"))
save("USER_CERTS_ADDED", adb(
    "ls -la /data/misc/user/0/cacerts-added/ 2>/dev/null"
))
save("USER_CERTS_REMOVED", adb(
    "ls -la /data/misc/user/0/cacerts-removed/ 2>/dev/null"
))
save("SYSTEM_CERT_COUNT", adb(
    "ls /system/etc/security/cacerts/ 2>/dev/null | wc -l"
))
save("WIFI_CERTS", adb("ls -la /data/misc/wifi/certs/ 2>/dev/null"))
save("VPN_PROFILES", adb("ls -la /data/misc/vpn/ 2>/dev/null"))

# ─── PHASE 10: PARTITIONS ────────────────────
log("PHASE 10: PARTITIONS")
save("PERSISTENT_DIR", adb("ls -laR /persistent/ 2>/dev/null"))
save("VENDOR_PERSIST", adb("ls -laR /mnt/vendor/persist/ 2>/dev/null"))
save("METADATA_DIR", adb("ls -laR /metadata/ 2>/dev/null"))
save("FRP_CONTENT", adb(
    "cat /dev/block/by-name/frp 2>/dev/null | strings | head -50"
))
save("PRODUCT_APP_ENTERPRISE", adb(
    "ls -la /product/app/ | grep -iE "
    "'policy|dpc|device|repair|enroll|work|cloud|oob|setup|enterprise'"
))
save("SYSTEM_EXT_ENTERPRISE", adb(
    "ls -la /system_ext/app/ | grep -iE "
    "'policy|dpc|device|repair|enroll|work|cloud|oob|setup|enterprise'"
))
save("SYSTEM_APP_ENTERPRISE", adb(
    "ls -la /system/app/ | grep -iE "
    "'policy|dpc|device|repair|enroll|work|cloud|oob|setup|enterprise'"
))
save("PRIV_APP_ENTERPRISE", adb(
    "ls -la /system/priv-app/ | grep -iE "
    "'policy|dpc|device|repair|enroll|work|cloud|oob|setup|enterprise'"
))

# ─── PHASE 11: GSERVICES AND LAFORGE ─────────
log("PHASE 11: GSERVICES AND LAFORGE")
gservices = adb(
    "content query --uri content://com.google.android.gsf.gservices/main "
    "--projection name:value 2>/dev/null | grep -iE "
    "'enterprise|enroll|mdm|dpc|owner|provision|zero.touch|laforge|"
    "checkin|device_management|android_id|gcm'"
)
save("GSERVICES_ENTERPRISE", gservices)
extract_and_chase(gservices)

save("GSERVICES_ALL", adb(
    "content query --uri content://com.google.android.gsf.gservices/main "
    "--projection name:value 2>/dev/null"
))
save("ANDROID_ID", adb(
    "settings get secure android_id"
))
save("GMS_CHECKIN", adb(
    "dumpsys activity service com.google.android.gms/.checkin.CheckinService "
    "2>/dev/null"
))
save("GMS_DEVICE_STATE", adb(
    "dumpsys activity service com.google.android.gms "
    "2>/dev/null | grep -iE "
    "'enroll|enterprise|owner|laforge|provision|token|checkin'"
))

# ─── PHASE 12: LOGCAT FULL HISTORY ───────────
log("PHASE 12: LOGCAT")
save("LOGCAT_ENTERPRISE", adb(
    "logcat -d | grep -iE "
    "'enterprise|enroll|provision|owner|dpc|laforge|zero.touch|"
    "repairmode|clouddpc|setupwizard' | tail -500",
    timeout=30
))
save("LOGCAT_MDM", adb(
    "logcat -d | grep -iE "
    "'mdm|device.policy|devicepolicy|DevicePolicyManager|"
    "DeviceAdmin|device_admin' | tail -500",
    timeout=30
))
save("LOGCAT_ESIM", adb(
    "logcat -d | grep -iE "
    "'euicc|esim|profile|iccid|embedded|eUICC' | tail -200",
    timeout=30
))
save("LOGCAT_VPN", adb(
    "logcat -d | grep -iE "
    "'vpn|wildlife|tunnel|always.on|WildlifeVpn' | tail -200",
    timeout=30
))
save("LOGCAT_MODEM", adb(
    "logcat -d | grep -iE "
    "'modem|baseband|ril|RIL|telephony|cbrs|CBRS' | tail -200",
    timeout=30
))
save("LOGCAT_BOOT", adb(
    "logcat -d | grep -iE "
    "'boot|provision|setup|wizard|factory.reset|frp' | tail -200",
    timeout=30
))
save("LOGCAT_ALL_BUFFERS", adb(
    "logcat -d -b all | grep -iE "
    "'enterprise|enroll|laforge|zero.touch|repairmode' | tail -500",
    timeout=30
))

# ─── PHASE 13: FIREBASE ──────────────────────
log("PHASE 13: FIREBASE")
fb_base = "https://com-android-cloud-policy.firebaseio.com"
save("FIREBASE_ROOT", local(f"curl -sk --max-time 8 '{fb_base}/.json'"))
for path in [
    "enrollment","devices","policy","admin","config",
    "enterprise","owner","token","users","orgs",
    "organizations","tenants","management","dpc","mdm"
]:
    r = local(f"curl -sk --max-time 5 '{fb_base}/{path}.json'")
    save(f"FIREBASE_{path.upper()}", r)
    if r and 'permission' not in r.lower() and r != 'null':
        extract_and_chase(r)

# ─── PHASE 14: ENTERPRISE PACKAGE CHASE ──────
log("PHASE 14: PACKAGE CHASE")
seed_pkgs = [
    "com.google.android.apps.work.clouddpc",
    "com.google.android.apps.work.oobconfig",
    "com.google.android.repairmode",
    "com.google.android.gms",
    "com.google.android.setupwizard",
    "com.google.android.apps.work.profile",
    "com.google.android.devicepolicymanager",
]
for pkg in seed_pkgs:
    chase(pkg)

# ─── PHASE 15: RECURSIVE CHASE ───────────────
log("PHASE 15: RECURSIVE CHASE")
while chase_queue:
    pkg = chase_queue.pop(0)
    if pkg not in visited:
        log(f"RECURSIVE: {pkg}")
        chase(pkg)

# ─── PHASE 16: REPAIR MODE EXIT STATE ────────
log("PHASE 16: REPAIR MODE EXIT STATE PROBE")
save("REPAIR_EXIT_BEHAVIOR", adb(
    "dumpsys device_policy | grep -iE "
    "'exit|restore|transfer|after|complete|cleanup|wipe'"
))
save("REPAIR_PENDING_UPDATE", adb(
    "dumpsys device_policy | grep -iE 'pending|update|system'"
))
save("WHAT_HAPPENS_AFTER_REPAIR", adb(
    "cat /data/user/0/com.google.android.repairmode/shared_prefs/*.xml "
    "2>/dev/null"
))
save("REPAIRMODE_INTENT_FILTERS", adb(
    "dumpsys package com.google.android.repairmode | "
    "grep -iE 'action|category|intent|filter'"
))
save("REPAIRMODE_PERMISSIONS_GRANTED", adb(
    "dumpsys package com.google.android.repairmode | "
    "grep -iE 'granted=true|permission'"
))

# ─── PHASE 17: WHAT PERSISTS AFTER EXIT ──────
log("PHASE 17: PERSISTENCE PROBE")
save("FACTORY_RESET_PROTECTION", adb(
    "cat /dev/block/by-name/frp 2>/dev/null | strings"
))
save("METADATA_ENCRYPTION_STATE", adb(
    "ls -la /metadata/vold/ 2>/dev/null"
))
save("ROLLBACK_DATA", adb("ls -laR /data/rollback/ 2>/dev/null"))
save("STAGED_UPDATES", adb("ls -laR /data/staged-installs/ 2>/dev/null"))
save("OTA_PACKAGE", adb("ls -la /data/ota_package/ 2>/dev/null"))
save("PROPERTY_PERSIST_ALL", adb("getprop | grep '^\\[persist'"))

# ─── PHASE 18: SYNTHESIS ─────────────────────
log("PHASE 18: SYNTHESIS")
findings = {
    "device": {
        "model": evidence.get("PRODUCT_MODEL",""),
        "serial": evidence.get("SERIAL",""),
        "build": evidence.get("BUILD_FINGERPRINT",""),
        "bootloader_locked": evidence.get("BOOTLOADER",""),
        "verified_boot": evidence.get("VERIFIED_BOOT",""),
        "boot_reason_history": evidence.get("BOOT_REASON_HISTORY",""),
    },
    "enterprise_flags": {
        "enterprise_mode": evidence.get("ENTERPRISE_MODE_PROP",""),
        "organization_owned": evidence.get("ORGANIZATION_OWNED",""),
        "setup_wizard_mode": evidence.get("SETUP_WIZARD_MODE",""),
        "remote_sim_slot": evidence.get("REMOTE_SIM_SLOT",""),
        "euicc_provisioned": evidence.get("EUICC_PROVISIONED",""),
        "enrollment_token": evidence.get("ENROLLMENT_TOKEN",""),
        "enterprise_privacy_init": evidence.get("ENTERPRISE_PRIVACY_INIT",""),
    },
    "esim": {
        "euicc_controller": evidence.get("EUICC_CONTROLLER_FULL","")[:500],
        "last_provisioning": evidence.get("LAST_PROVISIONING_INFO",""),
        "slot1_detail": evidence.get("SLOT1_DETAIL",""),
    },
    "network": {
        "always_on_vpn": evidence.get("ALWAYS_ON_VPN_APP",""),
        "active_connections": evidence.get("ACTIVE_CONNECTIONS",""),
        "routing": evidence.get("ROUTING_TABLE",""),
    },
    "certs": {
        "added_certs": evidence.get("USER_CERTS_ADDED",""),
        "removed_certs": evidence.get("USER_CERTS_REMOVED",""),
        "system_cert_count": evidence.get("SYSTEM_CERT_COUNT",""),
    },
    "emails_found": [v for k,v in evidence.items() if k.startswith("EMAIL_")],
    "tokens_found": [v for k,v in evidence.items() if k.startswith("TOKEN_")],
    "urls_chased": [k.replace("URL_HIT_","") for k in evidence if k.startswith("URL_HIT_")],
    "firebase": {k:v for k,v in evidence.items()
                 if k.startswith("FIREBASE_")
                 and "permission" not in str(v).lower()
                 and v not in ["null","[EMPTY]"]},
    "packages_chased": list(visited),
}

save("SYNTHESIS", json.dumps(findings, indent=2))

log(f"BARN BUILT. Evidence: {OUT}")
log(f"JSON: {JSON_OUT}")
log(f"Log: {LOG}")
print(f"\n[REPAIR COMPLETE]\nEvidence : {OUT}\nJSON     : {JSON_OUT}\nLog      : {LOG}")
