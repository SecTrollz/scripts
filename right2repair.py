#!/usr/bin/env python3
import subprocess, os, json, re
from datetime import datetime

TS = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT = os.path.expanduser(f"~/repair_evidence_{TS}.txt")
LOG = os.path.expanduser(f"~/repair_chase_{TS}.log")
JSON_OUT = os.path.expanduser(f"~/repair_evidence_{TS}.json")

evidence = {}
chase_queue = []
visited = set()

RISH = os.path.expanduser("~/rish")

def log(msg):
    print(f"[REPAIR] {msg}")
    with open(LOG, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def run(cmd, timeout=20):
    """Run command directly in Termux context."""
    try:
        r = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=timeout
        )
        out = r.stdout.strip()
        err = r.stderr.strip()
        return out if out else (err if err else "[EMPTY]")
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT: {cmd[:60]}]"
    except Exception as e:
        return f"[ERROR: {e}]"

def priv(cmd, timeout=20):
    """Run privileged command via rish/Shizuku."""
    escaped = cmd.replace('"', '\\"')
    return run(f'{RISH} -c "{escaped}"', timeout=timeout)

def curl(url, timeout=8):
    return run(f"curl -sk --max-time {timeout} '{url}'")

def save(section, data):
    if not data or data.strip() in ("", "null", "[]", "{}"):
        data = "[EMPTY]"
    evidence[section] = data
    with open(OUT, "a") as f:
        f.write(f"\n{'='*60}\n=== {section} ===\n{'='*60}\n{data}\n")
    with open(JSON_OUT, "w") as f:
        json.dump(evidence, f, indent=2)

def extract_and_chase(text):
    if not text or len(text) < 5:
        return

    pkgs = re.findall(r'com\.[a-zA-Z0-9_.]{5,}', text)
    for pkg in set(pkgs):
        if any(kw in pkg.lower() for kw in [
            'work','enterprise','mdm','dpc','policy','enroll',
            'manage','admin','repair','oob','provision','setup',
            'laforge','clouddpc','devicepolicy'
        ]):
            if pkg not in visited:
                chase_queue.append(pkg)

    for url in set(re.findall(r'https?://[^\s\'"<>]{10,}', text)):
        if url not in visited:
            visited.add(url)
            log(f"URL: {url}")
            r = curl(url)
            save(f"URL_{url[:80].replace('/','_')}", r)
            extract_and_chase(r)

    for email in set(re.findall(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text
    )):
        log(f"EMAIL: {email}")
        save(f"EMAIL_{email}", email)

    for domain in set(re.findall(
        r'[a-zA-Z0-9.-]+\.(google|firebase|googleapis|android|firebaseio)\.com',
        text
    )):
        if domain not in visited:
            visited.add(domain)
            save(f"DOMAIN_{domain}",
                 curl(f"https://{domain}/.json"))

def chase_pkg(pkg):
    if pkg in visited or '/' in pkg or ' ' in pkg or len(pkg) < 8:
        return
    visited.add(pkg)
    log(f"CHASING: {pkg}")

    detail = priv(f"dumpsys package {pkg}")
    save(f"PKG_DETAIL_{pkg}", detail)
    extract_and_chase(detail)

    save(f"PKG_PATH_{pkg}", priv(f"pm path {pkg}"))
    save(f"PKG_PERMS_{pkg}", priv(
        f"dumpsys package {pkg} | grep -iE 'permission|granted|requested'"
    ))

    for subdir in ['', 'shared_prefs', 'databases', 'files', 'cache']:
        path = (f"/data/user/0/{pkg}/{subdir}"
                if subdir else f"/data/user/0/{pkg}")
        listing = priv(f"ls -la {path} 2>/dev/null")
        if listing and 'No such file' not in listing:
            save(f"PKG_DIR_{pkg}_{subdir or 'root'}", listing)

    prefs = priv(
        f"ls /data/user/0/{pkg}/shared_prefs/ 2>/dev/null"
    )
    if prefs and 'No such file' not in prefs and '[EMPTY]' not in prefs:
        for pref in prefs.splitlines():
            pref = pref.strip()
            if not pref:
                continue
            content = priv(
                f"cat /data/user/0/{pkg}/shared_prefs/{pref} 2>/dev/null"
            )
            save(f"PREF_{pkg}_{pref}", content)
            extract_and_chase(content)

    dbs = priv(f"ls /data/user/0/{pkg}/databases/ 2>/dev/null")
    if dbs and 'No such file' not in dbs and '[EMPTY]' not in dbs:
        for db in dbs.splitlines():
            db = db.strip()
            if db and not any(db.endswith(x)
                              for x in ('-journal','-wal','-shm')):
                content = priv(
                    f"sqlite3 /data/user/0/{pkg}/databases/{db} "
                    f".dump 2>/dev/null"
                )
                save(f"DB_{pkg}_{db}", content)
                extract_and_chase(content)

# ── PHASE 1: VERIFY RISH ─────────────────────
log("PHASE 1: VERIFY RISH")
save("RISH_TEST", priv("id"))
save("RISH_WHOAMI", priv("whoami"))
save("TERMUX_ENV", run("id && whoami && pwd"))

# ── PHASE 2: DEVICE IDENTITY ─────────────────
log("PHASE 2: DEVICE IDENTITY")
save("SERIAL", priv("getprop ro.serialno"))
save("MODEL", priv("getprop ro.product.model"))
save("DEVICE_CODENAME", priv("getprop ro.product.device"))
save("BUILD_FINGERPRINT", priv("getprop ro.build.fingerprint"))
save("BUILD_ID", priv("getprop ro.build.id"))
save("ANDROID_VERSION", priv("getprop ro.build.version.release"))
save("SECURITY_PATCH", priv("getprop ro.build.version.security_patch"))
save("BOOTLOADER_LOCKED", priv("getprop ro.boot.flash.locked"))
save("VERIFIED_BOOT", priv("getprop ro.boot.verifiedbootstate"))
save("VBMETA_STATE", priv("getprop ro.boot.vbmeta.device_state"))
save("VBMETA_DIGEST", priv("getprop ro.boot.vbmeta.digest"))
save("SECURE_BOOT", priv("getprop ro.boot.secure_boot"))
save("FRP_PARTITION_PATH", priv("getprop ro.frp.pst"))
save("ZUFS_PROVISIONED", priv("getprop ro.boot.zufs_provisioned"))
save("BOOT_REASON_HISTORY",
     priv("getprop persist.sys.boot.reason.history"))
save("BOOT_REASON", priv("getprop ro.boot.bootreason"))
save("SLOT_SUFFIX", priv("getprop ro.boot.slot_suffix"))
save("ALL_BOOT_PROPS", priv("getprop | grep '^\\[ro.boot'"))
save("ALL_PRODUCT_PROPS", priv("getprop | grep '^\\[ro.product'"))

# ── PHASE 3: ENTERPRISE FLAGS ─────────────────
log("PHASE 3: ENTERPRISE FLAGS")
save("ENTERPRISE_MODE",
     priv("getprop ro.setupwizard.enterprise_mode"))
save("SETUP_WIZARD_MODE",
     priv("getprop ro.setupwizard.mode"))
save("ORGANIZATION_OWNED",
     priv("getprop ro.organization_owned"))
save("REMOTE_SIM_SLOT",
     priv("getprop persist.radio.uim.remote.slot"))
save("MULTISIM_CONFIG",
     priv("getprop persist.radio.multisim.config"))
save("ALL_ENTERPRISE_PROPS", priv(
    "getprop | grep -iE "
    "'enterprise|enroll|provision|owner|mdm|dpc|laforge|"
    "zero.touch|organization|setupwizard'"
))
save("ALL_PERSIST_PROPS", priv("getprop | grep '^\\[persist'"))

# ── PHASE 4: PROVISIONING STATE ───────────────
log("PHASE 4: PROVISIONING STATE")
save("DEVICE_PROVISIONED",
     priv("settings get global device_provisioned"))
save("SETUP_WIZARD_RAN",
     priv("settings get global setup_wizard_has_run"))
save("USER_SETUP_COMPLETE",
     priv("settings get secure user_setup_complete"))
save("ENTERPRISE_PRIVACY",
     priv("settings get global enterprise_privacy_initialized"))
save("ENROLLMENT_TOKEN",
     priv("settings get global enrollment_token"))
save("EUICC_PROVISIONED",
     priv("settings get global euicc_provisioned"))
save("ANDROID_ID",
     priv("settings get secure android_id"))
save("ALL_GLOBAL_SETTINGS", priv("settings list global"))
save("ALL_SECURE_SETTINGS", priv("settings list secure"))
save("ALL_SYSTEM_SETTINGS", priv("settings list system"))

# ── PHASE 5: DEVICE POLICY ────────────────────
log("PHASE 5: DEVICE POLICY")
dp = priv("dumpsys device_policy")
save("DEVICE_POLICY_FULL", dp)
extract_and_chase(dp)
save("DEVICE_POLICY_ENTERPRISE", priv(
    "dumpsys device_policy | grep -iE "
    "'laforge|organization|admin|enroll|tenant|domain|owner|"
    "headless|provisioning|isOrganizationOwned|enterprise'"
))
save("ACTIVE_RESTRICTIONS",
     priv("dumpsys device_policy | grep -A3 'Resolved Policy'"))
save("SUSPENSION_LIST",
     priv("dumpsys device_policy | grep -A30 'subject to suspension'"))
save("DPM_LIST_OWNERS", priv("dpm list-owners 2>/dev/null"))

# ── PHASE 6: REPAIR MODE INTERNALS ───────────
log("PHASE 6: REPAIR MODE INTERNALS")
save("REPAIRMODE_PATH",
     priv("pm path com.google.android.repairmode"))
save("REPAIRMODE_DUMPSYS",
     priv("dumpsys activity service com.google.android.repairmode"))
save("REPAIRMODE_SOURCE",
     priv("ls -la /system_ext/app/RepairMode/"))
save("REPAIRMODE_STRINGS", priv(
    "strings /system_ext/app/RepairMode/RepairMode.apk 2>/dev/null "
    "| grep -iE 'https://|enroll|enterprise|org|admin|token|"
    "laforge|domain|server|url|endpoint'"
))
save("REPAIRMODE_DATA",
     priv("ls -laR /data/user/0/com.google.android.repairmode/"))
save("REPAIRMODE_PREFS_LIST", priv(
    "ls /data/user/0/com.google.android.repairmode/shared_prefs/"
))
prefs_rm = priv(
    "ls /data/user/0/com.google.android.repairmode/shared_prefs/"
)
if prefs_rm and 'No such file' not in prefs_rm:
    for pref in prefs_rm.splitlines():
        pref = pref.strip()
        if pref:
            content = priv(
                f"cat /data/user/0/com.google.android.repairmode"
                f"/shared_prefs/{pref}"
            )
            save(f"REPAIRMODE_PREF_{pref}", content)
            extract_and_chase(content)
save("REPAIRMODE_DB_LIST", priv(
    "ls /data/user/0/com.google.android.repairmode/databases/"
))
save("REPAIRMODE_PERMISSIONS", priv(
    "dumpsys package com.google.android.repairmode "
    "| grep -iE 'permission|granted'"
))
save("REPAIRMODE_INTENTS", priv(
    "dumpsys package com.google.android.repairmode "
    "| grep -iE 'action|category|intent|filter'"
))
save("REPAIRMODE_OVERLAY_PATHS", priv(
    "dumpsys package com.google.android.repairmode "
    "| grep -iE 'overlay|resource|frro'"
))

# ── PHASE 7: ACCOUNTS ────────────────────────
log("PHASE 7: ACCOUNTS")
acct = priv("dumpsys account")
save("ACCOUNTS_FULL", acct)
extract_and_chase(acct)
save("ACCOUNTS_ENTERPRISE", priv(
    "dumpsys account | grep -iE "
    "'enterprise|work|managed|domain|org|laforge|enroll'"
))
save("WORK_ACCOUNT_SERVICE", priv(
    "dumpsys activity service "
    "com.google.android.gms/"
    ".auth.account.authenticator.WorkAccountAuthenticatorService"
))

# ── PHASE 8: ESIM AND MODEM ───────────────────
log("PHASE 8: ESIM AND MODEM")
save("EUICC_CONTROLLER", priv("dumpsys euicc_controller"))
save("EUICC_CARD_MGR", priv("dumpsys euicc_card_mgr"))
save("ISUB_FULL", priv("dumpsys isub"))
save("ISUB_ENTERPRISE", priv(
    "dumpsys isub | grep -iE "
    "'esim|euicc|profile|iccid|imsi|enroll|enterprise|embedded|remote'"
))
save("TELEPHONY_REGISTRY", priv("dumpsys telephony.registry"))
save("PHONE_SUBINFO", priv("dumpsys iphonesubinfo"))
save("PHYSICAL_CHANNEL", priv(
    "dumpsys telephony.registry "
    "| grep -iE 'physical|channel|pci|band|earfcn'"
))
save("SLOT0", priv(
    "dumpsys telephony.registry | grep -A30 'Phone=0'"
))
save("SLOT1", priv(
    "dumpsys telephony.registry | grep -A30 'Phone=1'"
))
save("CARRIER_CONFIG", priv("dumpsys carrier_config"))
save("MODEM_ACTIVITY",
     priv("dumpsys modem_activity_info"))
save("CBRS_STATE", priv(
    "dumpsys telephony.registry "
    "| grep -iE 'cbrs|citizen|3550|band48'"
))
save("LAST_PROVISIONING", priv(
    "dumpsys euicc_controller | grep -A5 -iE 'last.*provision|provision.*info'"
))
save("REMOTE_SIM_DETAIL", priv(
    "dumpsys telephony.registry "
    "| grep -iE 'remote|uim|slot.*-1|-1.*slot'"
))

# ── PHASE 9: NETWORK AND VPN ─────────────────
log("PHASE 9: NETWORK AND VPN")
save("VPN_FULL", priv("dumpsys vpn"))
save("ALWAYS_ON_VPN",
     priv("settings get secure always_on_vpn_app"))
save("ALWAYS_ON_LOCKDOWN",
     priv("settings get secure always_on_vpn_lockdown"))
save("NETPOLICY_FULL", priv("dumpsys netpolicy"))
save("CONNECTIVITY_FULL", priv("dumpsys connectivity"))
save("IP_ADDR", priv("ip addr show"))
save("IP_ROUTE", priv("ip route show"))
save("ACTIVE_CONNECTIONS",
     priv("ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null"))
save("DNS_CONFIG",
     priv("getprop | grep -iE 'net.dns|dhcp.*dns'"))
save("WIFI_SSID",
     priv("dumpsys wifi | grep -iE 'ssid|bssid|connect|state'"))
save("VPN_WILDLIFE_PROCESS", priv(
    "dumpsys activity service "
    "com.google.android.apps.privacy.wildlife"
))

# ── PHASE 10: KEYSTORE AND CERTS ─────────────
log("PHASE 10: KEYSTORE AND CERTS")
save("KEYSTORE_LIST", priv("keystore_cli_v2 list 2>/dev/null"))
save("USER_CERTS_ADDED",
     priv("ls -la /data/misc/user/0/cacerts-added/"))
save("USER_CERTS_REMOVED",
     priv("ls -la /data/misc/user/0/cacerts-removed/"))
save("SYSTEM_CERT_COUNT",
     priv("ls /system/etc/security/cacerts/ | wc -l"))
save("WIFI_CERTS",
     priv("ls -la /data/misc/wifi/certs/ 2>/dev/null"))
save("VPN_PROFILES",
     priv("ls -la /data/misc/vpn/ 2>/dev/null"))
save("CREDENTIAL_STORAGE",
     priv("ls -laR /data/misc/keystore/ 2>/dev/null"))

# ── PHASE 11: PARTITIONS ─────────────────────
log("PHASE 11: PARTITIONS")
save("PERSISTENT_DIR", priv("ls -laR /persistent/"))
save("VENDOR_PERSIST", priv("ls -laR /mnt/vendor/persist/"))
save("METADATA_DIR", priv("ls -laR /metadata/"))
save("FRP_RAW",
     priv("cat /dev/block/by-name/frp 2>/dev/null | strings | head -100"))
save("FRP_HEXDUMP",
     priv("xxd /dev/block/by-name/frp 2>/dev/null | head -50"))
save("PRODUCT_APP_LIST",
     priv("ls -la /product/app/"))
save("SYSTEM_EXT_APP_LIST",
     priv("ls -la /system_ext/app/"))
save("PRIV_APP_LIST",
     priv("ls -la /system/priv-app/"))
save("ROLLBACK_DATA",
     priv("ls -laR /data/rollback/"))
save("STAGED_INSTALLS",
     priv("ls -laR /data/staged-installs/"))
save("OTA_PACKAGE",
     priv("ls -la /data/ota_package/"))
save("METADATA_VOLD",
     priv("ls -la /metadata/vold/"))

# ── PHASE 12: GSERVICES AND LAFORGE ──────────
log("PHASE 12: GSERVICES AND LAFORGE")
gservices = priv(
    "content query "
    "--uri content://com.google.android.gsf.gservices/main "
    "--projection name:value 2>/dev/null | grep -iE "
    "'enterprise|enroll|mdm|dpc|owner|provision|zero.touch|"
    "laforge|checkin|device_management|android_id|gcm'"
)
save("GSERVICES_ENTERPRISE", gservices)
extract_and_chase(gservices)
save("GSERVICES_ALL", priv(
    "content query "
    "--uri content://com.google.android.gsf.gservices/main "
    "--projection name:value 2>/dev/null"
))
save("GMS_CHECKIN", priv(
    "dumpsys activity service "
    "com.google.android.gms/.checkin.CheckinService"
))

# ── PHASE 13: LOGCAT ─────────────────────────
log("PHASE 13: LOGCAT")
for label, grep in [
    ("ENTERPRISE",
     "'enterprise|enroll|provision|owner|dpc|laforge|"
     "zero.touch|repairmode|clouddpc|setupwizard'"),
    ("MDM",
     "'mdm|device.policy|devicepolicy|DevicePolicyManager|"
     "DeviceAdmin|device_admin'"),
    ("ESIM",
     "'euicc|esim|profile|iccid|embedded|eUICC'"),
    ("VPN",
     "'vpn|wildlife|tunnel|always.on|WildlifeVpn'"),
    ("MODEM",
     "'modem|baseband|ril|RIL|telephony|cbrs|CBRS'"),
    ("BOOT",
     "'boot|provision|setup|wizard|factory.reset|frp'"),
]:
    save(f"LOGCAT_{label}", priv(
        f"logcat -d | grep -iE {grep} | tail -500",
        timeout=30
    ))

# ── PHASE 14: FIREBASE ───────────────────────
log("PHASE 14: FIREBASE")
fb = "https://com-android-cloud-policy.firebaseio.com"
save("FIREBASE_ROOT", curl(f"{fb}/.json"))
for path in [
    "enrollment","devices","policy","admin","config",
    "enterprise","owner","token","users","orgs",
    "organizations","tenants","management","dpc","mdm"
]:
    r = curl(f"{fb}/{path}.json")
    save(f"FIREBASE_{path.upper()}", r)
    if r and 'permission' not in r.lower() and r != 'null':
        extract_and_chase(r)

# ── PHASE 15: PACKAGE CHASE ──────────────────
log("PHASE 15: PACKAGE CHASE")
for pkg in [
    "com.google.android.apps.work.clouddpc",
    "com.google.android.apps.work.oobconfig",
    "com.google.android.repairmode",
    "com.google.android.gms",
    "com.google.android.setupwizard",
    "com.google.android.apps.work.profile",
]:
    chase_pkg(pkg)

# ── PHASE 16: RECURSIVE CHASE ────────────────
log("PHASE 16: RECURSIVE CHASE")
while chase_queue:
    pkg = chase_queue.pop(0)
    if pkg not in visited:
        log(f"RECURSIVE: {pkg}")
        chase_pkg(pkg)

# ── PHASE 17: WHAT SURVIVES REPAIR EXIT ──────
log("PHASE 17: POST-REPAIR PERSISTENCE PROBE")
save("REPAIR_EXIT_POLICY", priv(
    "dumpsys device_policy | grep -iE "
    "'exit|restore|transfer|after|complete|cleanup|wipe|pending'"
))
save("PENDING_SYSTEM_UPDATE", priv(
    "dumpsys device_policy | grep -A5 'Pending System Update'"
))
save("NO_FACTORY_RESET_ENFORCED", priv(
    "dumpsys device_policy | grep -A5 'no_factory_reset'"
))
save("WHAT_REPAIRMODE_PREFS_SAY", priv(
    "cat /data/user/0/com.google.android.repairmode/shared_prefs/*.xml "
    "2>/dev/null"
))
save("SETUPWIZARD_DATA", priv(
    "ls -laR /data/user/0/com.google.android.setupwizard/ 2>/dev/null"
))
save("SETUPWIZARD_PREFS", priv(
    "ls /data/user/0/com.google.android.setupwizard/shared_prefs/ "
    "2>/dev/null"
))
swprefs = priv(
    "ls /data/user/0/com.google.android.setupwizard/shared_prefs/ 2>/dev/null"
)
if swprefs and 'No such file' not in swprefs:
    for pref in swprefs.splitlines():
        pref = pref.strip()
        if pref:
            content = priv(
                f"cat /data/user/0/com.google.android.setupwizard"
                f"/shared_prefs/{pref} 2>/dev/null"
            )
            save(f"SETUPWIZARD_PREF_{pref}", content)
            extract_and_chase(content)

# ── PHASE 18: SYNTHESIS ──────────────────────
log("PHASE 18: SYNTHESIS")
findings = {
    "device": {
        "model": evidence.get("MODEL",""),
        "serial": evidence.get("SERIAL",""),
        "build": evidence.get("BUILD_FINGERPRINT",""),
        "bootloader_locked": evidence.get("BOOTLOADER_LOCKED",""),
        "verified_boot": evidence.get("VERIFIED_BOOT",""),
        "boot_history": evidence.get("BOOT_REASON_HISTORY",""),
        "security_patch": evidence.get("SECURITY_PATCH",""),
    },
    "enterprise": {
        "enterprise_mode_flag": evidence.get("ENTERPRISE_MODE",""),
        "organization_owned": evidence.get("ORGANIZATION_OWNED",""),
        "setup_wizard_mode": evidence.get("SETUP_WIZARD_MODE",""),
        "remote_sim_slot": evidence.get("REMOTE_SIM_SLOT",""),
        "euicc_provisioned": evidence.get("EUICC_PROVISIONED",""),
        "enrollment_token": evidence.get("ENROLLMENT_TOKEN",""),
        "enterprise_privacy": evidence.get("ENTERPRISE_PRIVACY",""),
        "android_id": evidence.get("ANDROID_ID",""),
    },
    "esim": {
        "last_provisioning": evidence.get("LAST_PROVISIONING",""),
        "slot1": evidence.get("SLOT1","")[:500],
        "cbrs": evidence.get("CBRS_STATE",""),
    },
    "network": {
        "always_on_vpn": evidence.get("ALWAYS_ON_VPN",""),
        "connections": evidence.get("ACTIVE_CONNECTIONS","")[:500],
        "routes": evidence.get("IP_ROUTE",""),
        "dns": evidence.get("DNS_CONFIG",""),
    },
    "certs": {
        "added": evidence.get("USER_CERTS_ADDED",""),
        "removed": evidence.get("USER_CERTS_REMOVED",""),
        "count": evidence.get("SYSTEM_CERT_COUNT",""),
    },
    "emails": [v for k,v in evidence.items() if k.startswith("EMAIL_")],
    "tokens": [v for k,v in evidence.items() if k.startswith("TOKEN_")],
    "urls_chased": [k for k in evidence if k.startswith("URL_")],
    "firebase": {
        k:v for k,v in evidence.items()
        if k.startswith("FIREBASE_")
        and "permission" not in str(v).lower()
        and v not in ["null","[EMPTY]"]
    },
    "packages_chased": list(visited),
    "frp_content": evidence.get("FRP_RAW",""),
    "repair_prefs": {
        k:v for k,v in evidence.items()
        if k.startswith("REPAIRMODE_PREF_")
    },
    "setupwizard_prefs": {
        k:v for k,v in evidence.items()
        if k.startswith("SETUPWIZARD_PREF_")
    },
}
save("SYNTHESIS", json.dumps(findings, indent=2))

log(f"BARN BUILT.")
log(f"Evidence : {OUT}")
log(f"JSON     : {JSON_OUT}")
log(f"Log      : {LOG}")
print(f"\n[DONE]\nEvidence : {OUT}\nJSON     : {JSON_OUT}\nLog      : {LOG}")
