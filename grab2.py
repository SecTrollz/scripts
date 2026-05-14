#!/usr/bin/env python3
import subprocess, os, json, time, re, sys
from datetime import datetime

TS = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT = os.path.expanduser(f"~/amish_evidence_{TS}.txt")
LOG = os.path.expanduser(f"~/amish_chase_{TS}.log")
JSON_OUT = os.path.expanduser(f"~/amish_evidence_{TS}.json")

evidence = {}
chase_queue = []
visited = set()

def log(msg):
    print(f"[AMISH] {msg}")
    with open(LOG, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def shell(cmd):
    try:
        result = subprocess.run(
            ["adb", "shell", cmd],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def local(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def save(section, data):
    evidence[section] = data
    with open(OUT, "a") as f:
        f.write(f"\n{'='*60}\n=== {section} ===\n{'='*60}\n{data}\n")
    with open(JSON_OUT, "w") as f:
        json.dump(evidence, f, indent=2)

def chase(pkg):
    if pkg in visited:
        return
    visited.add(pkg)
    log(f"CHASING PACKAGE: {pkg}")

    save(f"PKG_DETAIL_{pkg}", shell(f"dumpsys package {pkg}"))
    save(f"PKG_PATH_{pkg}", shell(f"pm path {pkg}"))
    save(f"PKG_PERMISSIONS_{pkg}", shell(f"dumpsys package {pkg} | grep -iE 'permission|granted|requested'"))
    save(f"PKG_RECEIVERS_{pkg}", shell(f"dumpsys package {pkg} | grep -iE 'receiver|service|activity|provider'"))
    save(f"PKG_DATA_{pkg}", shell(f"ls -laR /data/user/0/{pkg}/ 2>/dev/null"))
    save(f"PKG_PREFS_{pkg}", shell(f"ls -la /data/user/0/{pkg}/shared_prefs/ 2>/dev/null"))
    save(f"PKG_DB_{pkg}", shell(f"ls -la /data/user/0/{pkg}/databases/ 2>/dev/null"))
    save(f"PKG_CACHE_{pkg}", shell(f"ls -la /data/user/0/{pkg}/cache/ 2>/dev/null"))
    save(f"PKG_FILES_{pkg}", shell(f"ls -la /data/user/0/{pkg}/files/ 2>/dev/null"))

    prefs_list = shell(f"ls /data/user/0/{pkg}/shared_prefs/ 2>/dev/null")
    for pref in prefs_list.splitlines():
        if pref.strip():
            pref = pref.strip()
            content = shell(f"cat /data/user/0/{pkg}/shared_prefs/{pref} 2>/dev/null")
            save(f"PREF_CONTENT_{pkg}_{pref}", content)
            extract_and_chase(content)

    db_list = shell(f"ls /data/user/0/{pkg}/databases/ 2>/dev/null")
    for db in db_list.splitlines():
        if db.strip() and not db.endswith("-journal") and not db.endswith("-wal"):
            db = db.strip()
            content = shell(f"sqlite3 /data/user/0/{pkg}/databases/{db} .dump 2>/dev/null")
            save(f"DB_DUMP_{pkg}_{db}", content)
            extract_and_chase(content)

def extract_and_chase(text):
    if not text:
        return

    packages = re.findall(r'com\.[a-zA-Z0-9_.]+', text)
    for pkg in set(packages):
        if pkg not in visited and len(pkg) > 10:
            interesting = any(kw in pkg.lower() for kw in [
                'work', 'enterprise', 'mdm', 'dpc', 'policy',
                'enroll', 'manage', 'admin', 'repair', 'oob',
                'provision', 'setup', 'gms', 'laforge'
            ])
            if interesting:
                chase_queue.append(pkg)

    urls = re.findall(r'https?://[^\s\'"<>]+', text)
    for url in set(urls):
        if url not in visited:
            visited.add(url)
            log(f"FOUND URL: {url}")
            save(f"URL_HIT_{url[:80]}", local(f"curl -sk --max-time 5 '{url}'"))

    tokens = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
    for token in set(tokens):
        save(f"TOKEN_FOUND", token)

    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    for email in set(emails):
        log(f"EMAIL FOUND: {email}")
        save(f"EMAIL_FOUND", email)

    domains = re.findall(r'[a-zA-Z0-9.-]+\.(google|firebase|googleapis|android|gstatic)\.com', text)
    for domain in set(domains):
        log(f"DOMAIN FOUND: {domain}")
        result = local(f"curl -sk --max-time 5 'https://{domain}/.json' 2>/dev/null")
        save(f"DOMAIN_HIT_{domain}", result)

log("AMISH POWER ACTIVATED. BUILDING THE BARN.")

log("PHASE 1: DEVICE IDENTITY")
save("IMEI_INFO", shell("service call iphonesubinfo 1 | grep -o \"'[^']*'\" | sed \"s/'//g\" | tr -d ' \n'"))
save("DEVICE_PROPS", shell("getprop | grep -iE 'ro.serial|ro.build|ro.product|ro.boot|ro.hardware'"))
save("ORGANIZATION_OWNED", shell("getprop ro.organization_owned"))
save("SETUP_WIZARD_MODE", shell("getprop ro.setupwizard.mode"))
save("FRP_STATE", shell("getprop ro.frp.pst"))
save("BOOTLOADER", shell("getprop ro.boot.flash.locked"))
save("VERIFIED_BOOT", shell("getprop ro.boot.verifiedbootstate"))
save("ALL_PERSIST_PROPS", shell("getprop | grep '^\\[persist'"))
save("ALL_RO_ENTERPRISE", shell("getprop | grep -iE 'enterprise|enroll|provision|owner|mdm|dpc|laforge|zero.touch|organization'"))

log("PHASE 2: PROVISIONING STATE")
save("DEVICE_PROVISIONED", shell("settings get global device_provisioned"))
save("SETUP_WIZARD_RAN", shell("settings get global setup_wizard_has_run"))
save("USER_SETUP_COMPLETE", shell("settings get secure user_setup_complete"))
save("ENTERPRISE_PRIVACY", shell("settings get global enterprise_privacy_initialized"))
save("ENROLLMENT_TOKEN", shell("settings get global enrollment_token"))
save("ALL_GLOBAL_ENTERPRISE", shell("settings list global | grep -iE 'enterprise|enroll|provision|owner|mdm|dpc|policy|manage|zero|touch|laforge'"))
save("ALL_SECURE_ENTERPRISE", shell("settings list secure | grep -iE 'enterprise|enroll|provision|owner|mdm|dpc|policy|manage|zero|touch|laforge'"))

log("PHASE 3: DEVICE POLICY FULL MAP")
dp_dump = shell("dumpsys device_policy")
save("DEVICE_POLICY_FULL", dp_dump)
extract_and_chase(dp_dump)

log("PHASE 4: ACCOUNTS")
acct_dump = shell("dumpsys account")
save("ACCOUNTS_FULL", acct_dump)
extract_and_chase(acct_dump)
save("WORK_ACCOUNT_SERVICE", shell("dumpsys activity service com.google.android.gms/.auth.account.authenticator.WorkAccountAuthenticatorService"))

log("PHASE 5: ESIM AND MODEM")
save("EUICC_CONTROLLER", shell("dumpsys euicc_controller 2>/dev/null"))
save("EUICC_CARD_MGR", shell("dumpsys euicc_card_mgr 2>/dev/null"))
save("ISUB_ENTERPRISE", shell("dumpsys isub | grep -iE 'esim|euicc|profile|iccid|imsi|enroll|enterprise|embedded'"))
save("TELEPHONY_REGISTRY", shell("dumpsys telephony.registry"))
save("IPHONESUBINFO", shell("dumpsys iphonesubinfo"))
save("SECOND_SLOT", shell("dumpsys telephony.registry | grep -iE 'slot|sim|imsi|iccid|state'"))

log("PHASE 6: NETWORK AND VPN")
save("VPN_FULL", shell("dumpsys vpn"))
save("ALWAYS_ON_VPN", shell("settings get secure always_on_vpn_app"))
save("ALWAYS_ON_LOCKDOWN", shell("settings get secure always_on_vpn_lockdown"))
save("NETPOLICY_ENTERPRISE", shell("dumpsys netpolicy | grep -iE 'owner|enterprise|manage|restrict|vpn|always'"))
save("CONNECTIVITY_ENTERPRISE", shell("dumpsys connectivity | grep -iE 'vpn|enterprise|manage|restrict|always'"))

log("PHASE 7: KEYSTORE AND CERTS")
save("KEYSTORE_KEYS", shell("keystore_cli_v2 list 2>/dev/null"))
save("USER_CERTS_ADDED", shell("ls -la /data/misc/user/0/cacerts-added/ 2>/dev/null"))
save("USER_CERTS_REMOVED", shell("ls -la /data/misc/user/0/cacerts-removed/ 2>/dev/null"))
save("SYSTEM_CA_STORE", shell("ls /system/etc/security/cacerts/ 2>/dev/null | wc -l"))

log("PHASE 8: PARTITIONS")
save("PERSISTENT_DIR", shell("ls -laR /persistent/ 2>/dev/null"))
save("VENDOR_PERSIST", shell("ls -laR /mnt/vendor/persist/ 2>/dev/null"))
save("METADATA_DIR", shell("ls -laR /metadata/ 2>/dev/null"))
save("PRODUCT_APP_DPC", shell("ls -la /product/app/ | grep -iE 'policy|dpc|device|repair|enroll|work|cloud|oob'"))
save("SYSTEM_EXT_DPC", shell("ls -la /system_ext/app/ | grep -iE 'policy|dpc|device|repair|enroll|work|cloud|oob'"))

log("PHASE 9: GSERVICES AND LAFORGE")
gservices = shell("content query --uri content://com.google.android.gsf.gservices/main --projection name:value 2>/dev/null | grep -iE 'enterprise|enroll|mdm|dpc|owner|provision|zero.touch|laforge|checkin|device_management'")
save("GSERVICES_ENTERPRISE", gservices)
extract_and_chase(gservices)

save("GMS_CHECKIN", shell("dumpsys activity service com.google.android.gms/.checkin.CheckinService 2>/dev/null | grep -iE 'enroll|enterprise|owner|laforge|provision|token'"))

log("PHASE 10: LOGCAT HISTORY")
save("LOGCAT_ENTERPRISE", shell("logcat -d | grep -iE 'enterprise|enroll|provision|owner|dpc|laforge|zero.touch|repairmode|clouddpc' | tail -300"))
save("LOGCAT_MDM", shell("logcat -d -b all | grep -iE 'mdm|device.policy|devicepolicy|DevicePolicyManager' | tail -300"))
save("LOGCAT_ESIM", shell("logcat -d | grep -iE 'euicc|esim|profile|iccid|embedded' | tail -100"))
save("LOGCAT_VPN", shell("logcat -d | grep -iE 'vpn|wildlife|tunnel|always.on' | tail -100"))

log("PHASE 11: FIREBASE CHECK")
firebase_result = local("curl -sk --max-time 5 'https://com-android-cloud-policy.firebaseio.com/.json'")
save("FIREBASE_ROOT", firebase_result)
firebase_paths = ["enrollment", "devices", "policy", "admin", "config", "enterprise", "owner", "token"]
for path in firebase_paths:
    result = local(f"curl -sk --max-time 5 'https://com-android-cloud-policy.firebaseio.com/{path}.json'")
    save(f"FIREBASE_{path.upper()}", result)
    if "permission" not in result.lower() and result != "null":
        extract_and_chase(result)

log("PHASE 12: CHASE ALL ENTERPRISE PACKAGES")
enterprise_pkgs = [
    "com.google.android.apps.work.clouddpc",
    "com.google.android.apps.work.oobconfig",
    "com.google.android.repairmode",
    "com.google.android.gms",
    "com.google.android.apps.work.profile",
]
for pkg in enterprise_pkgs:
    chase(pkg)

log("PHASE 13: RECURSIVE CHASE QUEUE")
while chase_queue:
    pkg = chase_queue.pop(0)
    if pkg not in visited:
        log(f"RECURSIVE CHASE: {pkg}")
        chase(pkg)

log("PHASE 14: SYNTHESIZE FINDINGS")
findings = {
    "organization_owned": evidence.get("ORGANIZATION_OWNED", ""),
    "setup_wizard_mode": evidence.get("SETUP_WIZARD_MODE", ""),
    "enrollment_token": evidence.get("ENROLLMENT_TOKEN", ""),
    "always_on_vpn": evidence.get("ALWAYS_ON_VPN", ""),
    "device_provisioned": evidence.get("DEVICE_PROVISIONED", ""),
    "emails_found": [v for k,v in evidence.items() if "EMAIL" in k],
    "urls_found": [k.replace("URL_HIT_","") for k in evidence.keys() if "URL_HIT" in k],
    "tokens_found": [v for k,v in evidence.items() if "TOKEN" in k],
    "firebase_results": {k:v for k,v in evidence.items() if "FIREBASE" in k and "null" not in v and "Permission" not in v},
}

save("SYNTHESIS", json.dumps(findings, indent=2))

log(f"BARN IS BUILT. Evidence: {OUT}")
log(f"JSON map: {JSON_OUT}")
log(f"Chase log: {LOG}")
print(f"\n[AMISH COMPLETE]\nEvidence: {OUT}\nJSON: {JSON_OUT}\nLog: {LOG}")
