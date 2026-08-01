# scripts

### USE AT YOUR OWN RISK (;

A grab-bag of personal tooling: Android/ADB device forensics, OCI deploy automation, Replit-to-GitHub migration, and a blackjack "provably fair" audit pair. Filenames were renamed for consistency (see [Renamed](#renamed-for-consistency) below) — nothing was rewritten beyond the one bugfix noted in the table.

🟢 = ran a syntax/lint pass, logic checked out, good to go (still read the per-script must-knows before running — several require a real device, cloud account, or API key to do anything).
🔴 = has a reproducible bug.

## Android / ADB device investigation

Host-side tools drive a phone over `adb`; the Termux-flagged ones run **on** the phone instead.

| Status | Script | Platform | What it does |
|---|---|---|---|
| 🟢 | `detect_hidden_root.sh` | Android (on-device, via `adb shell`) | Pushed to `/data/local/tmp` and run on the phone. Checks for `su` binaries, inspects the Zygote process, greps for MDM-flavored system services, checks if `/system` is writable, and checks ADB root status. Read-only. |
| 🟢 | `enrollment_evidence_quick.sh` *(was `grab.sh`)* | Linux/macOS host, drives phone via `adb` | One-shot dump of device-policy, account, and eSIM enrollment state into a timestamped `~/evidence_*.txt`. The minimal seed version of `enrollment_evidence_deep.py`. |
| 🟢 | `enrollment_evidence_deep.py` *(was `grab2.py`)* | Linux/macOS host, drives phone via `adb` | 14-phase enterprise-enrollment evidence collector. Recursively "chases" any package name, URL, token, or email it finds in one dump into further dumps, so it self-expands its own scope. Never deletes/modifies device state — writes `.txt`/`.json`/log evidence files only. |
| 🟢 | `repairmode_evidence_adb.py` *(was `repair.py`)* | Linux/macOS host, drives phone via `adb` | Same recursive-chase design as `enrollment_evidence_deep.py`, expanded to 18 phases: adds bootloader/verified-boot state, FRP partition dump, repair-mode APK internals, and a "what survives repair-mode exit" probe. |
| 🟢 | `repairmode_evidence_termux.py` *(was `right2repair.py`)* | **On-device**, Termux + `rish` (Shizuku) | Same 18-phase evidence collector as `repairmode_evidence_adb.py`, but runs directly on the phone using `rish` for privileged shell instead of driving it over `adb` from a second machine. |
| 🟢 | `adb_cache_purge.sh` | Linux/macOS host, drives phone via `adb` | Measures per-app cache via `du`, supports `--dry-run`/`--force`, escalates through `pm trim-caches` → `adb root` → `su`-based cleanup (each gated by an actual capability check), then verifies bytes actually freed. |
| 🟢 | `lan_sigint_scanner.py` *(was `Sigint_v2.py`)* | **On-device**, Termux (Pydroid3 works in a degraded mode) | Flask web UI (`localhost:8747`) for LAN asset discovery: TCP/ICMP sweep, ARP, mDNS (TXT/SRV parsing for real model names), SSDP, optional WiFi RSSI + Bluetooth. SQLite sighting history with proximity trend. Runs a real functional preflight per Termux capability (not just `which`) and tells you exactly which permission/APK is missing. |

## Cloud provisioning (Oracle Cloud Infrastructure)

| Status | Script | Platform | What it does |
|---|---|---|---|
| 🟢 | `oci_fips_node_launch.sh` *(was `oci_1liner.sh`)* | Linux/macOS/WSL, needs `oci` CLI configured | Single chained command: generates an SSH key if missing, resolves compartment/subnet/AD/image OCIDs, launches an ARM `A1.Flex` Always-Free instance with a FIPS-hardened, sysctl-hardened, Docker-ready cloud-init payload. |
| 🟢 | `deploy_ironring_v2.sh` *(was `deploy_ironring.sh`)* | Linux/macOS/WSL, needs `oci` CLI configured | Multi-instance OCI deploy (n8n+Traefik, plain Ubuntu node, WireGuard netstack box) across dual public/private NSGs. Superseded by v3 below — kept for reference. |
| 🟢 | `deploy_ironring_v3.sh` | Linux/macOS/WSL, needs `oci` CLI configured | Full rewrite of v2 into a staged, idempotent reconciler: every resource is lookup-or-create, OCIDs persist to a state file so re-runs skip finished work, a lockfile blocks concurrent runs, and it ends with a real SSH/HTTP/HTTPS/WireGuard verification pass. This is the one to run. |

Both deploy scripts ship with placeholder values (tenancy OCID, domain, email) that must be set via env vars (v3) or in-file edits (v2) before running.

## Replit → local/GitHub migration

| Status | Script | Platform | What it does |
|---|---|---|---|
| 🟢 | `replit_bloat_cleaner.py` *(was `CleanReplitBloat.py`)* | Cross-platform Python (needs `requests`, `send2trash`) | Walks a directory for bloat patterns, groups matches, and asks the DeepSeek API to explain each group before an interactive delete/keep prompt. Deletes go through `send2trash` (recoverable). Needs `DEEPSEEK_API_KEY`. |
| 🟢 | `replit_to_github.py` | Cross-platform Python | Strips Replit lock-in files, rewrites hardcoded `*.repl.co`/env-var references, scaffolds missing Android/Node/Python configs, then creates/pushes a GitHub repo via raw `urllib`. Has an optional raw-socket "DNS patch" mode for broken `api.github.com` resolution — off by default. Token-auth push writes the token to a temp-file `GIT_ASKPASS` shim (chmod 700, but touches disk). |
| 🟢 (fixed) | `replit_to_github_hardening_patch.py` *(was `replit_shitstorm.py`)* | Cross-platform Python | A hardening patch layered on top of `replit_to_github.py` (imports from it directly — keep both files together). Fixes: token-free credential-helper push, no `shell=True`, interactive project-root disambiguation, dry-run preview. **Was broken:** `dry_run_cleanup()` called `re.search()` without importing `re`, so choosing dry-run crashed with `NameError` every time. Fixed by adding the missing import. |
| 🟢 | `dns_intrusion_hunter.py` *(was `volcano_github_uploader.py`)* | Cross-platform Python (needs `requests`; has Windows/macOS/Linux process-scan branches) | Resolves a suspicious domain, pulls matching logs from the NextDNS API, greps the filesystem and running processes for references to it, **copies (never deletes)** hits into quarantine, writes a forensic report, and uploads report + quarantine to GitHub. `SUSPICIOUS_DOMAINS` is a placeholder (`malware.example`) — edit before running, and expect the full-filesystem scan to be slow. |

## Blackjack "provably fair" audit pair

| Status | Script | Platform | What it does |
|---|---|---|---|
| 🟢 | `blackjack-advisor.user.js` | Browser userscript (Tampermonkey/Violentmonkey), tuned for Firefox for Android | Glassmorphism overlay: reads the table via DOM heuristics or a pasted site-adapter plugin, tracks Hi-Lo count, shows basic-strategy + count-based deviations and Kelly bet sizing, plus a "provably fair" audit panel. Advisory only — never clicks buttons or sets bet fields. Domain-gated with a per-hostname confirmation prompt. |
| 🟢 | `blackjack-audit-server.js` | Node.js (no dependencies) | Companion to the userscript, binds `127.0.0.1:9999`. Recomputes a casino's committed HMAC-SHA256 + Fisher-Yates shuffle independently of the casino's own verify page. CORS is intentionally wide open since it can't know the casino origin in advance — stop it (Ctrl+C) when you're done auditing. |

## Non-script files (not renamed — not scripts)

- `ReplitExport-rljnunez.tar.gz` — a Replit project export bundle (a `Secure-Script-Runner` git repo), the kind of input `replit_to_github.py` / `replit_bloat_cleaner.py` process.
- `privacy-stack.zip` — a self-hosted privacy-stack Docker-Compose kit (Traefik+Authelia, WireGuard, dnscrypt-proxy, Tor, i2p, Portainer) with its own `setup.sh`.
- `LICENSE`

## Renamed for consistency

Everything is now `snake_case.ext` (the two userscript/Node files were already fine and left untouched). If you have anything — aliases, cron jobs, notes — pointing at the old names, update them:

| Old name | New name |
|---|---|
| `adb-cache-purge.sh` | `adb_cache_purge.sh` |
| `CleanReplitBloat.py` | `replit_bloat_cleaner.py` |
| `Sigint_v2.py` | `lan_sigint_scanner.py` |
| `deploy_ironring.sh` | `deploy_ironring_v2.sh` |
| `grab.sh` | `enrollment_evidence_quick.sh` |
| `grab2.py` | `enrollment_evidence_deep.py` |
| `oci_1liner.sh` | `oci_fips_node_launch.sh` |
| `repair.py` | `repairmode_evidence_adb.py` |
| `replit_shitstorm.py` | `replit_to_github_hardening_patch.py` |
| `right2repair.py` | `repairmode_evidence_termux.py` |
| `volcano_github_uploader.py` | `dns_intrusion_hunter.py` |
