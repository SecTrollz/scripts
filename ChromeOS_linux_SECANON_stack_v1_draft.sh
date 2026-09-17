#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# ChromeOS_linux_SECANON_stack_v1_draft.sh — superseded draft,
# kept only as a forwarding shim.
#
# This was an earlier draft of the same PIN/FIDO2-gated, cert-
# generating SECANON stack: it cut off mid-function at line 345
# (`bash -n` failed with "unexpected end of file"), before the
# package-install, service-start, or watchdog phases were ever
# written. ChromeOS_LINUX_SECANON_stack_v2.sh is the complete,
# "production hardened" version of this exact idea, so rather than
# guess at the missing back half, this file now just forwards to
# it — anything that still calls the v1 draft by name gets the
# real, finished stack instead of a syntax error.
# ============================================================
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
exec "$HERE/ChromeOS_LINUX_SECANON_stack_v2.sh" "$@"
