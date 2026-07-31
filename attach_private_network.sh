#!/bin/bash
# attach_private_network.sh
#
# Forces a modem to deregister from auto-selection and attach to a
# specific PLMN (private/test network) over its AT command port, then
# reports registration and signal status.
#
# Usage:
#   ./attach_private_network.sh [PLMN] [AT_PORT]
#
#   PLMN     - target PLMN id passed to AT+COPS (default: 103824)
#   AT_PORT  - modem AT command tty (default: /dev/pts/1)

set -euo pipefail

PLMN="${1:-103824}"
AT_PORT="${2:-/dev/pts/1}"

if [ ! -c "$AT_PORT" ] && [ ! -p "$AT_PORT" ]; then
  echo "AT port not found: $AT_PORT" >&2
  exit 1
fi

su -c "sh -c '
exec 3<>\"$AT_PORT\"

echo \"Disabling auto-registration...\"
echo \"AT+CREG=0\" >&3
sleep 1

echo \"Forcing 2G/3G/LTE scan...\"
echo \"AT+COPS=1,2,\\\"$PLMN\\\"\" >&3
sleep 3

echo \"Checking registration...\"
echo \"AT+CREG?\" >&3
sleep 1

echo \"Checking data registration...\"
echo \"AT+CGREG?\" >&3
sleep 1

echo \"Signal strength...\"
echo \"AT+CSQ\" >&3
sleep 1

exec 3>&-
'"
