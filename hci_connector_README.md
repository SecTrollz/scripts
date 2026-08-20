# hci_connector.py

A raw-HCI Bluetooth reconnect stress tester. Talks straight to a local
Bluetooth controller over a kernel HCI socket - no BlueZ D-Bus API, no
`bluetoothctl`, no subprocess calls to other tools. It's built for
exercising a device's (or fleet's) reconnect handling under repeated,
correctly-formed connection attempts, either against a fixed list of
known addresses or by discovering live targets on the fly.

## Requirements

- Linux with a Bluetooth controller and kernel HCI socket support
  (`AF_BLUETOOTH` / `BTPROTO_HCI`). Works under Termux on rooted Android
  the same way it works on any other Linux host.
- **Root, or `CAP_NET_RAW`** - raw HCI sockets require it. Run as root
  or grant the capability (`setcap cap_net_raw+ep $(which python3)`,
  though granting it to the whole interpreter is broad - prefer running
  the script itself with elevated privileges instead if you can).
- Python 3, standard library only. No pip dependencies.

## How it works

One physical controller can only run one `Create Connection` (classic)
or `LE Create Connection` procedure at a time - the radio doesn't
actually support parallel connection attempts, regardless of how many
threads you throw at it. So this script doesn't pretend to: it queues
attempts and runs them one at a time on a single socket, which gives you
honest throughput and success-rate numbers instead of a pile of hidden
"Command Disallowed" rejections from a thread pool fighting itself.

Each attempt:
1. Sends `Create Connection` (or `LE Create Connection` with `--le`).
2. Waits for `Command Status`, matched by opcode.
3. Waits for `Connection Complete` (or the LE Meta Event's Connection
   Complete subevent), matched by peer address.
4. On success, sends a real `Disconnect` and waits for `Disconnect
   Complete` before moving on - it doesn't just close the local socket
   and leave the baseband link up.

Retries and inter-attempt delay use adaptive backoff: the delay grows on
consecutive failures and shrinks back down once attempts start
succeeding again, bounded by `--min-delay`/`--max-delay`.

## Two ways to pick targets

**Static list** (default): put one MAC per line in a file (`devices.txt`
by default, or `-f/--file`) and the script attempts reconnects against
exactly that list, `--rounds` times.

**Live discovery** (`--discover`): for targets whose address rotates or
changes during the test (e.g. simulated/emulated peripherals, or real
BLE devices using random resolvable addresses), a short scan burst runs
before each round on the same socket - classic `Inquiry` normally, or LE
scanning with `--le` - and the round targets whatever's currently live.
Three knobs control how this tracks a moving target:

- `--scan-window` - how long each scan burst runs before a round. Set it
  shorter than however often your targets' identifiers change, so you
  never go a full round without a fresh read.
- `--ttl` - how long a discovered identifier is considered "live" after
  last being seen. Once it expires, the script stops chasing it.
- `--allow-prefix AA:BB:CC` (repeatable) - restrict discovery to known
  address prefixes (OUIs). Without this, a scan picks up *every* nearby
  device that answers, not just your targets - use this to scope
  discovery to hardware you're actually testing.

## Classic BR/EDR vs. LE

Most modern peripherals - wearables, sensors, beacons, most IoT hardware
- are Bluetooth LE only and won't respond to classic `Create Connection`
at all. Pass `--le` to switch the whole tool (both discovery and
connects) to the LE equivalents. Without `--le`, it speaks classic
BR/EDR, matching hardware that still uses the "page scan" style
connection flow.

One LE-specific note: `Create Connection` needs the correct
public-vs-random address type for a peer, or the controller will reject
it. In `--discover` mode this is learned automatically from the scan. In
static-list mode there's no way to specify it from a plain MAC list, so
it defaults to public (`0x00`) - if your targets use random addresses,
use `--discover` instead of a static file.

**Heads up on LE advertising report parsing**: the LE Advertising Report
event uses a parallel-array wire format (all address types together,
then all addresses together, etc. - not per-device chunks), which is
implemented here per the Core Spec but hasn't been validated against a
real capture. If `--le --discover` doesn't pick up devices you can see
with `bluetoothctl` or a phone, that parsing is the first place to check
- ideally with a packet capture (`btmon`) to compare against.

## Usage examples

Fixed list, classic BT, 50 reconnect rounds:
```
python3 hci_connector.py -f devices.txt -d 0 --rounds 50 -t 5 -v
```

Live discovery, classic BT, scoped to a known OUI, rotating identifiers:
```
python3 hci_connector.py -d 0 --discover --allow-prefix 28:CD:C1 \
    --ttl 15 --scan-window 3 --rounds 100 -t 5 -v
```

LE peripheral with a fixed public address:
```
python3 hci_connector.py -f devices.txt --le -d 0 --rounds 50 -t 5 -v
```

LE with rotating random addresses, discovered live:
```
python3 hci_connector.py --le --discover --allow-prefix DE:AD:BE \
    --ttl 20 --scan-window 4 --rounds 100 -t 8 -v
```

## Intended use

This is a reconnect/load-testing tool for Bluetooth hardware you own or
are authorized to test - a bench rig, a fleet of devices under your
control, or similar. It actively scans for and connects to real
Bluetooth devices; point it only at things you have permission to
connect to.

## Output

At the end of a run you get success/fail counts and elapsed time. For
programmatic use, `HCIReconnectTester` is importable directly - `run()`
returns `(success_count, fail_count, elapsed_seconds)`, and
`tester.stats` gives a live snapshot of attempts/success/failed/retries
at any point during a run.
