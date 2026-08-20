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
1. Sends `Create Connection` (classic) or `LE Create Connection`,
   depending on `--mode`.
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
before each round on the same socket - classic `Inquiry`, LE scanning,
or both depending on `--mode` - and the round targets whatever's
currently live. Three knobs control how this tracks a moving target:

- `--scan-window` - how long each scan burst runs before a round. Set it
  shorter than however often your targets' identifiers change, so you
  never go a full round without a fresh read.
- `--ttl` - how long a discovered identifier is considered "live" after
  last being seen. Once it expires, the script stops chasing it.
- `--allow-prefix AA:BB:CC` (repeatable, optional) - restrict discovery
  to known address prefixes (OUIs), if your targets keep a stable OUI
  while rotating the rest of the address. This does nothing for targets
  using fully-random addresses (no fixed prefix to filter on) - without
  it, or when it doesn't apply, a scan picks up every nearby device that
  answers, not just your targets. See **Authorization** below.

## Classic BR/EDR vs. LE vs. auto

Most modern peripherals - wearables, sensors, beacons, most IoT hardware
- are Bluetooth LE only and won't respond to classic `Create Connection`
at all; older/simpler devices are often classic-only. `--mode` controls
which transport(s) are used:

- `--mode auto` (**default**) - supports both without needing to know
  which one a target uses in advance:
  - In `--discover` mode, both an `Inquiry` burst and an LE scan burst
    run before each round, and each discovered target is connected with
    whichever transport it actually answered on.
  - In static-list mode, each MAC tries classic first, then LE (public
    address) if classic doesn't succeed, and caches whichever transport
    worked so later rounds don't pay for both attempts every time.
- `--mode classic` - classic BR/EDR only (`Inquiry` / `Create Connection`).
- `--mode le` - LE only (LE scan / `LE Create Connection`).

Trade-off: `auto` costs up to double the time per attempt against a
target that's genuinely unreachable on both transports (or during the
first, uncached attempt against each new static-list target), since it
has to try both before giving up. If you already know your fleet is
one transport or the other, pinning `--mode` avoids that overhead.

One LE-specific note: `LE Create Connection` needs the correct
public-vs-random address type for a peer, or the controller will reject
it. In `--discover` mode this is learned automatically from the scan. In
static-list mode there's no way to specify it from a plain MAC list, so
`--mode le` and the LE half of `--mode auto` both default to public
(`0x00`) - if your targets use random addresses, use `--discover`
instead of a static file.

**Heads up on LE advertising report parsing**: the LE Advertising Report
event uses a parallel-array wire format (all address types together,
then all addresses together, etc. - not per-device chunks), which is
implemented here per the Core Spec but hasn't been validated against a
real capture. If LE discovery doesn't pick up devices you can see with
`bluetoothctl` or a phone, that parsing is the first place to check -
ideally with a packet capture (`btmon`) to compare against.

## Usage examples

Fixed list, don't know (or don't want to specify) classic vs. LE per
device, 50 reconnect rounds - this is the default:
```
python3 hci_connector.py -f devices.txt -d 0 --rounds 50 -t 5 -v -y
```

Live discovery, auto transport, scoped to a known OUI, rotating
identifiers:
```
python3 hci_connector.py -d 0 --discover --allow-prefix 28:CD:C1 \
    --ttl 15 --scan-window 3 --rounds 100 -t 5 -v -y
```

Classic-only, fixed list (skip the LE fallback attempt entirely):
```
python3 hci_connector.py -f devices.txt --mode classic -d 0 --rounds 50 -t 5 -v -y
```

LE-only peripheral with a fixed public address:
```
python3 hci_connector.py -f devices.txt --mode le -d 0 --rounds 50 -t 5 -v -y
```

LE-only with rotating/fully-random addresses, discovered live (no
`--allow-prefix` - a random address has no stable OUI to filter on):
```
python3 hci_connector.py --mode le --discover \
    --ttl 20 --scan-window 4 --rounds 100 -t 8 -v -y
```

## Authorization

This is a reconnect/load-testing tool for Bluetooth hardware you own or
are authorized to test - a bench rig, a fleet of devices under your
control, or similar. It actively scans for and connects to real
Bluetooth devices; point it only at things you have permission to
connect to. `--allow-prefix` can narrow *what* a scan picks up when it
applies, but it isn't reliable enforcement (it does nothing against
fully-random addresses) and isn't the thing that's supposed to be
doing the enforcing here.

Every run prints a warning banner and requires explicit confirmation
before touching the radio - type `yes` at the prompt, or pass `-y/--yes`
to confirm non-interactively for scripted/automated runs. This is a
consent gate, not a technical restriction: it doesn't verify anything
about the targets, it just makes sure a human (or an explicit flag)
affirmed authorization before the tool does anything active.

## Output

At the end of a run you get success/fail counts and elapsed time. For
programmatic use, `HCIReconnectTester` is importable directly - `run()`
returns `(success_count, fail_count, elapsed_seconds)`, and
`tester.stats` gives a live snapshot of attempts/success/failed/retries
at any point during a run.
