#!/usr/bin/env python3
"""
hci_connector.py - Raw-HCI Bluetooth reconnect stress tester.
No BlueZ, no D-Bus, no subprocess - direct kernel HCI sockets.

Built for bench testing reconnect handling against a fixed set of target
devices (e.g. emulated peripherals) from a single local Bluetooth
controller. A single controller can only have one Create Connection
procedure in flight at a time, so this queues attempts on one adapter
rather than faking concurrency with a thread pool.

Features:
- Correct HCI Create Connection / Connection Complete / Disconnect flow
- Retry with adaptive backoff
- Optional live target discovery (--discover) via HCI Inquiry, interleaved
  between rounds on the same socket, for targets with rotating/changing
  identifiers - scopeable to known OUIs with --allow-prefix
- MAC validation and deduplication
- Detailed logging and performance metrics
- Graceful shutdown and resource cleanup
- Runs under Termux on rooted Android (raw HCI sockets need root/CAP_NET_RAW)
  as well as any Linux host with a Bluetooth controller and BlueZ kernel support
"""

import os
import sys
import time
import socket
import struct
import threading
import logging
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple

# -------------------- Constants --------------------
AF_BLUETOOTH = 31
BTPROTO_HCI = 1
SOL_HCI = 0
HCI_FILTER = 2

HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT = 0x04

OGF_LINK_CTL = 0x01
OCF_CREATE_CONN = 0x0005
OCF_DISCONNECT = 0x0006
OCF_INQUIRY = 0x0001
OCF_INQUIRY_CANCEL = 0x0002

OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_CREATE_CONN = 0x000D
OCF_LE_CREATE_CONN_CANCEL = 0x000E

EVT_CMD_STATUS = 0x0F
EVT_CONN_COMPLETE = 0x03
EVT_DISCONN_COMPLETE = 0x05
EVT_INQUIRY_COMPLETE = 0x01
EVT_INQUIRY_RESULT = 0x02
EVT_INQUIRY_RESULT_WITH_RSSI = 0x22
EVT_LE_META = 0x3E

LE_SUBEVT_CONN_COMPLETE = 0x01
LE_SUBEVT_ADV_REPORT = 0x02

GIAC_LAP = bytes([0x33, 0x8B, 0x9E])  # General Inquiry Access Code 0x9E8B33, little-endian on the wire

# Conservative LE connection parameters (units per Core Spec: interval/latency
# in 1.25ms steps, supervision timeout in 10ms steps). Chosen so the
# supervision-timeout-vs-interval constraint (timeout_ms > 2 * (1+latency) *
# interval_max_ms) is comfortably satisfied.
LE_CONN_INTERVAL_MIN = 0x0018   # 30ms
LE_CONN_INTERVAL_MAX = 0x0028   # 50ms
LE_CONN_LATENCY = 0x0000
LE_SUPERVISION_TIMEOUT = 0x00C8  # 2000ms
LE_SCAN_INTERVAL = 0x0010        # 10ms
LE_SCAN_WINDOW = 0x0010          # 10ms (100% duty cycle)

DEFAULT_HCI_DEV = 0
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_RETRIES = 1
DEFAULT_MIN_DELAY_MS = 20
DEFAULT_MAX_DELAY_MS = 150
DEFAULT_INITIAL_DELAY_MS = 50
DEFAULT_TARGET_TTL = 30.0
DEFAULT_SCAN_WINDOW = 4.0


def hci_opcode(ogf: int, ocf: int) -> int:
    return (ogf << 10) | ocf


# -------------------- Core HCI Classes --------------------

@dataclass
class HCICommand:
    opcode: int
    params: bytes

    def pack(self) -> bytes:
        return struct.pack('<H', self.opcode) + struct.pack('<B', len(self.params)) + self.params


@dataclass
class HCIEvent:
    code: int
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        # data[0] = packet type (already stripped by caller), data[0]=code, data[1]=len, data[2:]=params
        if len(data) < 2:
            raise ValueError("Event too short")
        return cls(code=data[0], data=data[2:])


class HCISocket:
    """Wrapper for a raw HCI socket bound to a single controller."""

    def __init__(self, dev_id: int = DEFAULT_HCI_DEV):
        self.dev_id = dev_id
        self.sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        self.sock.bind((dev_id,))
        self._set_filter()

    def _set_filter(self):
        type_mask = (1 << HCI_EVENT_PKT)
        event_mask = [0xffffffff, 0xffffffff]
        opcode = 0
        filt = struct.pack('<I', type_mask) + struct.pack('<II', *event_mask) + struct.pack('<H', opcode)
        self.sock.setsockopt(SOL_HCI, HCI_FILTER, filt)

    def send_command(self, cmd: HCICommand) -> None:
        packet = struct.pack('<B', HCI_COMMAND_PKT) + cmd.pack()
        self.sock.send(packet)

    def recv_event(self, timeout: float) -> Optional[HCIEvent]:
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(255)
            if data and data[0] == HCI_EVENT_PKT:
                return HCIEvent.from_bytes(data[1:])
        except socket.timeout:
            pass
        return None

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# -------------------- Live Target Tracking --------------------

class TargetTracker:
    """
    Tracks recently-discovered BD_ADDRs with a last-seen timestamp so
    rotating/emulated identifiers can be chased as they change, instead
    of relying on a MAC list that goes stale. Optionally restricted to
    an allowlist of address prefixes (OUIs) so discovery only picks up
    the intended targets rather than every nearby classic BT device.
    """

    def __init__(self, ttl: float, allow_prefixes: Optional[List[str]] = None):
        self.ttl = ttl
        self.allow_prefixes = [p.upper().replace('-', ':') for p in (allow_prefixes or [])]
        self._lock = threading.Lock()
        self._seen = {}  # mac -> (last_seen timestamp, meta)

    def _allowed(self, mac: str) -> bool:
        if not self.allow_prefixes:
            return True
        mac_u = mac.upper()
        return any(mac_u.startswith(p) for p in self.allow_prefixes)

    def observe(self, mac: str, meta=None) -> None:
        if not self._allowed(mac):
            return
        with self._lock:
            self._seen[mac] = (time.time(), meta)

    def live_macs(self) -> List[str]:
        now = time.time()
        with self._lock:
            return [m for m, (t, _meta) in self._seen.items() if now - t <= self.ttl]

    def live_targets(self) -> List[Tuple[str, object]]:
        """Like live_macs(), but paired with each target's stored metadata (e.g. LE address type)."""
        now = time.time()
        with self._lock:
            return [(m, meta) for m, (t, meta) in self._seen.items() if now - t <= self.ttl]

    def prune(self) -> None:
        now = time.time()
        with self._lock:
            stale = [m for m, (t, _meta) in self._seen.items() if now - t > self.ttl]
            for m in stale:
                del self._seen[m]


# -------------------- Connection Manager --------------------

class HCIReconnectTester:
    """
    Queues Create Connection attempts on a single local controller and
    measures reconnect behavior against a fixed or live-discovered device
    list. One attempt is in flight at a time - that matches what a real
    controller can do.
    """

    def __init__(
        self,
        dev_id: int = DEFAULT_HCI_DEV,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        min_delay_ms: int = DEFAULT_MIN_DELAY_MS,
        max_delay_ms: int = DEFAULT_MAX_DELAY_MS,
        initial_delay_ms: int = DEFAULT_INITIAL_DELAY_MS,
        mode: str = "auto",
    ):
        if mode not in ("auto", "classic", "le"):
            raise ValueError("mode must be 'auto', 'classic', or 'le'")
        self.dev_id = dev_id
        self.connect_timeout = connect_timeout
        self.retries = retries
        self.mode = mode
        self.min_delay = min_delay_ms / 1000.0
        self.max_delay = max_delay_ms / 1000.0
        self.initial_delay = initial_delay_ms / 1000.0
        self._lock = threading.Lock()
        self._stop = False
        self._current_delay = self.initial_delay
        self._consecutive_fails = 0
        self._transport_cache = {}  # mac -> 'classic' | 'le', learned in auto mode
        self._stats = {
            "attempts": 0,
            "success": 0,
            "failed": 0,
            "retries": 0,
        }

    def _next_delay(self) -> float:
        with self._lock:
            if self._consecutive_fails > 0:
                self._current_delay = min(self._current_delay * 1.5, self.max_delay)
            else:
                self._current_delay = max(self._current_delay * 0.95, self.min_delay)
            return self._current_delay

    def _disconnect(self, hci: HCISocket, conn_handle: int, reason: int = 0x13) -> None:
        # OCF_DISCONNECT params: Connection_Handle (2 bytes, 12 bits used), Reason (1 byte)
        opcode = hci_opcode(OGF_LINK_CTL, OCF_DISCONNECT)
        params = struct.pack('<H', conn_handle) + struct.pack('<B', reason)
        hci.send_command(HCICommand(opcode, params))
        deadline = time.time() + 2.0
        while time.time() < deadline:
            evt = hci.recv_event(0.2)
            if evt and evt.code == EVT_DISCONN_COMPLETE:
                return

    @staticmethod
    def _parse_inquiry_result(data: bytes, tracker: TargetTracker) -> None:
        # Both EVT_INQUIRY_RESULT and EVT_INQUIRY_RESULT_WITH_RSSI are
        # Num_Responses(1) followed by fixed 14-byte entries, BD_ADDR
        # first in each entry - that's the only field we need.
        if len(data) < 1:
            return
        num = data[0]
        offset = 1
        entry_size = 14
        for _ in range(num):
            if offset + 6 > len(data):
                break
            addr_bytes = data[offset:offset + 6]
            mac = ':'.join(f'{b:02X}' for b in reversed(addr_bytes))
            tracker.observe(mac, meta=('classic', None))
            offset += entry_size

    def _scan_burst(self, hci: HCISocket, tracker: TargetTracker, scan_window: float) -> None:
        """Run one Inquiry burst on the given socket, feeding results into tracker."""
        opcode_inq = hci_opcode(OGF_LINK_CTL, OCF_INQUIRY)
        length_units = max(1, min(0x30, round(scan_window / 1.28)))
        params = GIAC_LAP + struct.pack('<B', length_units) + struct.pack('<B', 0)
        hci.send_command(HCICommand(opcode_inq, params))

        deadline = time.time() + scan_window + 1.0
        completed = False
        while time.time() < deadline and not self._stop:
            evt = hci.recv_event(0.2)
            if not evt:
                continue
            if evt.code in (EVT_INQUIRY_RESULT, EVT_INQUIRY_RESULT_WITH_RSSI):
                self._parse_inquiry_result(evt.data, tracker)
            elif evt.code == EVT_INQUIRY_COMPLETE:
                completed = True
                break

        if not completed:
            # Scan didn't self-terminate in time (or we're stopping) - cancel it
            # so it doesn't keep occupying the radio during connect attempts.
            opcode_cancel = hci_opcode(OGF_LINK_CTL, OCF_INQUIRY_CANCEL)
            hci.send_command(HCICommand(opcode_cancel, b''))
            hci.recv_event(0.5)

        tracker.prune()

    def connect_one(self, mac: str, hci: HCISocket) -> bool:
        """Attempt a single connection (with retries) on an already-open socket."""
        mac_bytes = bytes(reversed(bytes.fromhex(mac.replace(':', ''))))  # BD_ADDR is little-endian on the wire

        for attempt in range(self.retries + 1):
            if self._stop:
                return False
            if attempt > 0:
                with self._lock:
                    self._stats["retries"] += 1

            opcode = hci_opcode(OGF_LINK_CTL, OCF_CREATE_CONN)
            # BD_ADDR, PacketType, PageScanRepMode, Reserved, ClockOffset, RoleSwitch
            params = mac_bytes + struct.pack('<H', 0xcc18) + struct.pack('<B', 0x02)
            params += struct.pack('<B', 0x00) + struct.pack('<H', 0x0000) + struct.pack('<B', 0x00)
            cmd = HCICommand(opcode, params)

            start = time.time()
            hci.send_command(cmd)

            status_seen = False
            while time.time() - start < self.connect_timeout:
                evt = hci.recv_event(0.1)
                if not evt:
                    continue
                if evt.code == EVT_CMD_STATUS and len(evt.data) >= 4 and evt.data[2:4] == struct.pack('<H', opcode):
                    status = evt.data[0]
                    if status != 0x00:
                        break  # command rejected (e.g. another connection already in progress)
                    status_seen = True
                elif evt.code == EVT_CONN_COMPLETE and status_seen and len(evt.data) >= 11:
                    conn_status = evt.data[0]
                    conn_handle = struct.unpack('<H', evt.data[1:3])[0]
                    conn_mac = evt.data[3:9]
                    if conn_status == 0x00 and conn_mac == mac_bytes:
                        self._disconnect(hci, conn_handle)
                        return True
                    break
        return False

    @staticmethod
    def _parse_le_adv_report(data: bytes, tracker: TargetTracker) -> None:
        # LE Advertising Report is NOT per-report chunks - it's parallel
        # arrays: Subevent_Code(1), Num_Reports(1), Event_Type[N](1 each),
        # Address_Type[N](1 each), Address[N](6 each), Length_Data[N](1 each),
        # then Data[i] back-to-back per Length_Data[i], then RSSI[N](1 each).
        if len(data) < 2:
            return
        num = data[1]
        offset = 2

        if offset + num > len(data):
            return
        offset += num  # skip Event_Type[N]

        if offset + num > len(data):
            return
        addr_types = data[offset:offset + num]
        offset += num

        if offset + num * 6 > len(data):
            return
        addresses = [data[offset + i * 6: offset + i * 6 + 6] for i in range(num)]
        offset += num * 6

        if offset + num > len(data):
            return
        lengths = data[offset:offset + num]
        offset += num

        for length in lengths:
            offset += length  # skip each report's AD data, we only need the address

        for addr_bytes, addr_type in zip(addresses, addr_types):
            mac = ':'.join(f'{b:02X}' for b in reversed(addr_bytes))
            tracker.observe(mac, meta=('le', addr_type))

    def _scan_burst_le(self, hci: HCISocket, tracker: TargetTracker, scan_window: float) -> None:
        """Run one LE scan burst on the given socket, feeding results into tracker."""
        opcode_params = hci_opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS)
        params = struct.pack('<B', 0x01)  # Scan_Type: active
        params += struct.pack('<H', LE_SCAN_INTERVAL) + struct.pack('<H', LE_SCAN_WINDOW)
        params += struct.pack('<B', 0x00)  # Own_Address_Type: public
        params += struct.pack('<B', 0x00)  # Scanning_Filter_Policy: accept all advertisements
        hci.send_command(HCICommand(opcode_params, params))
        hci.recv_event(0.5)  # best-effort drain of Command Complete

        opcode_enable = hci_opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE)
        hci.send_command(HCICommand(opcode_enable, struct.pack('<BB', 0x01, 0x00)))  # enable, no dup filter
        hci.recv_event(0.5)

        deadline = time.time() + scan_window
        while time.time() < deadline and not self._stop:
            evt = hci.recv_event(0.2)
            if evt and evt.code == EVT_LE_META and len(evt.data) >= 2 and evt.data[0] == LE_SUBEVT_ADV_REPORT:
                self._parse_le_adv_report(evt.data, tracker)

        hci.send_command(HCICommand(opcode_enable, struct.pack('<BB', 0x00, 0x00)))  # disable
        hci.recv_event(0.5)
        tracker.prune()

    def connect_one_le(self, mac: str, addr_type: int, hci: HCISocket) -> bool:
        """Attempt a single LE connection (with retries) on an already-open socket."""
        mac_bytes = bytes(reversed(bytes.fromhex(mac.replace(':', ''))))  # address is little-endian on the wire

        for attempt in range(self.retries + 1):
            if self._stop:
                return False
            if attempt > 0:
                with self._lock:
                    self._stats["retries"] += 1

            opcode = hci_opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN)
            params = struct.pack('<H', LE_SCAN_INTERVAL) + struct.pack('<H', LE_SCAN_WINDOW)
            params += struct.pack('<B', 0x00)          # Initiator_Filter_Policy: use peer address below
            params += struct.pack('<B', addr_type)     # Peer_Address_Type
            params += mac_bytes                        # Peer_Address
            params += struct.pack('<B', 0x00)          # Own_Address_Type: public
            params += struct.pack('<H', LE_CONN_INTERVAL_MIN)
            params += struct.pack('<H', LE_CONN_INTERVAL_MAX)
            params += struct.pack('<H', LE_CONN_LATENCY)
            params += struct.pack('<H', LE_SUPERVISION_TIMEOUT)
            params += struct.pack('<H', 0x0000)        # Min_CE_Length
            params += struct.pack('<H', 0x0000)        # Max_CE_Length
            cmd = HCICommand(opcode, params)

            start = time.time()
            hci.send_command(cmd)

            status_seen = False
            while time.time() - start < self.connect_timeout:
                evt = hci.recv_event(0.1)
                if not evt:
                    continue
                if evt.code == EVT_CMD_STATUS and len(evt.data) >= 4 and evt.data[2:4] == struct.pack('<H', opcode):
                    status = evt.data[0]
                    if status != 0x00:
                        break  # command rejected
                    status_seen = True
                elif (evt.code == EVT_LE_META and status_seen and len(evt.data) >= 12
                      and evt.data[0] == LE_SUBEVT_CONN_COMPLETE):
                    conn_status = evt.data[1]
                    conn_handle = struct.unpack('<H', evt.data[2:4])[0]
                    peer_addr = evt.data[6:12]
                    if conn_status == 0x00 and peer_addr == mac_bytes:
                        self._disconnect(hci, conn_handle)
                        return True
                    break

            # This attempt didn't succeed - if the initiation was accepted (status_seen)
            # but timed out waiting for the peer, or is still pending, cancel it before
            # the next attempt/command so it doesn't linger and block future connects.
            opcode_cancel = hci_opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN_CANCEL)
            hci.send_command(HCICommand(opcode_cancel, b''))
            hci.recv_event(0.3)
        return False

    def connect_one_auto(self, mac: str, hci: HCISocket) -> bool:
        """
        Transport-agnostic connect for a static target list: tries whichever
        transport already worked for this MAC before, or tries classic then
        LE (public address) the first time, caching whichever succeeds so
        later rounds don't pay for both attempts every time.
        """
        cached = self._transport_cache.get(mac)
        if cached == 'le':
            return self.connect_one_le(mac, 0x00, hci)
        if cached == 'classic':
            return self.connect_one(mac, hci)

        if self.connect_one(mac, hci):
            self._transport_cache[mac] = 'classic'
            return True
        if self.connect_one_le(mac, 0x00, hci):
            self._transport_cache[mac] = 'le'
            return True
        return False

    def run(
        self,
        macs: Optional[List[str]] = None,
        rounds: int = 1,
        progress_callback=None,
        discover: bool = False,
        ttl: float = DEFAULT_TARGET_TTL,
        allow_prefixes: Optional[List[str]] = None,
        scan_window: float = DEFAULT_SCAN_WINDOW,
    ) -> Tuple[int, int, float]:
        """
        Repeatedly attempt reconnects, one attempt in flight at a time on
        the local controller, for the given number of rounds.

        With discover=False (default), targets are the fixed `macs` list.
        With discover=True, a short scan burst runs before each round on
        the same socket, and the round targets whatever's currently live
        in the TargetTracker (last seen within `ttl` seconds) - so
        rotating/emulated identifiers get picked up as they change
        instead of chasing a stale static list. `allow_prefixes` scopes
        discovery to known target OUIs so it doesn't chase unrelated
        nearby devices.

        self.mode controls which transport(s) are used:
        - 'classic': classic BR/EDR only (Inquiry / Create Connection)
        - 'le': LE only (LE Scan / LE Create Connection)
        - 'auto' (default): both. In discover mode, both an Inquiry and an
          LE scan burst run each cycle and each target is connected with
          whichever transport it was actually seen on. In static-list
          mode, each MAC tries classic then LE the first time and caches
          whichever transport works.
        """
        if not discover and not macs:
            raise ValueError("macs is required when discover=False")

        self._stop = False
        success_count = 0
        fail_count = 0
        start_time = time.time()
        processed = 0
        total = None if discover else len(macs) * rounds

        tracker = TargetTracker(ttl=ttl, allow_prefixes=allow_prefixes) if discover else None

        with HCISocket(self.dev_id) as hci:
            round_num = 0
            while round_num < rounds and not self._stop:
                if discover:
                    if self.mode in ('classic', 'auto'):
                        self._scan_burst(hci, tracker, scan_window)
                    if self.mode in ('le', 'auto'):
                        self._scan_burst_le(hci, tracker, scan_window)
                    targets = tracker.live_targets()
                    if not targets:
                        logging.info("No live targets discovered yet, rescanning...")
                        continue
                else:
                    if self.mode == 'classic':
                        targets = [(m, ('classic', None)) for m in macs]
                    elif self.mode == 'le':
                        targets = [(m, ('le', 0x00)) for m in macs]
                    else:
                        targets = [(m, ('auto', None)) for m in macs]

                round_num += 1
                for mac, (transport, payload) in targets:
                    if self._stop:
                        break
                    if transport == 'classic':
                        ok = self.connect_one(mac, hci)
                    elif transport == 'le':
                        ok = self.connect_one_le(mac, payload if payload is not None else 0x00, hci)
                    else:
                        ok = self.connect_one_auto(mac, hci)
                    processed += 1

                    with self._lock:
                        self._stats["attempts"] += 1
                        if ok:
                            success_count += 1
                            self._consecutive_fails = max(0, self._consecutive_fails - 1)
                        else:
                            fail_count += 1
                            self._consecutive_fails += 1

                    if progress_callback:
                        progress_callback(processed, total)

                    time.sleep(self._next_delay())

        elapsed = time.time() - start_time
        return success_count, fail_count, elapsed

    def stop(self):
        self._stop = True

    @property
    def stats(self):
        with self._lock:
            return self._stats.copy()


# -------------------- Utility Functions --------------------

MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def validate_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac))


def load_macs_from_file(filepath: str) -> List[str]:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    valid = [m for m in lines if validate_mac(m)]
    invalid = len(lines) - len(valid)
    if invalid:
        logging.warning(f"Skipped {invalid} invalid MACs")
    return list(dict.fromkeys(valid))  # dedupe, preserve order


CONSENT_BANNER = """\
================================================================
 hci_connector.py - active Bluetooth reconnect stress tester
================================================================
 This tool actively scans for and connects to real nearby
 Bluetooth devices (classic and/or LE). Only run it against
 devices you own or are explicitly authorized to test.
================================================================\
"""


def confirm_authorized_use(assume_yes: bool = False) -> None:
    """
    Print the consent banner and require explicit confirmation before
    doing anything active on the radio. --yes/-y confirms non-interactively
    for scripted runs; otherwise this requires a typed 'yes' at a TTY and
    exits rather than silently proceeding if neither is available.
    """
    print(CONSENT_BANNER, file=sys.stderr)

    if assume_yes:
        logging.info("Authorization confirmed via --yes")
        return

    if not sys.stdin.isatty():
        logging.error(
            "No TTY to prompt for confirmation and --yes was not passed. "
            "Re-run with -y/--yes to confirm you're authorized to target these devices."
        )
        sys.exit(1)

    try:
        answer = input("Type 'yes' to confirm you are authorized to proceed: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""

    if answer.strip().lower() != "yes":
        logging.error("Not confirmed - exiting.")
        sys.exit(1)


# -------------------- Main Entry Point --------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Raw HCI Bluetooth reconnect stress tester")
    parser.add_argument("-f", "--file", default="devices.txt", help="File with target MACs (one per line). Ignored with --discover")
    parser.add_argument("-d", "--dev", type=int, default=DEFAULT_HCI_DEV, help="HCI device index (e.g. 0 for hci0)")
    parser.add_argument("--rounds", type=int, default=1, help="Number of reconnect rounds")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT, help="Per-attempt timeout (seconds)")
    parser.add_argument("-r", "--retries", type=int, default=DEFAULT_RETRIES, help="Retry attempts per device per round")
    parser.add_argument("--min-delay", type=int, default=DEFAULT_MIN_DELAY_MS, help="Minimum delay between attempts (ms)")
    parser.add_argument("--max-delay", type=int, default=DEFAULT_MAX_DELAY_MS, help="Maximum delay between attempts (ms)")
    parser.add_argument("--initial-delay", type=int, default=DEFAULT_INITIAL_DELAY_MS, help="Initial delay (ms)")
    parser.add_argument("--discover", action="store_true",
                         help="Discover live targets via HCI Inquiry between rounds instead of using a static file "
                              "- for targets with rotating/changing identifiers")
    parser.add_argument("--allow-prefix", action="append", default=None,
                         help="Optional: restrict --discover to BD_ADDR prefixes (OUIs), e.g. AA:BB:CC. Repeatable. "
                              "Only useful when targets keep a stable OUI while rotating the rest of the address - "
                              "does nothing for targets using fully-random addresses")
    parser.add_argument("--ttl", type=float, default=DEFAULT_TARGET_TTL,
                         help="Seconds a discovered identifier stays a live target after last seen (--discover only)")
    parser.add_argument("--scan-window", type=float, default=DEFAULT_SCAN_WINDOW,
                         help="Inquiry/scan burst duration in seconds, run before each round (--discover only)")
    parser.add_argument("--mode", choices=["auto", "classic", "le"], default="auto",
                         help="Transport to use: 'classic' (BR/EDR only), 'le' (Bluetooth Low Energy only), or "
                              "'auto' (default) - tries both, so classic devices and LE-only devices "
                              "(most modern wearables/sensors/beacons) are both supported without knowing "
                              "which one a target uses in advance")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Confirm you are authorized to run this against its targets, non-interactively "
                              "(skips the interactive consent prompt - for scripted/automated runs)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    confirm_authorized_use(assume_yes=args.yes)

    macs = None
    if not args.discover:
        try:
            macs = load_macs_from_file(args.file)
        except Exception as e:
            logging.error(f"Failed to load MACs: {e}")
            sys.exit(1)

        if not macs:
            logging.error("No valid MACs found.")
            sys.exit(1)

    tester = HCIReconnectTester(
        dev_id=args.dev,
        connect_timeout=args.timeout,
        retries=args.retries,
        min_delay_ms=args.min_delay,
        max_delay_ms=args.max_delay,
        initial_delay_ms=args.initial_delay,
        mode=args.mode,
    )

    if args.discover:
        logging.info(
            f"Starting reconnect test: mode={args.mode} live discovery on hci{args.dev} "
            f"(ttl={args.ttl}s, scan={args.scan_window}s, {args.rounds} round(s), "
            f"prefixes={args.allow_prefix or 'any'})"
        )
    else:
        logging.info(
            f"Starting reconnect test: mode={args.mode}, {len(macs)} devices x {args.rounds} round(s) on hci{args.dev}"
        )

    def progress(processed, total):
        if total is None:
            if processed % 10 == 0:
                logging.info(f"Progress: {processed} attempts so far")
        elif processed % 10 == 0 or processed == total:
            logging.info(f"Progress: {processed}/{total} ({processed/total*100:.1f}%)")

    try:
        success, failed, elapsed = tester.run(
            macs,
            rounds=args.rounds,
            progress_callback=progress,
            discover=args.discover,
            ttl=args.ttl,
            allow_prefixes=args.allow_prefix,
            scan_window=args.scan_window,
        )
        logging.info(f"Completed in {elapsed:.1f}s. Success: {success}, Failed: {failed}")
    except KeyboardInterrupt:
        tester.stop()
        logging.warning("Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
