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

EVT_CMD_STATUS = 0x0F
EVT_CONN_COMPLETE = 0x03
EVT_DISCONN_COMPLETE = 0x05

DEFAULT_HCI_DEV = 0
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_RETRIES = 1
DEFAULT_MIN_DELAY_MS = 20
DEFAULT_MAX_DELAY_MS = 150
DEFAULT_INITIAL_DELAY_MS = 50


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


# -------------------- Connection Manager --------------------

class HCIReconnectTester:
    """
    Queues Create Connection attempts on a single local controller and
    measures reconnect behavior against a fixed device list. One attempt
    is in flight at a time - that matches what a real controller can do.
    """

    def __init__(
        self,
        dev_id: int = DEFAULT_HCI_DEV,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        min_delay_ms: int = DEFAULT_MIN_DELAY_MS,
        max_delay_ms: int = DEFAULT_MAX_DELAY_MS,
        initial_delay_ms: int = DEFAULT_INITIAL_DELAY_MS,
    ):
        self.dev_id = dev_id
        self.connect_timeout = connect_timeout
        self.retries = retries
        self.min_delay = min_delay_ms / 1000.0
        self.max_delay = max_delay_ms / 1000.0
        self.initial_delay = initial_delay_ms / 1000.0
        self._lock = threading.Lock()
        self._stop = False
        self._current_delay = self.initial_delay
        self._consecutive_fails = 0
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

    def run(
        self,
        macs: List[str],
        rounds: int = 1,
        progress_callback=None,
    ) -> Tuple[int, int, float]:
        """
        Repeatedly attempt reconnects to each MAC, one attempt in flight
        at a time on the local controller, for the given number of rounds.
        """
        self._stop = False
        success_count = 0
        fail_count = 0
        start_time = time.time()
        total = len(macs) * rounds
        processed = 0

        with HCISocket(self.dev_id) as hci:
            for _ in range(rounds):
                for mac in macs:
                    if self._stop:
                        break
                    ok = self.connect_one(mac, hci)
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


# -------------------- Main Entry Point --------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Raw HCI Bluetooth reconnect stress tester")
    parser.add_argument("-f", "--file", default="devices.txt", help="File with target MACs (one per line)")
    parser.add_argument("-d", "--dev", type=int, default=DEFAULT_HCI_DEV, help="HCI device index (e.g. 0 for hci0)")
    parser.add_argument("--rounds", type=int, default=1, help="Number of reconnect rounds per device")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT, help="Per-attempt timeout (seconds)")
    parser.add_argument("-r", "--retries", type=int, default=DEFAULT_RETRIES, help="Retry attempts per device per round")
    parser.add_argument("--min-delay", type=int, default=DEFAULT_MIN_DELAY_MS, help="Minimum delay between attempts (ms)")
    parser.add_argument("--max-delay", type=int, default=DEFAULT_MAX_DELAY_MS, help="Maximum delay between attempts (ms)")
    parser.add_argument("--initial-delay", type=int, default=DEFAULT_INITIAL_DELAY_MS, help="Initial delay (ms)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

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
    )

    logging.info(f"Starting reconnect test: {len(macs)} devices x {args.rounds} round(s) on hci{args.dev}")

    def progress(processed, total):
        if processed % 10 == 0 or processed == total:
            logging.info(f"Progress: {processed}/{total} ({processed/total*100:.1f}%)")

    try:
        success, failed, elapsed = tester.run(macs, rounds=args.rounds, progress_callback=progress)
        logging.info(f"Completed in {elapsed:.1f}s. Success: {success}, Failed: {failed}")
    except KeyboardInterrupt:
        tester.stop()
        logging.warning("Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
