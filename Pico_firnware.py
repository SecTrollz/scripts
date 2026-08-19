import network
import time
import machine
import ubinascii
import ujson
import os
import struct
import binascii
import bluetooth
from machine import Pin
from micropython import const
from umqtt.simple import MQTTClient

WIFI_SSID = "YourStableAP"
WIFI_PASS = "password"

MQTT_BROKER = "your.cloud.com"
MQTT_PORT = 8883
MQTT_CLIENT_ID = "bridge_" + ubinascii.hexlify(machine.unique_id()).decode()
MQTT_TOPIC_CMD = "pico/executor/command"
MQTT_TOPIC_ACK = "pico/bridge/ack"
MQTT_TOPIC_STATUS = "pico/bridge/status"
MQTT_USER = "bridge_user"
MQTT_PASS = "supersecret"

SHARED_SECRET = "hunter2"
AUTH_PIN = b"1234"

MQTT_VERIFY_CERT = False
MQTT_CA_CERT = "/cert/ca.pem"

MAX_RETRIES = 3
COMMAND_TIMEOUT_MS = 5000
MAX_CMD_PAYLOAD = 16
QUEUE_MAX_BYTES = 8192
CMD_QUEUE_MAX = 128
MQTT_QUEUE_MAX = 10
COMPLETED_MAX = 64

STATE_A = "state_a.bin"
STATE_B = "state_b.bin"
STATE_MAGIC = b"BRDG"
STATE_VERSION = 1
STATE_HEADER_SIZE = 16
STATE_RECORD_SIZE = 4
STATE_SIZE = STATE_HEADER_SIZE + (COMPLETED_MAX * STATE_RECORD_SIZE) + 4

EVENT_MAX = 64
EVENT_SIZE = 5

EVT_CONNECT = const(1)
EVT_DISCONNECT = const(2)
EVT_CMD_WRITE = const(3)
EVT_ACK_WRITE = const(4)
EVT_AUTH_WRITE = const(5)

_IRQ_CENTRAL_CONNECT = const(1)
_IRQ_CENTRAL_DISCONNECT = const(2)
_IRQ_GATTS_WRITE = const(3)

_EXECUTOR_SERVICE_UUID = bluetooth.UUID(
    "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
)
_CMD_CHAR_UUID = bluetooth.UUID(
    "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
)
_NOTIFY_CHAR_UUID = bluetooth.UUID(
    "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
)
_STATUS_CHAR_UUID = bluetooth.UUID(
    "6E400004-B5A3-F393-E0A9-E50E24DCCA9E"
)
_ACK_CHAR_UUID = bluetooth.UUID(
    "6E400005-B5A3-F393-E0A9-E50E24DCCA9E"
)
_AUTH_CHAR_UUID = bluetooth.UUID(
    "6E400006-B5A3-F393-E0A9-E50E24DCCA9E"
)

LED_PIN = "LED"
BUTTON_PIN = 15

event_buf = bytearray(EVENT_MAX * EVENT_SIZE)
event_head = 0
event_tail = 0
event_overflow = 0

cmd_queue = []
queue_used = 0
mqtt_rejected = 0

ble_bridge = None
mqtt_mgr = None

ack_pending = False
auth_pending = False
pending_auth_handle = None

wifi_state = 0
wifi_retry_at = 0


class PersistentState:
    def __init__(self):
        self.next_id = 1
        self.terminal_ids = []
        self.sequence = 0
        self.active_slot = 0
        self.dirty = False
        self.load()

    def load(self):
        a = self._read_slot(STATE_A)
        b = self._read_slot(STATE_B)

        if a is None and b is None:
            self.next_id = 1
            self.terminal_ids = []
            self.sequence = 0
            self.active_slot = 0
            self.dirty = True
            self.save()
            return

        if b is None or (a is not None and a[0] >= b[0]):
            seq, next_id, ids = a
            self.active_slot = 0
        else:
            seq, next_id, ids = b
            self.active_slot = 1

        self.sequence = seq
        self.next_id = next_id
        self.terminal_ids = ids
        self.dirty = False

    def _read_slot(self, filename):
        try:
            with open(filename, "rb") as f:
                data = f.read()

            if len(data) != STATE_SIZE:
                return None

            stored_crc = struct.unpack_from(
                "<I",
                data,
                STATE_SIZE - 4
            )[0]

            calculated_crc = binascii.crc32(
                data[:-4]
            ) & 0xFFFFFFFF

            if stored_crc != calculated_crc:
                return None

            if data[:4] != STATE_MAGIC:
                return None

            if data[4] != STATE_VERSION:
                return None

            count = data[5]

            if count > COMPLETED_MAX:
                return None

            sequence = struct.unpack_from(
                "<I",
                data,
                8
            )[0]

            next_id = struct.unpack_from(
                "<I",
                data,
                12
            )[0]

            if next_id == 0:
                next_id = 1

            ids = []

            for i in range(count):
                offset = STATE_HEADER_SIZE + i * STATE_RECORD_SIZE
                value = struct.unpack_from(
                    "<I",
                    data,
                    offset
                )[0]

                if value != 0:
                    ids.append(value)

            return sequence, next_id, ids

        except Exception:
            return None

    def save(self):
        target_slot = 1 - self.active_slot
        filename = STATE_B if target_slot else STATE_A

        count = len(self.terminal_ids)

        if count > COMPLETED_MAX:
            self.terminal_ids = self.terminal_ids[-COMPLETED_MAX:]
            count = COMPLETED_MAX

        data = bytearray(STATE_SIZE)

        data[0:4] = STATE_MAGIC
        data[4] = STATE_VERSION
        data[5] = count

        struct.pack_into(
            "<I",
            data,
            8,
            (self.sequence + 1) & 0xFFFFFFFF
        )

        next_id = self.next_id & 0xFFFFFFFF

        if next_id == 0:
            next_id = 1

        struct.pack_into(
            "<I",
            data,
            12,
            next_id
        )

        for i, value in enumerate(self.terminal_ids):
            struct.pack_into(
                "<I",
                data,
                STATE_HEADER_SIZE + i * STATE_RECORD_SIZE,
                value & 0xFFFFFFFF
            )

        crc = binascii.crc32(data[:-4]) & 0xFFFFFFFF

        struct.pack_into(
            "<I",
            data,
            STATE_SIZE - 4,
            crc
        )

        tmp = filename + ".tmp"

        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()

            try:
                os.sync()
            except Exception:
                pass

            try:
                os.remove(filename)
            except Exception:
                pass

            os.rename(tmp, filename)

            self.sequence = (
                self.sequence + 1
            ) & 0xFFFFFFFF

            self.active_slot = target_slot
            self.dirty = False

        except Exception:
            try:
                os.remove(tmp)
            except Exception:
                pass
            raise

    def contains(self, command_id):
        return command_id in self.terminal_ids

    def add_terminal(self, command_id):
        if self.contains(command_id):
            return

        self.terminal_ids.append(command_id)

        if len(self.terminal_ids) > COMPLETED_MAX:
            del self.terminal_ids[
                :len(self.terminal_ids) - COMPLETED_MAX
            ]

        self.dirty = True
        self.save()

    def allocate(self):
        start = self.next_id

        while True:
            command_id = self.next_id

            self.next_id = (
                self.next_id + 1
            ) & 0xFFFFFFFF

            if self.next_id == 0:
                self.next_id = 1

            if not self.contains(command_id):
                self.save()
                return command_id

            if self.next_id == start:
                raise RuntimeError(
                    "command_id_exhausted"
                )


state = PersistentState()


def event_push(evt_type, handle=0):
    global event_head
    global event_tail
    global event_overflow

    nxt = (
        event_tail + 1
    ) % EVENT_MAX

    if nxt == event_head:
        event_overflow += 1
        return False

    offset = event_tail * EVENT_SIZE

    struct.pack_into(
        "<BI",
        event_buf,
        offset,
        evt_type & 0xFF,
        handle & 0xFFFFFFFF
    )

    event_tail = nxt
    return True


def event_pop():
    global event_head

    if event_head == event_tail:
        return None

    offset = event_head * EVENT_SIZE

    evt_type, handle = struct.unpack_from(
        "<BI",
        event_buf,
        offset
    )

    event_head = (
        event_head + 1
    ) % EVENT_MAX

    return evt_type, handle


def entry_size(entry):
    return 8 + len(entry["payload"])


def cmd_push(entry):
    global queue_used
    global mqtt_rejected

    if len(cmd_queue) >= CMD_QUEUE_MAX:
        mqtt_rejected += 1
        return False

    size = entry_size(entry)

    if queue_used + size > QUEUE_MAX_BYTES:
        mqtt_rejected += 1
        return False

    cmd_queue.append(entry)
    queue_used += size
    return True


def cmd_pop():
    for entry in cmd_queue:
        if not entry["in_flight"]:
            entry["in_flight"] = True
            return entry

    return None


def cmd_complete(entry):
    global queue_used

    try:
        cmd_queue.remove(entry)
        queue_used -= entry_size(entry)

        if queue_used < 0:
            queue_used = 0

    except ValueError:
        pass


def cmd_clear():
    global queue_used

    if mqtt_mgr is not None:
        for entry in cmd_queue:
            if entry["in_flight"]:
                mqtt_mgr.publish_json({
                    "id": entry["id"],
                    "status": "failed",
                    "reason": "emergency_clear"
                })

    cmd_queue.clear()
    queue_used = 0


class BLEBridge:
    def __init__(self, ble):
        self.ble = ble
        self.owner = None
        self.connections = {}
        self.in_flight_entry = None
        self.pending_cmd_request = False

        self.ble.active(True)
        self.ble.irq(self._irq)

        self._register_services()
        self._advertise()

    def _register_services(self):
        service = (
            _EXECUTOR_SERVICE_UUID,
            (
                (
                    _CMD_CHAR_UUID,
                    bluetooth.FLAG_WRITE |
                    bluetooth.FLAG_WRITE_NO_RESPONSE
                ),
                (
                    _NOTIFY_CHAR_UUID,
                    bluetooth.FLAG_READ |
                    bluetooth.FLAG_NOTIFY
                ),
                (
                    _STATUS_CHAR_UUID,
                    bluetooth.FLAG_READ
                ),
                (
                    _ACK_CHAR_UUID,
                    bluetooth.FLAG_WRITE |
                    bluetooth.FLAG_WRITE_NO_RESPONSE
                ),
                (
                    _AUTH_CHAR_UUID,
                    bluetooth.FLAG_WRITE |
                    bluetooth.FLAG_WRITE_NO_RESPONSE
                ),
            ),
        )

        (
            (
                self.handle_cmd,
                self.handle_notify,
                self.handle_status,
                self.handle_ack,
                self.handle_auth,
            ),
        ) = self.ble.gatts_register_services(
            [service]
        )

        self.ble.gatts_set_buffer(
            self.handle_cmd,
            1,
            True
        )

        self.ble.gatts_set_buffer(
            self.handle_ack,
            5 * 16,
            True
        )

        self.ble.gatts_set_buffer(
            self.handle_auth,
            len(AUTH_PIN) * 16,
            True
        )

        self.ble.gatts_set_buffer(
            self.handle_notify,
            MAX_CMD_PAYLOAD + 4,
            False
        )

        self.ble.gatts_write(
            self.handle_notify,
            b""
        )

        self.ble.gatts_write(
            self.handle_status,
            b"\x00"
        )

        self.ble.gatts_write(
            self.handle_ack,
            b""
        )

        self.ble.gatts_write(
            self.handle_auth,
            b""
        )

        self.ble.gatts_write(
            self.handle_cmd,
            b""
        )

    def _advertise(self):
        name = b"Bridge"

        uuid = bytes(
            self._service_uuid_bytes()
        )

        payload = bytearray()

        payload.extend(
            bytes((2, 0x01, 0x06))
        )

        payload.extend(
            bytes((len(name) + 1, 0x09))
        )

        payload.extend(name)

        payload.extend(
            bytes((len(uuid) + 1, 0x07))
        )

        payload.extend(uuid)

        try:
            self.ble.gap_advertise(
                100000,
                adv_data=bytes(payload)
            )
        except TypeError:
            self.ble.gap_advertise(
                100000,
                bytes(payload)
            )

    def _service_uuid_bytes(self):
        return self.ble_uuid_to_bytes(
            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
        )

    @staticmethod
    def ble_uuid_to_bytes(value):
        parts = value.split("-")

        a = bytes.fromhex(parts[0])
        b = bytes.fromhex(parts[1])
        c = bytes.fromhex(parts[2])
        d = bytes.fromhex(parts[3])
        e = bytes.fromhex(parts[4])

        return (
            a[::-1] +
            b[::-1] +
            c[::-1] +
            d[::-1] +
            e[::-1]
        )

    def _irq(self, event, data):
        if event == _IRQ_CENTRAL_CONNECT:
            conn_handle, addr_type, addr = data

            event_push(
                EVT_CONNECT,
                conn_handle
            )

        elif event == _IRQ_CENTRAL_DISCONNECT:
            conn_handle, addr_type, addr = data

            event_push(
                EVT_DISCONNECT,
                conn_handle
            )

        elif event == _IRQ_GATTS_WRITE:
            conn_handle, attr_handle = data

            if attr_handle == self.handle_cmd:
                event_push(
                    EVT_CMD_WRITE,
                    conn_handle
                )

            elif attr_handle == self.handle_ack:
                event_push(
                    EVT_ACK_WRITE,
                    conn_handle
                )

            elif attr_handle == self.handle_auth:
                event_push(
                    EVT_AUTH_WRITE,
                    conn_handle
                )

    def process_events(self):
        global ack_pending
        global auth_pending
        global pending_auth_handle

        while True:
            event = event_pop()

            if event is None:
                break

            event_type, handle = event

            if event_type == EVT_CONNECT:
                self.connections[handle] = {
                    "auth": False,
                    "connected_at": time.ticks_ms()
                }

                led.on()

            elif event_type == EVT_DISCONNECT:
                if self.owner == handle:
                    self.owner = None

                    if self.in_flight_entry is not None:
                        self.in_flight_entry["in_flight"] = False
                        self.in_flight_entry = None

                self.connections.pop(
                    handle,
                    None
                )

                if not self.connections:
                    led.off()
                    self._advertise()

            elif event_type == EVT_AUTH_WRITE:
                if pending_auth_handle is None:
                    pending_auth_handle = handle

                auth_pending = True

            elif event_type == EVT_CMD_WRITE:
                if handle != self.owner:
                    continue

                connection = self.connections.get(
                    handle
                )

                if connection is None:
                    continue

                elapsed = time.ticks_diff(
                    time.ticks_ms(),
                    connection["connected_at"]
                )

                if elapsed < 200:
                    self.pending_cmd_request = True
                else:
                    self._handle_cmd_request()

            elif event_type == EVT_ACK_WRITE:
                if handle == self.owner:
                    ack_pending = True

        if auth_pending:
            auth_pending = False
            self._process_auth_events()

        if ack_pending:
            ack_pending = False
            self._process_ack_events()

    def _process_auth_events(self):
        global pending_auth_handle

        handle = pending_auth_handle
        pending_auth_handle = None

        if handle is None:
            return

        if handle not in self.connections:
            self.ble.gatts_write(
                self.handle_auth,
                b""
            )
            return

        if self.owner is not None:
            self.ble.gatts_write(
                self.handle_auth,
                b""
            )
            return

        if len(self.connections) != 1:
            self.ble.gatts_write(
                self.handle_auth,
                b""
            )
            return

        data = self.ble.gatts_read(
            self.handle_auth
        )

        self.ble.gatts_write(
            self.handle_auth,
            b""
        )

        frame_size = len(AUTH_PIN)

        if frame_size == 0:
            return

        authenticated = False
        offset = 0

        while offset + frame_size <= len(data):
            frame = data[
                offset:
                offset + frame_size
            ]

            offset += frame_size

            if frame == AUTH_PIN:
                if self.owner is None:
                    self.owner = handle
                    self.connections[handle]["auth"] = True
                    authenticated = True
                    break

        self.ble.gatts_write(
            self.handle_auth,
            b"\x01" if authenticated else b"\x00"
        )

    def _process_ack_events(self):
        data = self.ble.gatts_read(
            self.handle_ack
        )

        self.ble.gatts_write(
            self.handle_ack,
            b""
        )

        frame_size = 5
        offset = 0

        while offset + frame_size <= len(data):
            ack_id = int.from_bytes(
                data[
                    offset:
                    offset + 4
                ],
                "little"
            )

            ack_status = data[
                offset + 4
            ]

            offset += frame_size

            self._handle_ack(
                ack_id,
                ack_status
            )

    def _handle_cmd_request(self):
        if self.owner is None:
            return

        if self.in_flight_entry is not None:
            return

        entry = cmd_pop()

        if entry is None:
            self.ble.gatts_write(
                self.handle_status,
                b"\x00"
            )
            return

        self.in_flight_entry = entry

        command_id = entry["id"]
        payload = entry["payload"]

        if len(payload) > MAX_CMD_PAYLOAD:
            self._report_failure(
                command_id,
                "payload_too_large"
            )

            self._complete_entry(entry)
            self.in_flight_entry = None
            return

        try:
            packet = (
                command_id.to_bytes(
                    4,
                    "little"
                ) +
                payload.encode()
            )

            if len(packet) > 20:
                raise ValueError("mtu")

            self.ble.gatts_notify(
                self.owner,
                self.handle_notify,
                packet
            )

            self.ble.gatts_write(
                self.handle_status,
                b"\x01"
            )

            entry["sent_at"] = time.ticks_ms()

        except Exception:
            self._requeue_in_flight()

    def _handle_ack(self, ack_id, ack_status):
        entry = self.in_flight_entry

        if entry is None:
            return

        if entry["id"] != ack_id:
            return

        if ack_status == 0:
            self._complete_entry(entry)
            self.in_flight_entry = None

            self.ble.gatts_write(
                self.handle_status,
                b"\x00"
            )

            return

        self._requeue_in_flight()

    def _requeue_in_flight(self):
        entry = self.in_flight_entry

        if entry is None:
            return

        entry["retries"] += 1

        if entry["retries"] > MAX_RETRIES:
            self._report_failure(
                entry["id"],
                "max_retries"
            )

            self._complete_entry(entry)
            self.in_flight_entry = None

            self.ble.gatts_write(
                self.handle_status,
                b"\x00"
            )

            return

        entry["in_flight"] = False
        self.in_flight_entry = None

        self.ble.gatts_write(
            self.handle_status,
            b"\x00"
        )

    def _complete_entry(self, entry):
        entry["in_flight"] = False

        cmd_complete(entry)

        try:
            state.add_terminal(
                entry["id"]
            )
        except Exception:
            pass

    def _report_failure(self, command_id, reason):
        if mqtt_mgr is not None:
            mqtt_mgr.publish_json({
                "id": command_id,
                "status": "failed",
                "reason": reason
            })

    def check_timeout(self):
        entry = self.in_flight_entry

        if entry is None:
            return

        elapsed = time.ticks_diff(
            time.ticks_ms(),
            entry.get(
                "sent_at",
                time.ticks_ms()
            )
        )

        if elapsed >= COMMAND_TIMEOUT_MS:
            self._requeue_in_flight()

    def process_pending_requests(self):
        if not self.pending_cmd_request:
            return

        if self.owner is None:
            self.pending_cmd_request = False
            return

        connection = self.connections.get(
            self.owner
        )

        if connection is None:
            self.pending_cmd_request = False
            return

        elapsed = time.ticks_diff(
            time.ticks_ms(),
            connection["connected_at"]
        )

        if elapsed >= 200:
            self.pending_cmd_request = False
            self._handle_cmd_request()


led = Pin(
    LED_PIN,
    Pin.OUT
)

button = Pin(
    BUTTON_PIN,
    Pin.IN,
    Pin.PULL_UP
)

wlan = network.WLAN(
    network.STA_IF
)


def wifi_connect():
    global wifi_state
    global wifi_retry_at

    now = time.ticks_ms()

    if wifi_state != 0:
        return

    if time.ticks_diff(
        now,
        wifi_retry_at
    ) < 0:
        return

    wlan.active(True)

    try:
        wlan.disconnect()
    except Exception:
        pass

    wlan.connect(
        WIFI_SSID,
        WIFI_PASS
    )

    wifi_state = 1


def wifi_tick():
    global wifi_state
    global wifi_retry_at

    if wifi_state == 0:
        wifi_connect()
        return False

    if wifi_state == 1:
        status = wlan.status()

        if status == network.STAT_GOT_IP:
            wifi_state = 2
            return True

        if status < 0:
            wifi_state = 0
            wifi_retry_at = (
                time.ticks_ms() + 5000
            )

            try:
                wlan.disconnect()
            except Exception:
                pass

            return False

        return False

    if wifi_state == 2:
        if wlan.isconnected():
            return True

        wifi_state = 0
        wifi_retry_at = (
            time.ticks_ms() + 5000
        )

        return False

    wifi_state = 0
    return False


class MQTTManager:
    def __init__(self):
        self.client = None
        self.connected = False
        self.backoff = 1
        self.last_attempt = 0

        self.msg_queue = [
            None
        ] * MQTT_QUEUE_MAX

        self.msg_head = 0
        self.msg_tail = 0
        self.dropped = 0

    def _enqueue(self, message):
        nxt = (
            self.msg_tail + 1
        ) % MQTT_QUEUE_MAX

        if nxt == self.msg_head:
            self.dropped += 1
            return False

        self.msg_queue[
            self.msg_tail
        ] = message

        self.msg_tail = nxt
        return True

    def connect(self):
        now = time.ticks_ms()

        if self.connected:
            return

        if time.ticks_diff(
            now,
            self.last_attempt
        ) < self.backoff * 1000:
            return

        self.last_attempt = now

        if self.client is not None:
            try:
                self.client.disconnect()
            except Exception:
                pass

            self.client = None

        try:
            ssl_params = {}

            if MQTT_PORT == 8883:
                ssl_params[
                    "server_hostname"
                ] = MQTT_BROKER

                if MQTT_VERIFY_CERT:
                    ssl_params[
                        "cert_reqs"
                    ] = "required"

                    ssl_params[
                        "ca_certs"
                    ] = MQTT_CA_CERT

            self.client = MQTTClient(
                MQTT_CLIENT_ID,
                MQTT_BROKER,
                port=MQTT_PORT,
                user=MQTT_USER,
                password=MQTT_PASS,
                ssl=(MQTT_PORT == 8883),
                ssl_params=ssl_params
            )

            self.client.set_callback(
                self._callback
            )

            self.client.connect()

            self.client.subscribe(
                MQTT_TOPIC_CMD
            )

            self.connected = True
            self.backoff = 1

        except Exception:
            self.connected = False

            if self.client is not None:
                try:
                    self.client.disconnect()
                except Exception:
                    pass

            self.client = None

            self.backoff = min(
                self.backoff * 2,
                300
            )

    def _callback(self, topic, message):
        self._enqueue(message)

    def publish_json(self, data):
        if not self.connected:
            return False

        try:
            payload = ujson.dumps(data)

            self.client.publish(
                MQTT_TOPIC_ACK,
                payload,
                retain=False
            )

            return True

        except Exception:
            self.connected = False

            if self.client is not None:
                try:
                    self.client.disconnect()
                except Exception:
                    pass

            self.client = None

            return False

    def process_pending(self):
        while self.msg_head != self.msg_tail:
            message = self.msg_queue[
                self.msg_head
            ]

            self.msg_queue[
                self.msg_head
            ] = None

            self.msg_head = (
                self.msg_head + 1
            ) % MQTT_QUEUE_MAX

            try:
                data = ujson.loads(message)

                if not isinstance(data, dict):
                    continue

                if data.get("secret") != SHARED_SECRET:
                    continue

                command = data.get("cmd")

                if not isinstance(command, str):
                    continue

                if not command:
                    continue

                command_id = data.get("id")

                if command_id is None:
                    command_id = state.allocate()

                else:
                    command_id = int(command_id)

                    if command_id <= 0:
                        self.publish_json({
                            "id": command_id,
                            "status": "rejected",
                            "reason": "invalid_id"
                        })
                        continue

                if state.contains(command_id):
                    self.publish_json({
                        "id": command_id,
                        "status": "duplicate"
                    })
                    continue

                if len(command) > MAX_CMD_PAYLOAD:
                    self.publish_json({
                        "id": command_id,
                        "status": "rejected",
                        "reason": "payload_too_large"
                    })
                    continue

                entry = {
                    "id": command_id,
                    "payload": command,
                    "retries": 0,
                    "in_flight": False,
                    "sent_at": 0
                }

                if not cmd_push(entry):
                    self.publish_json({
                        "id": command_id,
                        "status": "rejected",
                        "reason": "queue_full"
                    })
                    continue

                self.publish_json({
                    "id": command_id,
                    "status": "queued"
                })

            except Exception:
                continue

    def check(self):
        if not self.connected:
            return False

        try:
            self.client.check_msg()
            return True

        except Exception:
            self.connected = False

            if self.client is not None:
                try:
                    self.client.disconnect()
                except Exception:
                    pass

            self.client = None

            return False

    def heartbeat(self):
        if not self.connected:
            return

        try:
            status = {
                "queue": len(cmd_queue),
                "queue_bytes": queue_used,
                "owner": (
                    ble_bridge.owner is not None
                ),
                "connections": len(
                    ble_bridge.connections
                ),
                "event_overflow": event_overflow,
                "mqtt_dropped": self.dropped
            }

            self.client.publish(
                MQTT_TOPIC_STATUS,
                ujson.dumps(status),
                retain=False
            )

        except Exception:
            self.connected = False

            if self.client is not None:
                try:
                    self.client.disconnect()
                except Exception:
                    pass

            self.client = None


def main():
    global ble_bridge
    global mqtt_mgr

    ble = bluetooth.BLE()

    ble_bridge = BLEBridge(
        ble
    )

    mqtt_mgr = MQTTManager()

    wifi_connect()

    last_heartbeat = time.ticks_ms()
    last_advert = time.ticks_ms()
    last_button_check = time.ticks_ms()

    button_pressed_start = None

    while True:
        now = time.ticks_ms()

        ble_bridge.process_events()
        ble_bridge.process_pending_requests()
        ble_bridge.check_timeout()

        mqtt_mgr.process_pending()

        wifi_connected = wifi_tick()

        if (
            wifi_connected and
            not mqtt_mgr.connected
        ):
            mqtt_mgr.connect()

        mqtt_mgr.check()

        if time.ticks_diff(
            now,
            last_advert
        ) >= 30000:
            if not ble_bridge.connections:
                ble_bridge._advertise()

            last_advert = now

        if time.ticks_diff(
            now,
            last_heartbeat
        ) >= 60000:
            mqtt_mgr.heartbeat()
            last_heartbeat = now

        if time.ticks_diff(
            now,
            last_button_check
        ) >= 50:

            if button.value() == 0:

                if button_pressed_start is None:
                    button_pressed_start = now

                elif time.ticks_diff(
                    now,
                    button_pressed_start
                ) >= 2000:

                    cmd_clear()

                    ble_bridge.in_flight_entry = None
                    ble_bridge.pending_cmd_request = False
                    ble_bridge.owner = None

                    for handle in list(
                        ble_bridge.connections
                    ):
                        try:
                            ble.gap_disconnect(
                                handle
                            )
                        except Exception:
                            pass

                    button_pressed_start = None

            else:
                button_pressed_start = None

            last_button_check = now

        time.sleep_ms(50)


if __name__ == "__main__":
    main()
