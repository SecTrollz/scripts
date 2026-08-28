#!/usr/bin/env python3
"""
ngrok_tunnel.py -- a self-hosted, pure-stdlib reverse tunnel (ngrok-style).

Expose a service running on your machine to the public internet through a
relay server you control. No third-party account, no paid plan, and no
external Python packages -- everything here is standard library, so it
runs the same way on any machine that has Python 3.9+ and a terminal.

ARCHITECTURE
    You run two pieces:

      1. `server` -- the public relay. Runs on any machine with a public IP
         (a cheap VPS works great). It accepts a persistent control
         connection from your client and multiplexes public traffic to it
         over that single connection.

      2. `http` / `tcp` -- the client. Runs on your laptop/desktop next to
         the local service you want to expose. It dials OUT to the server
         (so it works from behind NAT/firewalls with zero port-forwarding
         on your side) and registers one or more tunnels.

QUICK START
    On your VPS (public IP 203.0.113.10):
        python3 ngrok_tunnel.py gen-token
        python3 ngrok_tunnel.py server --token <secret> \\
            --control-port 9000 --http-port 8080 --public-host 203.0.113.10

    On your laptop, expose a local web server running on :5000:
        python3 ngrok_tunnel.py http 5000 --server 203.0.113.10:9000 \\
            --token <secret> --subdomain myapp
        # -> http://myapp.203.0.113.10:8080  forwards to  127.0.0.1:5000

    Expose a raw TCP service (e.g. SSH on :22) instead:
        python3 ngrok_tunnel.py tcp 22 --server 203.0.113.10:9000 \\
            --token <secret> --remote-port 20022
        # -> 203.0.113.10:20022  forwards to  127.0.0.1:22

NOTES
    * For subdomain-based HTTP routing (myapp.example.com) point a wildcard
      DNS record ("*.example.com") at the server's IP, and pass
      --domain example.com when starting the server.
    * For HTTPS, provide --https-port plus --cert/--key for a certificate
      valid for your domain(s) (e.g. a wildcard cert from Let's Encrypt).
      The server terminates TLS and routes by the decrypted Host header,
      exactly like the plain HTTP path.
    * Always set --token in production. Without it, anyone who can reach
      the control port can open tunnels through your server.
    * The client automatically reconnects with exponential backoff if the
      connection to the server drops.
    * TCP tunnel ports are restricted to --tcp-port-range unless the
      server is started with --allow-any-port.

Requires Python 3.9+. No third-party dependencies.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import hmac
import itertools
import json
import logging
import secrets
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

LOG = logging.getLogger("tunnel")

# --------------------------------------------------------------------------
# Wire protocol
#
# Every message on the control connection is a fixed 9-byte header followed
# by an optional payload:
#
#   [ 1 byte type ][ 4 byte stream_id ][ 4 byte payload length ][ payload ]
#
# stream_id is 0 for connection-level messages (HELLO, PING, ...) and a
# per-connection unique id for anything tied to one proxied TCP stream.
# --------------------------------------------------------------------------

FRAME_HEADER = struct.Struct("!BII")
MAX_FRAME_SIZE = 1 << 20  # 1 MiB; well above our own CHUNK_SIZE writes
CHUNK_SIZE = 64 * 1024

MSG_HELLO = 0x01       # client -> server: {"token": str, "tunnels": [...]}
MSG_HELLO_ACK = 0x02   # server -> client: {"tunnels": [...]}
MSG_NEW_STREAM = 0x03  # server -> client: {"tunnel_id": str}
MSG_DATA = 0x04        # both ways: raw bytes for stream_id
MSG_CLOSE = 0x05       # both ways: stream_id finished
MSG_PING = 0x06
MSG_PONG = 0x07
MSG_ERROR = 0x08       # server -> client: {"error": str}


class ProtocolError(Exception):
    """Raised for malformed or disallowed control-protocol traffic."""


async def write_frame(writer: asyncio.StreamWriter, msg_type: int, stream_id: int,
                       payload: bytes = b"") -> None:
    writer.write(FRAME_HEADER.pack(msg_type, stream_id, len(payload)) + payload)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
    header = await reader.readexactly(FRAME_HEADER.size)
    msg_type, stream_id, length = FRAME_HEADER.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise ProtocolError(f"frame too large ({length} bytes)")
    payload = await reader.readexactly(length) if length else b""
    return msg_type, stream_id, payload


# --------------------------------------------------------------------------
# Tiny HTTP helpers (just enough to read a request's Host header so the
# server can route a shared HTTP/HTTPS port by subdomain, without pulling
# in a full HTTP library)
# --------------------------------------------------------------------------

def parse_host_header(head: bytes) -> Optional[str]:
    try:
        text = head.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    except Exception:
        return None
    for line in text.split("\r\n")[1:]:
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None


async def read_http_head(reader: asyncio.StreamReader, limit: int = 16384) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > limit:
            raise ProtocolError("request headers too large")
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("connection closed before headers completed")
        buf += chunk
    return buf


def _http_response(status: str, body: bytes) -> bytes:
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii") + body


HTTP_404 = _http_response("404 Not Found", b"Unknown tunnel subdomain")


def parse_port_range(spec: str) -> tuple[int, int]:
    try:
        lo, hi = spec.split("-", 1)
        lo, hi = int(lo), int(hi)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port range: {spec!r} (expected LOW-HIGH)")
    if not (0 < lo <= hi < 65536):
        raise argparse.ArgumentTypeError(f"invalid port range: {spec!r}")
    return lo, hi


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

@dataclass
class TunnelInfo:
    tunnel_id: str
    kind: str  # "http" or "tcp"
    local_port: int
    subdomain: Optional[str] = None
    remote_port: Optional[int] = None
    listener: Optional[asyncio.AbstractServer] = None
    public_url: str = ""


class ClientSession:
    def __init__(self, session_id: str, writer: asyncio.StreamWriter):
        self.id = session_id
        self.writer = writer
        self.tunnels: dict[str, TunnelInfo] = {}
        self.streams: dict[int, asyncio.StreamWriter] = {}
        self._stream_ids = itertools.count(1)
        self.last_seen = time.monotonic()

    def next_stream_id(self) -> int:
        return next(self._stream_ids)

    async def send(self, msg_type: int, stream_id: int, payload: bytes = b"") -> None:
        await write_frame(self.writer, msg_type, stream_id, payload)


class TunnelServer:
    def __init__(self, args: argparse.Namespace):
        self.bind = args.bind
        self.control_port = args.control_port
        self.http_port = args.http_port
        self.https_port = args.https_port
        self.cert = args.cert
        self.key = args.key
        self.domain = args.domain
        self.token = args.token
        self.tcp_port_range = args.tcp_port_range
        self.allow_any_port = args.allow_any_port
        self.public_host = args.public_host or (
            self.bind if self.bind not in ("0.0.0.0", "::") else "YOUR_SERVER_IP"
        )
        self.sessions: dict[str, ClientSession] = {}
        self.http_routes: dict[str, tuple[ClientSession, str]] = {}
        self.used_tcp_ports: set[int] = set()

    # -- lifecycle ---------------------------------------------------

    async def start(self) -> None:
        servers = []
        control_srv = await asyncio.start_server(
            self.handle_control, host=self.bind, port=self.control_port)
        servers.append(control_srv)
        LOG.info("control server listening on %s:%s", self.bind, self.control_port)

        if not self.token:
            LOG.warning(
                "no --token configured: ANYONE who can reach the control port "
                "can open tunnels through this server")

        http_srv = await asyncio.start_server(
            self.on_http_conn, host=self.bind, port=self.http_port)
        servers.append(http_srv)
        LOG.info("http server listening on %s:%s", self.bind, self.http_port)

        if self.https_port:
            if not (self.cert and self.key):
                raise SystemExit("--https-port requires --cert and --key")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert, self.key)
            https_srv = await asyncio.start_server(
                self.on_http_conn, host=self.bind, port=self.https_port, ssl=ctx)
            servers.append(https_srv)
            LOG.info("https server listening on %s:%s", self.bind, self.https_port)

        if not self.domain:
            LOG.warning(
                "no --domain set: HTTP tunnel URLs will use %s directly; set the "
                "Host header manually (curl -H 'Host: <subdomain>') or configure "
                "wildcard DNS + --domain for real subdomain URLs", self.public_host)

        async with contextlib.AsyncExitStack() as stack:
            for s in servers:
                stack.push_async_callback(s.wait_closed)
                stack.callback(s.close)
            await asyncio.gather(*(s.serve_forever() for s in servers))

    # -- control connection -------------------------------------------

    async def handle_control(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        session: Optional[ClientSession] = None
        try:
            msg_type, _, payload = await read_frame(reader)
            if msg_type != MSG_HELLO:
                raise ProtocolError("expected HELLO as first message")
            hello = json.loads(payload)

            if self.token and not hmac.compare_digest(str(hello.get("token", "")), self.token):
                await write_frame(writer, MSG_ERROR, 0,
                                   json.dumps({"error": "invalid token"}).encode())
                LOG.warning("rejected control connection from %s: bad token", peer)
                return

            session = ClientSession(secrets.token_hex(8), writer)
            ack_tunnels = []
            try:
                for req in hello.get("tunnels", []):
                    info = await self.register_tunnel(session, req)
                    ack_tunnels.append({
                        "id": info.tunnel_id,
                        "type": info.kind,
                        "public_url": info.public_url,
                        "remote_port": info.remote_port,
                    })
            except ProtocolError as e:
                await write_frame(writer, MSG_ERROR, 0, json.dumps({"error": str(e)}).encode())
                LOG.warning("rejected tunnel request from %s: %s", peer, e)
                return

            await write_frame(writer, MSG_HELLO_ACK, 0, json.dumps({"tunnels": ack_tunnels}).encode())
            self.sessions[session.id] = session
            LOG.info("client %s connected from %s with %d tunnel(s)",
                      session.id, peer, len(ack_tunnels))
            for t in ack_tunnels:
                LOG.info("  -> %s", t["public_url"])

            await self.control_loop(session, reader)
        except (asyncio.IncompleteReadError, ConnectionError, ProtocolError) as e:
            LOG.info("control connection from %s ended: %s", peer, e)
        except Exception:
            LOG.exception("unexpected error handling control connection from %s", peer)
        finally:
            await self.cleanup_session(session)
            with contextlib.suppress(Exception):
                writer.close()

    async def control_loop(self, session: ClientSession, reader: asyncio.StreamReader) -> None:
        while True:
            msg_type, stream_id, payload = await read_frame(reader)
            session.last_seen = time.monotonic()
            if msg_type == MSG_DATA:
                w = session.streams.get(stream_id)
                if w is not None:
                    w.write(payload)
                    await w.drain()
            elif msg_type == MSG_CLOSE:
                w = session.streams.pop(stream_id, None)
                if w is not None:
                    with contextlib.suppress(Exception):
                        w.close()
            elif msg_type == MSG_PING:
                await session.send(MSG_PONG, 0)
            elif msg_type == MSG_PONG:
                pass
            else:
                LOG.debug("ignoring unexpected message type %s from client %s",
                          msg_type, session.id)

    async def cleanup_session(self, session: Optional[ClientSession]) -> None:
        if session is None:
            return
        self.sessions.pop(session.id, None)
        for info in session.tunnels.values():
            if info.kind == "tcp":
                if info.listener is not None:
                    info.listener.close()
                if info.remote_port is not None:
                    self.used_tcp_ports.discard(info.remote_port)
            elif info.kind == "http" and info.subdomain in self.http_routes:
                del self.http_routes[info.subdomain]
        for w in session.streams.values():
            with contextlib.suppress(Exception):
                w.close()
        session.streams.clear()
        LOG.info("client %s disconnected, tunnels released", session.id)

    # -- tunnel registration -------------------------------------------

    def allocate_tcp_port(self, requested: int) -> int:
        lo, hi = self.tcp_port_range
        if requested:
            if not self.allow_any_port and not (lo <= requested <= hi):
                raise ProtocolError(
                    f"requested port {requested} outside allowed range {lo}-{hi}")
            if requested in self.used_tcp_ports:
                raise ProtocolError(f"port {requested} is already in use")
            self.used_tcp_ports.add(requested)
            return requested
        for p in range(lo, hi + 1):
            if p not in self.used_tcp_ports:
                self.used_tcp_ports.add(p)
                return p
        raise ProtocolError("no free ports left in --tcp-port-range")

    async def register_tunnel(self, session: ClientSession, req: dict) -> TunnelInfo:
        kind = req.get("type")
        local_port = req.get("local_port")
        if kind not in ("http", "tcp") or not isinstance(local_port, int):
            raise ProtocolError(f"malformed tunnel request: {req!r}")

        tunnel_id = secrets.token_hex(4)

        if kind == "tcp":
            port = self.allocate_tcp_port(int(req.get("remote_port") or 0))
            try:
                listener = await asyncio.start_server(
                    functools.partial(self.on_public_tcp_conn, session, tunnel_id),
                    host=self.bind, port=port)
            except OSError as e:
                self.used_tcp_ports.discard(port)
                raise ProtocolError(f"could not bind remote port {port}: {e}")
            info = TunnelInfo(tunnel_id, "tcp", local_port, remote_port=port, listener=listener)
            info.public_url = f"tcp://{self.public_host}:{port}"

        else:  # http
            subdomain = req.get("subdomain") or secrets.token_hex(3)
            if subdomain in self.http_routes:
                raise ProtocolError(f"subdomain {subdomain!r} is already in use")
            self.http_routes[subdomain] = (session, tunnel_id)
            info = TunnelInfo(tunnel_id, "http", local_port, subdomain=subdomain)
            proto = "https" if self.https_port else "http"
            port = self.https_port if proto == "https" else self.http_port
            port_part = "" if port in (80, 443) else f":{port}"
            host = self.domain or self.public_host
            info.public_url = f"{proto}://{subdomain}.{host}{port_part}"

        session.tunnels[tunnel_id] = info
        return info

    # -- public-facing connections --------------------------------------

    async def pump_public_to_control(self, session: ClientSession, stream_id: int,
                                      reader: asyncio.StreamReader) -> None:
        try:
            while True:
                chunk = await reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                await session.send(MSG_DATA, stream_id, chunk)
        except (ConnectionError, OSError):
            pass
        finally:
            w = session.streams.pop(stream_id, None)
            if w is not None:
                with contextlib.suppress(Exception):
                    w.close()
            with contextlib.suppress(Exception):
                await session.send(MSG_CLOSE, stream_id)

    async def on_public_tcp_conn(self, session: ClientSession, tunnel_id: str,
                                  reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> None:
        stream_id = session.next_stream_id()
        session.streams[stream_id] = writer
        await session.send(MSG_NEW_STREAM, stream_id, json.dumps({"tunnel_id": tunnel_id}).encode())
        await self.pump_public_to_control(session, stream_id, reader)

    async def on_http_conn(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        try:
            head = await read_http_head(reader)
        except (ConnectionError, ProtocolError):
            with contextlib.suppress(Exception):
                writer.close()
            return

        host_header = parse_host_header(head) or ""
        subdomain = host_header.split(":")[0].split(".")[0] if host_header else ""
        route = self.http_routes.get(subdomain)
        if route is None:
            writer.write(HTTP_404)
            with contextlib.suppress(Exception):
                await writer.drain()
            writer.close()
            return

        session, tunnel_id = route
        stream_id = session.next_stream_id()
        session.streams[stream_id] = writer
        await session.send(MSG_NEW_STREAM, stream_id, json.dumps({"tunnel_id": tunnel_id}).encode())
        await session.send(MSG_DATA, stream_id, head)
        await self.pump_public_to_control(session, stream_id, reader)


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

class TunnelClient:
    def __init__(self, args: argparse.Namespace):
        host, _, port = args.server.rpartition(":")
        if not host or not port.isdigit():
            raise SystemExit(f"--server must look like host:port, got {args.server!r}")
        self.host = host
        self.port = int(port)
        self.token = args.token
        self.use_tls = args.tls
        self.local_host = args.local_host
        self.local_port = args.local_port
        self.kind = args.command  # "http" or "tcp"
        self.subdomain = getattr(args, "subdomain", None)
        self.remote_port = getattr(args, "remote_port", 0)

    async def run(self) -> None:
        delay = 1
        while True:
            try:
                await self.connect_once()
                delay = 1  # clean reconnect after a healthy session
            except asyncio.CancelledError:
                raise
            except (ConnectionError, OSError, asyncio.IncompleteReadError, ProtocolError) as e:
                LOG.warning("disconnected (%s) -- reconnecting in %ss", e, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)

    async def connect_once(self) -> None:
        ssl_ctx = ssl.create_default_context() if self.use_tls else None
        reader, writer = await asyncio.open_connection(self.host, self.port, ssl=ssl_ctx)

        req = {"type": self.kind, "local_port": self.local_port}
        if self.kind == "http" and self.subdomain:
            req["subdomain"] = self.subdomain
        if self.kind == "tcp" and self.remote_port:
            req["remote_port"] = self.remote_port

        hello = {"token": self.token or "", "tunnels": [req]}
        await write_frame(writer, MSG_HELLO, 0, json.dumps(hello).encode())

        msg_type, _, payload = await read_frame(reader)
        if msg_type == MSG_ERROR:
            raise ProtocolError(json.loads(payload).get("error", "server rejected request"))
        if msg_type != MSG_HELLO_ACK:
            raise ProtocolError("unexpected reply from server")

        ack = json.loads(payload)
        for t in ack.get("tunnels", []):
            dest = f"{self.local_host}:{self.local_port}"
            print(f"Forwarding  {t['public_url']}  ->  {dest}")

        # Inbound data for a stream (headers, request/response bytes coming
        # from the server) can arrive before the local connection for that
        # stream has finished opening. Route it through a per-stream queue
        # rather than a plain dict of writers so nothing is dropped while
        # open_local_stream() is still connecting.
        streams: dict[int, asyncio.Queue] = {}
        ka_task = asyncio.create_task(self._keepalive(writer))
        try:
            while True:
                msg_type, stream_id, payload = await read_frame(reader)
                if msg_type == MSG_NEW_STREAM:
                    q: asyncio.Queue = asyncio.Queue()
                    streams[stream_id] = q
                    asyncio.create_task(self.open_local_stream(writer, streams, stream_id, q))
                elif msg_type == MSG_DATA:
                    q = streams.get(stream_id)
                    if q is not None:
                        q.put_nowait(payload)
                elif msg_type == MSG_CLOSE:
                    q = streams.pop(stream_id, None)
                    if q is not None:
                        q.put_nowait(None)  # sentinel: stop feeding the local socket
                elif msg_type == MSG_PING:
                    await write_frame(writer, MSG_PONG, 0)
                elif msg_type == MSG_PONG:
                    pass
        finally:
            ka_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ka_task
            for q in streams.values():
                q.put_nowait(None)
            with contextlib.suppress(Exception):
                writer.close()

    @staticmethod
    async def _keepalive(writer: asyncio.StreamWriter) -> None:
        while True:
            await asyncio.sleep(20)
            await write_frame(writer, MSG_PING, 0)

    async def open_local_stream(self, control_writer: asyncio.StreamWriter,
                                 streams: dict[int, asyncio.Queue],
                                 stream_id: int, inbound: asyncio.Queue) -> None:
        try:
            local_reader, local_writer = await asyncio.open_connection(
                self.local_host, self.local_port)
        except OSError as e:
            LOG.warning("cannot reach local service %s:%s (%s)",
                        self.local_host, self.local_port, e)
            streams.pop(stream_id, None)
            with contextlib.suppress(Exception):
                await write_frame(control_writer, MSG_CLOSE, stream_id)
            return

        async def feed_local() -> None:
            try:
                while True:
                    item = await inbound.get()
                    if item is None:
                        break
                    local_writer.write(item)
                    await local_writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    local_writer.close()

        feed_task = asyncio.create_task(feed_local())
        try:
            while True:
                chunk = await local_reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                await write_frame(control_writer, MSG_DATA, stream_id, chunk)
        except (ConnectionError, OSError):
            pass
        finally:
            streams.pop(stream_id, None)
            feed_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await feed_task
            with contextlib.suppress(Exception):
                local_writer.close()
            with contextlib.suppress(Exception):
                await write_frame(control_writer, MSG_CLOSE, stream_id)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ngrok_tunnel.py",
        description="Self-hosted, pure-stdlib reverse tunnel (ngrok-style).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-v", "--verbose", action="count", default=0,
                         help="increase log verbosity (-v, -vv)")
    sub = parser.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("server", help="run the public relay server")
    sp.add_argument("--bind", default="0.0.0.0", help="address to listen on (default: 0.0.0.0)")
    sp.add_argument("--control-port", type=int, default=9000,
                     help="port clients dial in to (default: 9000)")
    sp.add_argument("--http-port", type=int, default=8080,
                     help="shared public HTTP port for http tunnels (default: 8080)")
    sp.add_argument("--https-port", type=int, default=None,
                     help="shared public HTTPS port for http tunnels (requires --cert/--key)")
    sp.add_argument("--cert", default=None, help="TLS certificate file (PEM) for --https-port")
    sp.add_argument("--key", default=None, help="TLS private key file (PEM) for --https-port")
    sp.add_argument("--domain", default=None,
                     help="base domain for subdomain routing, e.g. tunnel.example.com "
                          "(requires wildcard DNS pointed at this server)")
    sp.add_argument("--public-host", default=None,
                     help="hostname/IP to print in generated URLs (default: --bind, or "
                          "a placeholder if --bind is 0.0.0.0)")
    sp.add_argument("--token", default=None,
                     help="shared auth token clients must present (strongly recommended)")
    sp.add_argument("--tcp-port-range", type=parse_port_range, default=(20000, 20100),
                     help="allowed port range LOW-HIGH for tcp tunnels (default: 20000-20100)")
    sp.add_argument("--allow-any-port", action="store_true",
                     help="let clients request any remote TCP port, ignoring --tcp-port-range")

    def add_client_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("local_port", type=int, help="local port to expose")
        p.add_argument("--server", required=True, metavar="HOST:PORT",
                        help="relay server's control address, e.g. 203.0.113.10:9000")
        p.add_argument("--token", default=None, help="auth token expected by the server")
        p.add_argument("--local-host", default="127.0.0.1",
                        help="local address the service is bound to (default: 127.0.0.1)")
        p.add_argument("--tls", action="store_true",
                        help="use TLS for the control connection to the server")

    hp = sub.add_parser("http", help="expose a local HTTP service")
    add_client_args(hp)
    hp.add_argument("--subdomain", default=None,
                     help="requested subdomain (default: randomly assigned by the server)")

    tp = sub.add_parser("tcp", help="expose a local TCP service (any protocol)")
    add_client_args(tp)
    tp.add_argument("--remote-port", type=int, default=0,
                     help="requested public port (default: first free port in the server's range)")

    sub.add_parser("gen-token", help="print a random secure token for --token")

    return parser


async def async_main(args: argparse.Namespace) -> None:
    if args.command == "server":
        await TunnelServer(args).start()
    elif args.command in ("http", "tcp"):
        await TunnelClient(args).run()
    elif args.command == "gen-token":
        print(secrets.token_urlsafe(32))
    else:  # pragma: no cover - argparse guards this
        raise SystemExit(f"unknown command: {args.command}")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    level = max(logging.DEBUG, logging.WARNING - 10 * args.verbose)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(message)s")
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
