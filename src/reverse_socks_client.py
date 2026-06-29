#!/usr/bin/env python3
"""
Reverse SOCKS5 Proxy Client (Standalone) - Auto-detecting Control Link

Connects outbound to a reverse SOCKS5 server and tunnels the server's SOCKS5
traffic through to local destinations.

The control link is auto-detected on first connect:
  * Plain TCP is tried first (the common case: localhost testing, or running
    behind a TLS terminator / VPN like Tailscale where the app sees plaintext).
  * If the server doesn't speak plain, the client falls back to TLS.
  * Whichever mode succeeds is remembered and reused for reconnects, so there is
    no per-reconnect probing cost and no flag/coordination needed.

Override with --plain or --tls if you want to force a mode.
"""
import asyncio
import argparse
import logging
import socket
import struct
import ssl
from enum import IntEnum
from typing import Dict, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# How long to wait for the server to echo our handshake HEARTBEAT before
# declaring a mode mismatch and trying the other transport.
PROBE_TIMEOUT = 4.0

# ============== Protocol Definitions ==============

class MessageType(IntEnum):
    REGISTER = 0x01
    NEW_CONN = 0x02
    CONNECT = 0x03
    CONNECT_REPLY = 0x04
    DATA = 0x05
    CLOSE = 0x06
    HEARTBEAT = 0x07

class AddressType(IntEnum):
    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04

async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)

async def write_message(writer: asyncio.StreamWriter, msg_type: int, conn_id: int, payload: bytes = b''):
    header = struct.pack('!BII', msg_type, conn_id, len(payload))
    writer.write(header + payload)
    await writer.drain()

async def read_message(reader: asyncio.StreamReader) -> Tuple[int, int, bytes]:
    header = await read_exact(reader, 9)
    msg_type, conn_id, length = struct.unpack('!BII', header)
    payload = await read_exact(reader, length) if length > 0 else b''
    return msg_type, conn_id, payload

def unpack_address(data: bytes) -> Tuple[int, str, int, int]:
    atype = data[0]
    if atype == AddressType.IPV4:
        addr = socket.inet_ntoa(data[1:5])
        port = struct.unpack('!H', data[5:7])[0]
        return atype, addr, port, 7
    elif atype == AddressType.DOMAIN:
        length = data[1]
        addr = data[2:2+length].decode('utf-8')
        port = struct.unpack('!H', data[2+length:4+length])[0]
        return atype, addr, port, 4 + length
    elif atype == AddressType.IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
        port = struct.unpack('!H', data[17:19])[0]
        return atype, addr, port, 19
    raise ValueError(f"Unknown address type: {atype}")

# ============== Client Implementation ==============

class TunnelConnection:
    def __init__(self, conn_id: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.conn_id = conn_id
        self.reader = reader
        self.writer = writer
        self.closed = False

class ReverseClient:
    def __init__(self, server_host: str, server_port: int,
                 force_mode: Optional[str] = None, insecure: bool = False):
        """
        force_mode: 'plain' | 'tls' | None (None = auto-detect, plain first)
        """
        self.server_host = server_host
        self.server_port = server_port
        self.force_mode = force_mode
        self.insecure = insecure
        # tls_mode is None until the transport is confirmed; then True/False.
        self.tls_mode: Optional[bool] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self.server_reader: Optional[asyncio.StreamReader] = None
        self.server_writer: Optional[asyncio.StreamWriter] = None
        self.tunnels: Dict[int, TunnelConnection] = {}
        self.lock = asyncio.Lock()
        self.running = True
        self.write_lock = asyncio.Lock()

    def _ssl(self) -> ssl.SSLContext:
        if self._ssl_context is None:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._ssl_context = ctx
        return self._ssl_context

    async def _open(self, use_tls: bool):
        if use_tls:
            return await asyncio.open_connection(
                self.server_host, self.server_port,
                ssl=self._ssl(), server_hostname=self.server_host,
            )
        return await asyncio.open_connection(self.server_host, self.server_port)

    async def _probe_handshake(self, reader, writer) -> Optional[Tuple[int, int, bytes]]:
        """
        Send REGISTER + HEARTBEAT and wait for any valid protocol reply.
        Returns the first message (to be replayed into the handler) on success,
        or None if this transport does not speak our protocol.
        """
        try:
            await write_message(writer, MessageType.REGISTER, 0, b'client')
            await write_message(writer, MessageType.HEARTBEAT, 0)
            msg = await asyncio.wait_for(read_message(reader), timeout=PROBE_TIMEOUT)
            return msg
        except Exception as e:
            logger.debug(f"Probe failed: {e}")
            return None

    def _mode_order(self):
        if self.force_mode == 'plain':
            return [False]
        if self.force_mode == 'tls':
            return [True]
        if self.tls_mode is not None:
            return [self.tls_mode]  # sticky: reuse the confirmed transport
        return [False, True]  # auto: plain first, then TLS

    async def connect_to_server(self):
        while self.running:
            established = False
            for use_tls in self._mode_order():
                if not self.running:
                    break
                reader = writer = None
                try:
                    reader, writer = await self._open(use_tls)
                    first = await self._probe_handshake(reader, writer)
                    if first is None:
                        logger.debug(f"Transport {'TLS' if use_tls else 'plain'} did not respond; trying next")
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except Exception:
                            pass
                        continue

                    # Link confirmed.
                    self.server_reader, self.server_writer = reader, writer
                    newly_tls = use_tls
                    if self.tls_mode is None:
                        self.tls_mode = newly_tls
                    mode_label = 'TLS' if newly_tls else 'plain TCP'
                    if self.force_mode is None and len(self._mode_order()) > 1:
                        logger.info(f"Auto-detected control link: {mode_label}")
                    logger.info(f"Connected and registered with server ({mode_label})")
                    established = True
                    await self.handle_server_messages(first)
                    break  # disconnected; outer loop reconnects (mode is now sticky)
                except Exception as e:
                    logger.debug(f"Connection attempt ({'TLS' if use_tls else 'plain'}) error: {e}")
                    if writer is not None:
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except Exception:
                            pass
            if not established and self.running:
                logger.info("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

    async def handle_server_messages(self, first: Optional[Tuple[int, int, bytes]] = None):
        try:
            pending = [first] if first is not None else []
            while self.running:
                if pending:
                    msg_type, conn_id, payload = pending.pop(0)
                else:
                    msg_type, conn_id, payload = await read_message(self.server_reader)
                if msg_type == MessageType.CONNECT:
                    asyncio.create_task(self.handle_connect(conn_id, payload))
                elif msg_type == MessageType.DATA:
                    async with self.lock:
                        tunnel = self.tunnels.get(conn_id)
                    if tunnel and not tunnel.closed:
                        try:
                            tunnel.writer.write(payload)
                            await tunnel.writer.drain()
                        except Exception as e:
                            logger.debug(f"Error writing to tunnel {conn_id}: {e}")
                elif msg_type == MessageType.CLOSE:
                    await self.close_tunnel(conn_id)
                elif msg_type == MessageType.HEARTBEAT:
                    async with self.write_lock:
                        await write_message(self.server_writer, MessageType.HEARTBEAT, 0)
        except asyncio.IncompleteReadError:
            logger.info("Server connection closed")
        except Exception as e:
            logger.error(f"Error handling server messages: {e}")

    async def handle_connect(self, conn_id: int, payload: bytes):
        try:
            atype, addr, port, _ = unpack_address(payload)
            logger.info(f"Connect request {conn_id}: {addr}:{port}")
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(addr, port), timeout=30.0
                )
                tunnel = TunnelConnection(conn_id, reader, writer)
                async with self.lock:
                    self.tunnels[conn_id] = tunnel
                async with self.write_lock:
                    await write_message(self.server_writer, MessageType.CONNECT_REPLY, conn_id, b'\x00')
                asyncio.create_task(self.forward_from_target(tunnel))
                logger.info(f"Connection {conn_id} established to local target {addr}:{port}")
            except asyncio.TimeoutError:
                logger.warning(f"Connection {conn_id} to {addr}:{port} timed out")
                async with self.write_lock:
                    await write_message(self.server_writer, MessageType.CONNECT_REPLY, conn_id, b'\x04')
            except OSError as e:
                logger.warning(f"Connection {conn_id} to {addr}:{port} failed: {e}")
                reply = b'\x01'
                if e.errno in (111, 10061): reply = b'\x05'
                elif e.errno in (113, 10065): reply = b'\x04'
                elif e.errno in (101, 10051): reply = b'\x03'
                async with self.write_lock:
                    await write_message(self.server_writer, MessageType.CONNECT_REPLY, conn_id, reply)
        except Exception as e:
            logger.error(f"Error handling connect {conn_id}: {e}")
            try:
                async with self.write_lock:
                    await write_message(self.server_writer, MessageType.CONNECT_REPLY, conn_id, b'\x01')
            except: pass

    async def forward_from_target(self, tunnel: TunnelConnection):
        try:
            while not tunnel.closed:
                data = await tunnel.reader.read(65536)
                if not data:
                    break
                async with self.write_lock:
                    await write_message(self.server_writer, MessageType.DATA, tunnel.conn_id, data)
        except Exception as e:
            logger.debug(f"Forward from target {tunnel.conn_id} error: {e}")
        finally:
            await self.close_tunnel(tunnel.conn_id)

    async def close_tunnel(self, conn_id: int):
        async with self.lock:
            tunnel = self.tunnels.pop(conn_id, None)
        if tunnel and not tunnel.closed:
            tunnel.closed = True
            try:
                tunnel.writer.close()
                await tunnel.writer.wait_closed()
            except: pass
            try:
                async with self.write_lock:
                    await write_message(self.server_writer, MessageType.CLOSE, conn_id)
            except: pass
            logger.debug(f"Tunnel {conn_id} closed")

    async def heartbeat_loop(self):
        while self.running:
            await asyncio.sleep(30)
            if self.server_writer and not self.server_writer.is_closing():
                try:
                    async with self.write_lock:
                        await write_message(self.server_writer, MessageType.HEARTBEAT, 0)
                except: pass

    async def start(self):
        mode_desc = self.force_mode or 'auto (plain first, TLS fallback)'
        logger.info(f"Starting reverse SOCKS5 client (control link: {mode_desc})")
        logger.info(f"Server: {self.server_host}:{self.server_port}")
        heartbeat_task = asyncio.create_task(self.heartbeat_loop())
        server_task = asyncio.create_task(self.connect_to_server())
        try:
            await asyncio.gather(heartbeat_task, server_task)
        except asyncio.CancelledError:
            self.running = False
            heartbeat_task.cancel()
            server_task.cancel()

DEFAULT_SERVER = 'localhost:9000'

async def main():
    parser = argparse.ArgumentParser(description='Reverse SOCKS5 Proxy Client (auto-detecting control link)')
    parser.add_argument('server', nargs='?', default=DEFAULT_SERVER, help='Server address (host:port)')
    parser.add_argument('--plain', dest='force_mode', action='store_const', const='plain',
                        help='Force plain TCP control link (no auto-detection)')
    parser.add_argument('--tls', dest='force_mode', action='store_const', const='tls',
                        help='Force TLS control link (no auto-detection)')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if ':' in args.server:
        host, port = args.server.rsplit(':', 1)
        port = int(port)
    else:
        host = args.server
        port = 9000

    client = ReverseClient(host, port, force_mode=args.force_mode, insecure=args.insecure)
    await client.start()

if __name__ == '__main__':
    asyncio.run(main())
