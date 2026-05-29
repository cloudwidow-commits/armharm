#!/usr/bin/env python3
"""
Reverse SOCKS5 Proxy Client (Standalone) - Control Tunnel TLS Mode
Optimized for Terminated TLS / VPN environments like Tailscale.
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
    def __init__(self, server_host: str, server_port: int, ssl_context: Optional[ssl.SSLContext] = None):
        self.server_host = server_host
        self.server_port = server_port
        self.ssl_context = ssl_context
        self.server_reader: Optional[asyncio.StreamReader] = None
        self.server_writer: Optional[asyncio.StreamWriter] = None
        self.tunnels: Dict[int, TunnelConnection] = {}
        self.lock = asyncio.Lock()
        self.running = True
        self.write_lock = asyncio.Lock()

    async def connect_to_server(self):
        while self.running:
            try:
                logger.info(f"Connecting to reverse server {self.server_host}:{self.server_port} via TLS")
                self.server_reader, self.server_writer = await asyncio.open_connection(
                    self.server_host, self.server_port, ssl=self.ssl_context
                )
                await write_message(self.server_writer, MessageType.REGISTER, 0, b'client')
                logger.info("Connected and registered with server (TLS Control Tunnel Active)")
                await self.handle_server_messages()
            except Exception as e:
                logger.error(f"Server connection error: {e}")
            if self.running:
                logger.info("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

    async def handle_server_messages(self):
        try:
            while self.running:
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
        logger.info(f"Starting reverse SOCKS5 client (TLS Control Link)")
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
    parser = argparse.ArgumentParser(description='Reverse SOCKS5 Proxy Client (TLS Control Tunnel)')
    parser.add_argument('server', nargs='?', default=DEFAULT_SERVER, help='Server address (host:port)')
    parser.add_argument('--insecure', action='store_true', help='Disable certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if args.insecure:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    if ':' in args.server:
        host, port = args.server.rsplit(':', 1)
        port = int(port)
    else:
        host = args.server
        port = 9000

    client = ReverseClient(host, port, ssl_context=ssl_context)
    await client.start()

if __name__ == '__main__':
    asyncio.run(main())
