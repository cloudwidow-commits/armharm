#!/usr/bin/env python3
"""
Reverse SOCKS5 Proxy Server (Standalone) - Plain TCP Control Link

This server waits for reverse connections from clients. When a client connects,
it can then proxy traffic through that client's connection to reach destinations.

The control link is plain TCP. Run this behind a TLS terminator (e.g. a
Tailscale sidecar / stunnel / Caddy) when encryption is required.
"""
import asyncio
import argparse
import logging
import socket
import struct
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

def pack_address(atype: int, addr: str, port: int) -> bytes:
    if atype == AddressType.IPV4:
        return struct.pack('!B', atype) + socket.inet_aton(addr) + struct.pack('!H', port)
    elif atype == AddressType.DOMAIN:
        encoded = addr.encode('utf-8')
        return struct.pack('!BB', atype, len(encoded)) + encoded + struct.pack('!H', port)
    elif atype == AddressType.IPV6:
        return struct.pack('!B', atype) + socket.inet_pton(socket.AF_INET6, addr) + struct.pack('!H', port)
    raise ValueError(f"Unknown address type: {atype}")

# ============== Server Implementation ==============

class ReverseClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.conn_id_counter = 0
        self.active_connections: Dict[int, asyncio.Queue] = {}
        self.lock = asyncio.Lock()
        self.running = True

    async def get_next_conn_id(self) -> int:
        async with self.lock:
            self.conn_id_counter += 1
            return self.conn_id_counter

    async def register_connection(self, conn_id: int) -> asyncio.Queue:
        async with self.lock:
            queue = asyncio.Queue()
            self.active_connections[conn_id] = queue
            return queue

    async def unregister_connection(self, conn_id: int):
        async with self.lock:
            self.active_connections.pop(conn_id, None)


class ProxyServer:
    def __init__(self, control_port: int, socks_port: int):
        self.control_port = control_port
        self.socks_port = socks_port
        self.clients: Dict[str, ReverseClient] = {}
        self.default_client: Optional[ReverseClient] = None
        self.lock = asyncio.Lock()

    async def start(self):
        control_server = await asyncio.start_server(
            self.handle_control_connection, '0.0.0.0', self.control_port
        )
        socks_server = await asyncio.start_server(
            self.handle_socks_connection, '0.0.0.0', self.socks_port
        )
        logger.info(f"Control server listening on port {self.control_port}")
        logger.info(f"SOCKS5 server listening on port {self.socks_port}")
        async with control_server, socks_server:
            await asyncio.gather(control_server.serve_forever(), socks_server.serve_forever())

    async def handle_control_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        logger.info(f"New control connection from {addr}")
        client = ReverseClient(reader, writer)
        client_id = f"{addr[0]}:{addr[1]}"

        async with self.lock:
            self.clients[client_id] = client
            if self.default_client is None:
                self.default_client = client
                logger.info(f"Set default client to {client_id}")

        try:
            msg_type, conn_id, payload = await read_message(reader)
            if msg_type != MessageType.REGISTER:
                logger.warning(f"Expected REGISTER, got {msg_type}")
                return
            logger.info(f"Client {client_id} registered")

            while client.running:
                try:
                    msg_type, conn_id, payload = await read_message(reader)
                    if msg_type == MessageType.CONNECT_REPLY:
                        if conn_id in client.active_connections:
                            await client.active_connections[conn_id].put(('reply', payload))
                    elif msg_type == MessageType.DATA:
                        if conn_id in client.active_connections:
                            await client.active_connections[conn_id].put(('data', payload))
                    elif msg_type == MessageType.CLOSE:
                        if conn_id in client.active_connections:
                            await client.active_connections[conn_id].put(('close', b''))
                    elif msg_type == MessageType.HEARTBEAT:
                        await write_message(writer, MessageType.HEARTBEAT, 0)
                except asyncio.IncompleteReadError:
                    break
        except Exception as e:
            logger.error(f"Control connection error: {e}")
        finally:
            client.running = False
            async with self.lock:
                self.clients.pop(client_id, None)
                if self.default_client == client:
                    self.default_client = next(iter(self.clients.values()), None)
            writer.close()
            await writer.wait_closed()
            logger.info(f"Control connection {client_id} closed")

    async def handle_socks_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        logger.debug(f"New SOCKS5 connection from {addr}")
        try:
            version = (await reader.readexactly(1))[0]
            if version != 0x05:
                logger.warning(f"Invalid SOCKS version: {version}")
                writer.close()
                return

            nmethods = (await reader.readexactly(1))[0]
            await reader.readexactly(nmethods)
            writer.write(b'\x05\x00')
            await writer.drain()

            header = await reader.readexactly(4)
            ver, cmd, rsv, atype = header

            if cmd != 0x01:
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            if atype == AddressType.IPV4:
                dst_addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atype == AddressType.DOMAIN:
                length = (await reader.readexactly(1))[0]
                dst_addr = (await reader.readexactly(length)).decode('utf-8')
            elif atype == AddressType.IPV6:
                dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            dst_port = struct.unpack('!H', await reader.readexactly(2))[0]
            logger.info(f"SOCKS5 CONNECT request to {dst_addr}:{dst_port}")

            client = self.default_client
            if not client or not client.running:
                logger.warning("No reverse client available")
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            await self.proxy_through_client(client, reader, writer, atype, dst_addr, dst_port)
        except Exception as e:
            logger.error(f"SOCKS5 connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def proxy_through_client(self, client: ReverseClient, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter, atype: int, dst_addr: str, dst_port: int):
        conn_id = await client.get_next_conn_id()
        queue = await client.register_connection(conn_id)
        try:
            addr_payload = pack_address(atype, dst_addr, dst_port)
            await write_message(client.writer, MessageType.CONNECT, conn_id, addr_payload)

            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                msg_type, payload = msg
                if msg_type != 'reply':
                    writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                if payload[0] != 0x00:
                    writer.write(b'\x05' + bytes([payload[0]]) + b'\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
            except asyncio.TimeoutError:
                logger.warning(f"Connection {conn_id} timed out")
                writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            await self.relay_data(client, conn_id, queue, reader, writer)
        finally:
            await client.unregister_connection(conn_id)
            try:
                await write_message(client.writer, MessageType.CLOSE, conn_id)
            except:
                pass

    async def relay_data(self, client: ReverseClient, conn_id: int, queue: asyncio.Queue,
                         reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        async def forward_to_client():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await write_message(client.writer, MessageType.DATA, conn_id, data)
            except Exception as e:
                logger.debug(f"Forward to client error: {e}")

        async def forward_from_client():
            try:
                while True:
                    msg = await queue.get()
                    msg_type, payload = msg
                    if msg_type == 'close':
                        break
                    elif msg_type == 'data':
                        writer.write(payload)
                        await writer.drain()
            except Exception as e:
                logger.debug(f"Forward from client error: {e}")

        task1 = asyncio.create_task(forward_to_client())
        task2 = asyncio.create_task(forward_from_client())
        done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


async def main():
    parser = argparse.ArgumentParser(description='Reverse SOCKS5 Proxy Server')
    parser.add_argument('-c', '--control-port', type=int, default=9000,
                        help='Port for reverse client connections (default: 9000)')
    parser.add_argument('-s', '--socks-port', type=int, default=1080,
                        help='Port for SOCKS5 connections (default: 1080)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    server = ProxyServer(args.control_port, args.socks_port)
    await server.start()


if __name__ == '__main__':
    asyncio.run(main())
