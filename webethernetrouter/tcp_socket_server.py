import asyncio
import struct
import time
import dpkt
import socket
import websockets
import os
from functools import partial
from .lan_segment import LanSegment
from .client import Client
import logging
logger = logging.getLogger(__name__)

last_addr = 0

writers = dict()

class TCPClient(Client):
    def __init__(self, lan_segment, address, reader, writer):
        super().__init__(lan_segment, address)
        
        self.reader = reader
        self.writer = writer

    async def read(self, length):
        return await self.reader.read(length)

    async def write(self, data):
        self.writer.write(data)
        await self.writer.drain()

    def close(self):
        try:
            self.reader.close()
        except:
            pass
        try:
            self.writer.close()
        except:
            pass


async def handle_client(lan_segment, reader, writer):
    global last_addr
    last_addr += 1
    addr = last_addr

    client = TCPClient(lan_segment, addr, reader, writer)

    with client:
        await client.run()

async def server():
    lan_segment = LanSegment()
    server = await asyncio.start_server(
        partial(handle_client, lan_segment),
        '0.0.0.0',
        int(os.environ.get("PORT", "12345"))
    )

    addr = server.sockets[0].getsockname()
    logger.info("Serving on %s", addr)
    async with server:
        await server.serve_forever()


