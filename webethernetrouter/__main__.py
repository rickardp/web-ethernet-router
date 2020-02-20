import asyncio
from .tcp_socket_server import server as tcp_server

import logging

logging.basicConfig(level=logging.DEBUG)

asyncio.run(tcp_server())