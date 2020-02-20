import asyncio
import os, sys
from .tcp_socket_server import server as tcp_server
from .websocket_server import server as websocket_server

import logging

if os.environ.get("DEBUG") in ("1", "true"):
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)


socket_type = os.environ.get("TYPE", "websocket")
if socket_type == "websocket":
    server = websocket_server
elif socket_type == "tcp":
    server = tcp_server
else:
    print(f"Invalid socket type {socket_type}", file=sys.stderr)
    sys.exit(1)

asyncio.run(server())
