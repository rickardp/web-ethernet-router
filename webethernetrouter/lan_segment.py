import struct

class LanSegment:
    def __init__(self):
        self.clients = dict()

    def get_by_mac(self, mac):
        addr, = struct.unpack('>H', mac[-2:])
        return self.clients.get(addr)