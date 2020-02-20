import dpkt
import os
import struct
from . import pcap, ethernet, util
import logging
import sys
import traceback
logger = logging.getLogger(__name__)

class Client:
    def __init__(self, lan_segment, address):
        pcap_path = os.environ.get("PCAP_PATH")
        if pcap_path:
            self.pcap_file = pcap.open_pcap(os.path.join(pcap_path, f"{address}.pcap"))
        else:
            self.pcap_file = None

        self.lan_segment = lan_segment
        self.address = address
        self.mac_address = None
        if address in lan_segment.clients:
            raise KeyError("Duplicate client address")
        lan_segment.clients[address] = self
    
    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        if self.pcap_file:
            self.pcap_file.close()
        del self.lan_segment.clients[self.address]
        self.close()

    async def send_packet(self, packet):
        packet = bytes(packet)
        if self.pcap_file:
            pcap.write_pcap(self.pcap_file, packet)
        packet = struct.pack('>H', len(packet) & 0xffff) + packet
        await self.write(packet)

    async def read(self, length):
        raise NotImplementedError()

    async def write(self, data):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    async def run(self):
        await self.write(struct.pack('>H', self.address & 0xffff))
        while True:
            try:
                data = await self.read(2)
                if len(data) < 2:
                    break
                framelen, = struct.unpack('>H', data)
                assert framelen > 14 + 8 and framelen < 2000
                data = await self.read(framelen)
                packet = dpkt.ethernet.Ethernet(data)
                src_addr, = struct.unpack('>H', packet.src[-2:])
                assert src_addr == self.address # No MAC spoofing here!
                assert packet.src[0] != '\x01' # Router has 01
                if self.mac_address is None:
                    self.mac_address = packet.src

                if self.pcap_file:
                    pcap.write_pcap(self.pcap_file, data)
                logger.debug("Received Ethernet packet from %s to %s", util.hex_str(packet.src), util.hex_str(packet.dst))

                await ethernet.route_packet(self, packet)
            except ConnectionResetError:
                break
            except:
                logger.error("Exception in client handling: %s", sys.exc_info()[1])
                logger.debug(traceback.format_exc())

