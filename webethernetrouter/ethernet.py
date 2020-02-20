import asyncio
import dpkt
from . import dhcp, util
import logging
logger = logging.getLogger(__name__)

ETHERNET_BROADCAST = b'\xff\xff\xff\xff\xff\xff'
APPLETALK_BROADCAST = b'\x09\x00\x07\xff\xff\xff'

async def route_packet(client, packet):
    """
    Route an Ethernet packet from specified client. This is the module entry point.
    """
    if packet.dst == ETHERNET_BROADCAST or packet.dst == APPLETALK_BROADCAST:
        handled_internally = False
        if isinstance(packet.data, dpkt.ip.IP):
            handled_internally = await route_ipv4(client, packet, True)

        if not handled_internally:
            await broadcast(client, packet)
    else:
        if packet.dst[0] != '\x01':
            await route_to_peer(client, packet)
        elif isinstance(packet.data, dpkt.ip.IP):
            await route_ipv4(client, packet, False)
        else:
            logger.warning("Unknown destination")

async def route_to_peer(client, packet):
    """
    Route an Ethernet packet from specified client to the peer specified by the MAC destination address.
    """
    peer = client.lan_segment.get_by_mac(packet.dst)
    if not peer:
        logger.warning("MAC address %s not routable", util.hex_str(packet.dst))
        for a,p in client.lan_segment.clients.items():
            logger.warning("  Peer %s: %s", a, util.hex_str(p.mac_address))
    else:
        logger.warning("Routing packet to %s", util.hex_str(packet.dst))
        await peer.send_packet(packet)

async def broadcast(client, packet):
    """
    Route an Ethernet broadcast packet from specified client to all peers in its segment.
    """
    write_ops = []
    logger.debug("Broadcasting packet from %s", util.hex_str(packet.src))
    for peer in client.lan_segment.clients.values():
        if peer is not client:
            try:
                logger.debug("Broadcasting packet to %s", peer.address)
                write_ops.append(peer.send_packet(packet))
            except BrokenPipeError:
                pass
    if write_ops:
        await asyncio.wait(write_ops)
    
async def route_ipv4(client, packet, is_broadcast):
    """
    Handle a IPv4 packet using an intrinsic service.
    """
    if isinstance(packet.data.data, dpkt.udp.UDP):
        dest_port = packet.data.data.dport
        src_port = packet.data.data.sport
        logger.debug(f"Routing UDP from {src_port} to {dest_port}")
        if dest_port == 67:
            await dhcp.handle_dhcp(packet, client)
            return True
    return False