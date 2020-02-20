import socket
import dpkt
import struct
import logging
logger = logging.getLogger(__name__)

async def handle_dhcp(packet, client):
    """
    Implements basic responses to DHCP Discover/Request to do bare minimum to hand out
    IP addresses to DHCP clients.
    """
    dhcp = dpkt.dhcp.DHCP(packet.data.data.data)
    msgtype = int([x for x in dhcp.opts if x[0] == dpkt.dhcp.DHCP_OPT_MSGTYPE][0][1][0])
    my_ip = socket.inet_pton(socket.AF_INET, f"10.42.{128 + (client.address >> 8)}.{client.address & 0xff}")
    gw_ip = socket.inet_pton(socket.AF_INET, f"10.42.0.1")
    logger.debug(f"Routing DHCP packet of type {msgtype}")
    if msgtype in (dpkt.dhcp.DHCPDISCOVER, dpkt.dhcp.DHCPREQUEST):
        # Discover / Request
        dhcp_response = dpkt.dhcp.DHCP()
        dhcp_response.op = dpkt.dhcp.DHCP_OP_REPLY
        dhcp_response.xid = dhcp.xid
        dhcp_response.yiaddr, = struct.unpack('>I', my_ip)
        if msgtype == dpkt.dhcp.DHCPDISCOVER:
            dhcp_response.opts = [(dpkt.dhcp.DHCP_OPT_MSGTYPE, b'\x02')]
        else:
            dhcp_response.opts = [(dpkt.dhcp.DHCP_OPT_MSGTYPE, b'\x05', )]
        dhcp_response.opts += [
            (dpkt.dhcp.DHCP_OPT_NETMASK, socket.inet_pton(socket.AF_INET, "255.255.0.0")),
            (dpkt.dhcp.DHCP_OPT_ROUTER, gw_ip),
            (dpkt.dhcp.DHCP_OPT_NAMESERVER, gw_ip),
            (dpkt.dhcp.DHCP_OPT_LEASE_SEC, struct.pack('>I', 3600*24*365)),
            (dpkt.dhcp.DHCP_OPT_DOMAIN, b'nineties.lan')
        ]
        dhcp_response.chaddr = dhcp.chaddr
        print([getattr(dhcp_response, k) for k in dhcp_response.__hdr_fields__])
        response = dpkt.ethernet.Ethernet(
            src = b'\x01\x01\x01\x01\x01\x01',
            dst = packet.src,
            data = dpkt.ip.IP(
                src = gw_ip,
                dst = my_ip,
                p = 17,
                data = dpkt.udp.UDP(
                    sport = packet.data.data.dport,
                    dport = packet.data.data.sport,
                    ulen = len(dhcp_response) + 8,
                    data = dhcp_response
                )
            )
        )
        await client.send_packet(response)