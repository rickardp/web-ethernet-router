import asyncio
import struct
import time
import dpkt
import socket

last_addr = 0

writers = dict()

def hex_str(b):
    return ":".join('%x' % c for c in b)

async def handle_client(reader, writer):
    global last_addr
    last_addr += 1
    addr = last_addr

    with open(f"{addr}.pcap", "wb") as fh:
        fh.write(struct.pack('>I', 0xa1b2c3d4)) # magic
        fh.write(struct.pack('>HH', 2, 4)) # version
        fh.write(struct.pack('>I', 0)) # thiszone
        fh.write(struct.pack('>I', 0)) # sigfigs
        fh.write(struct.pack('>I', 0xffff)) # snaplen
        fh.write(struct.pack('>I', 1)) # network

        client = (writer, addr, fh)
        client_addr = None

        writer.write(struct.pack('>H', addr & 0xffff))
        await writer.drain()
        while True:
            try:
                data = await reader.read(2)
                if len(data) < 2:
                    break
                framelen, = struct.unpack('>H', data)
                assert framelen > 14 + 8 and framelen < 2000
                data = await reader.read(framelen)
                packet = dpkt.ethernet.Ethernet(data)
                dst_mac = packet.dst
                src_mac = packet.src
                src_addr, = struct.unpack('>H', src_mac[-2:])
                assert src_addr == addr # No MAC spoofing here!
                assert src_mac[0] != '\x01' # Router has 01
                if client_addr is None:
                    client_addr = src_mac
                    writers[client_addr] = client

                write_pcap(fh, data)
                
                print(f"Destination MAC is {hex_str(dst_mac)}")
                if dst_mac == b'\x09\x00\x07\xff\xff\xff' or dst_mac == b'\xff\xff\xff\xff\xff\xff':
                    if isinstance(packet.data, dpkt.ip.IP):
                        await route_ipv4(packet, True, client)
                    await broadcast(writer, data)
                else:
                    if dst_mac[0] != '\x01':
                        await route_lan_segment(dst_mac, data)
                    if isinstance(packet.data, dpkt.ip.IP):
                        await route_ipv4(packet, False, client)
                    else:
                        print("Unknown dst mac")

                #print(f"Send: {message!r}")
                #writer.write(data)
                #await writer.drain()
            except ConnectionResetError:
                break
    if client_addr in writers:
        del writers[client_addr]
    try:
        writer.close()
    except IOError:
        pass

def write_pcap(fh, data):
    try:
        ts = time.time()
        fh.write(struct.pack('>I', int(ts))) # timestamp seconds
        fh.write(struct.pack('>I', int(ts * 1e6) % 1000000)) # timestamp microseconds
        fh.write(struct.pack('>I', len(data))) # incl_len
        fh.write(struct.pack('>I', len(data))) # orig_len
        fh.write(data)
        fh.flush()
    except ValueError: #fh was closed
        pass

async def route_lan_segment(dst_mac, data):
    target = writers.get(dst_mac)
    if not target:
        print(f"MAC address {dst_mac} not routable")
    else:
        (w, addr, fh) = target
        print(f"Routing packet to {dst_mac}")
        write_pcap(fh, data)
        w.write(struct.pack('>H', len(data) & 0xffff))
        w.write(data)
        await w.drain()

async def broadcast(writer, data):
    for w,addr,fh in writers.values():
        if w is not writer:
            try:
                print(f"Broadcasting packet to {addr}")
                write_pcap(fh, data)
                w.write(struct.pack('>H', len(data) & 0xffff))
                w.write(data)
            except BrokenPipeError:
                pass
    for w,_,_ in writers.values():
        if w is not writer:
            try:
                await w.drain()
            except BrokenPipeError:
                pass
    
async def route_ipv4(packet, is_broadcast, client):
    if isinstance(packet.data.data, dpkt.udp.UDP):
        dest_port = packet.data.data.dport
        src_port = packet.data.data.sport
        print(f"Routing UDP from {src_port} to {dest_port}")
        if dest_port == 67:
            await handle_dhcp(packet, client)

async def handle_dhcp(packet, client):
    (w, addr, fh) = client
    dhcp = dpkt.dhcp.DHCP(packet.data.data.data)
    msgtype = int([x for x in dhcp.opts if x[0] == dpkt.dhcp.DHCP_OPT_MSGTYPE][0][1][0])
    my_ip = socket.inet_pton(socket.AF_INET, f"10.42.{128 + (addr >> 8)}.{addr & 0xff}")
    gw_ip = socket.inet_pton(socket.AF_INET, f"10.42.0.1")
    print(f"Routing DHCP {msgtype}")
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
        response = bytes(response)
        write_pcap(fh, response)
        w.write(struct.pack('>H', len(response) & 0xffff))
        w.write(response)

async def main():
    server = await asyncio.start_server(
        handle_client, '0.0.0.0', 12345)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())

