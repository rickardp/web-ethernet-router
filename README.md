## What it is

This is a network server (TCP + WebSockets) that routes traffic in isolated LAN segments entirely in userland.

It can:
* Route Ethernet packets (including broadcast packets)
* Hand out IP addresses with a built-in tiny DHCP server
* Dump traffic to pcap files for inspection in Wireshark

It can NOT (yet):
* Use websockets (but this is next)
* NAT traffic to the host network (not sure if that is such a good idea...)

The purpose is to create Dockerized network servers to connect together emulators of legacy PCs running in Emscripten (think old-school network games in the browser!). No dependency on TUN/TAP devices etc, so it's easy to run in unprivileged Docker containers.

This is very early days development.

