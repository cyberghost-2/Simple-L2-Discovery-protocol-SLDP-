
# Simple Layer-2 Discovery Protocol (SLDP)

SLDP is a lightweight, stateless Layer-2 bootstrapping protocol designed to automate the discovery phase between IPv4-only and IPv6-only devices sharing a common broadcast domain. Operating directly over Ethernet frames, it requires zero IP stack initialization, active sockets, DNS, or DHCP infrastructure. It is explicitly not a replacement for ARP, NDP, mDNS, or LLDP, nor is it a runtime protocol for time-sensitive production data planes. Instead, it serves purely as a targeted commissioning tool.

## The Problem & Solution

Modern network environments frequently host a hybrid mix of legacy IPv4-only hardware, such as programmable logic controllers, and modern IPv6-only equipment, such as smart sensors. Bridging this gap historically requires manual MAC recording, proxy mappings, and static NAT64 configuration, creating operational bottlenecks and human error risks. 

SLDP solves this by executing an on-demand, two-way handshake at Layer 2, allowing opposite address families to declare their capabilities before an IP stack is configured. Once discovery is complete and mapping tables are built, SLDP stops transmitting to keep production traffic deterministic and light.

## Architecture & Protocol Mechanics

The underlying architecture relies on a dedicated EtherType value of `0x88B5` and a fixed 30-byte header that pads out to a standard 64-byte minimum Ethernet payload. 

- **Exchange:** Consists of an atomic `DISCOVERY_REQ` broadcast followed by a unicast `DISCOVERY_RESP` containing a 4-byte session ID and source address information.
- **Addressing:** Devices pack their addresses into a uniform 16-byte field using IPv4-mapped IPv6 encoding for legacy devices or native IPv6 formatting for modern assets.

## Comparison with Existing Protocols

Compared to traditional discovery mechanisms, SLDP fills a unique structural niche:

- **ARP and NDP:** Handle single-family address resolution and require an active IP stack. SLDP achieves cross-family discovery with zero IP setup.
- **mDNS:** Depends on transport layers to function. SLDP operates directly over Ethernet.
- **LLDP:** Broadcasts continuously as a background service. SLDP runs strictly on demand during initial setup or site maintenance before returning to a dormant state.

## Deployment Scenarios

Primary deployment scenarios include:
- Brownfield industrial automation
- Tactical disaster recovery networks
- Autonomous drone swarms
- Data center out-of-band management

In these environments, SLDP feeds newly discovered MAC-to-IP relationships directly into higher-level translation systems like NAT64 gateways, Proxy ARP nodes, or orchestration tools such as Ansible and Kubernetes.

## Usage & Compilation

To compile and execute the C implementation, compile the source file on a Linux system.

**Compile:**
```bash
gcc -O2 sldp.c -o sldp
```

Note: Running the engine requires root or CAP_NET_RAW privileges to interact directly with raw AF_PACKET sockets.

Start a listening node:

```bash
sudo ./sldp eth0 fe80::10 listen
```

Broadcast a probe from an initiator node:

```bash
sudo ./sldp eth0 192.168.1.10 probe
```

Wireshark Dissector: A Lua dissector (dissector.lua) is included in this repository. To use it, copy the file to your Wireshark plugin folder to inspect SLDP frames on your network.

Security Architecture

For security, the CLL (Cryptographic Link Layer) Trust Oracle Protocol v2.2 will be used as a blueprint. This ensures the Layer-2 discovery process is secured against address spoofing and manipulation during the commissioning phase.

License

MIT License
