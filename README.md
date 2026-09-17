# Simple Layer-2 Discovery Protocol (SLDP)

SLDP is a lightweight Layer-2 bootstrapping protocol designed to automate the
discovery phase between IPv4-only and IPv6-only devices sharing a common
broadcast domain. Operating directly over Ethernet frames, it requires zero IP
stack initialization, active sockets, DNS, or DHCP infrastructure. It is
explicitly not a replacement for ARP, NDP, mDNS, or LLDP, nor is it a runtime
protocol for time-sensitive production data planes. Instead, it serves purely
as a targeted commissioning tool.

SLDP uses a **stateless handshake** that produces a **stateful binding** — the
request-reply exchange carries no negotiated session, but both endpoints retain
the resulting IPv4 ↔ IPv6 ↔ MAC tuple for the orchestration layer to consume.

## The Problem & Solution

Modern network environments frequently host a hybrid mix of legacy IPv4-only
hardware, such as programmable logic controllers, and modern IPv6-only
equipment, such as smart sensors. Bridging this gap historically requires
manual MAC recording, proxy mappings, and static NAT64 configuration, creating
operational bottlenecks and human error risks.

SLDP solves this by executing an on-demand, two-way handshake at Layer 2,
allowing opposite address families to declare their capabilities before an IP
stack is configured. Once discovery is complete and mapping tables are built,
SLDP stops transmitting to keep production traffic deterministic and light.

## Architecture & Protocol Mechanics

The underlying architecture relies on a dedicated EtherType value of `0x88B5`
and a fixed **46-byte SLDP payload** that pads out to a standard **60-byte
minimum Ethernet frame** (14-byte Ethernet II header + 46-byte payload,
excluding FCS).

- **Exchange:** Consists of an atomic `DISCOVERY_REQ` broadcast followed by a
  unicast `DISCOVERY_RESP`. A response is accepted only when its *Target Type*
  and *Target IP* match the initiator's own address and family — eliminating
  the need for a session ID.
- **Addressing:** Each IP slot is 16 bytes, preceded by an explicit type tag
  (`0x04` = IPv4, `0x06` = IPv6). IPv4 addresses occupy the first 4 bytes of
  the slot; the remaining 12 are zero. This replaces IPv4-mapped IPv6 encoding
  with a deterministic, future-proof layout.
- **Wire format:** Version, Message Type, Origin MAC, Src Type, Src IP,
  Tgt Type, Tgt IP, and 4 reserved bytes — 46 bytes total.

### Wire format (60-byte frame)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 6  | Destination MAC |
| 6  | 6  | Source MAC |
| 12 | 2  | EtherType (`0x88B5`) |
| 14 | 6  | Origin MAC |
| 20 | 1  | Src Type (`0x04` / `0x06`) |
| 21 | 16 | Source IP |
| 37 | 1  | Tgt Type (`0x00` / `0x04` / `0x06`) |
| 38 | 16 | Target IP |
| 54 | 1  | Version (`0x01`) |
| 55 | 1  | Message Type (`0x01` probe, `0x02` response) |
| 56 | 4  | Reserved |

## Transport: IEEE 802 Networks

SLDP operates over any IEEE 802 link that carries Ethernet II frames with
arbitrary EtherType values. This makes it transport-agnostic across the common
Layer 2 media used in brownfield, industrial, and tactical environments.

### Supported transports

| Medium | Standard | SLDP support | Notes |
|---|---|:---:|---|
| Wired Ethernet | IEEE 802.3 | ✅ Native | Primary target for industrial, OT, and data-center use |
| Wi-Fi infrastructure | IEEE 802.11 (managed) | ✅ With constraints | Requires client isolation disabled; AP must pass unknown EtherTypes |
| Wi-Fi ad-hoc | IEEE 802.11 (IBSS) | ✅ Native | No AP filtering; preferred for disaster recovery and tactical use |
| Wi-Fi mesh | IEEE 802.11s | ✅ | Frames forwarded across mesh; EtherType must be permitted |
| Wi-Fi Direct | Wi-Fi P2P | ✅ | Direct station-to-station; useful for autonomous swarms |
| AP mode | IEEE 802.11 (hostapd) | ✅ | AP may run SLDP directly or proxy for its clients |

### Constraints on 802.11

Three conditions must hold for SLDP to function on Wi-Fi:

1. **Association first.** SLDP is pre-IP, not pre-association. Both endpoints
   must be associated to the same BSS (or in IBSS / mesh / Wi-Fi Direct) before
   any SLDP frame can be transmitted.
2. **Client isolation disabled.** Enterprise and guest SSIDs often block
   station-to-station traffic at the AP. SLDP probes will transmit but no
   response will arrive. This is the most common Wi-Fi failure mode.
3. **EtherType pass-through.** Some managed APs and drivers filter EtherTypes
   they do not recognize. `0x88B5` (local / experimental) is generally passed,
   but strict deployments may drop it.

### Performance notes

- **Broadcast rate.** Wi-Fi broadcast frames are sent at the lowest basic rate
  and are neither acknowledged nor retransmitted. SLDP's default probe timeout
  of 2000 ms is sized for this.
- **Power save.** Stations in power-save mode buffer frames at the AP and wake
  on DTIM beacons. Response latency can reach hundreds of milliseconds.
- **XDP fast path.** Native XDP is not available on most 802.11 drivers. On
  Wi-Fi, SLDP bindings are consumed by the kernel forwarding path or a local
  userspace daemon rather than an XDP-native translator. The XDP claim in the
  specification applies to wired Ethernet access ports.

### Recommended deployment modes

- **Industrial / OT / data center:** wired Ethernet — the primary target.
- **Disaster recovery / tactical field networks:** 802.11 IBSS or Wi-Fi Direct.
- **Autonomous swarms:** Wi-Fi Direct or 802.11s mesh.
- **Enterprise Wi-Fi:** supported only where client isolation is disabled and
  EtherType filtering is permissive.

## Comparison with Existing Protocols

Compared to traditional discovery mechanisms, SLDP fills a unique structural
niche:

- **ARP and NDP:** Handle single-family address resolution and require an
  active IP stack. SLDP achieves cross-family discovery with zero IP setup.
- **mDNS / DNS-SD:** Depend on transport layers and a functioning IP stack.
  SLDP operates directly over Ethernet.
- **LLDP / CDP / EDP / MNDP:** Broadcast continuously as background services
  and advertise existing capabilities passively. SLDP actively solicits a
  response and runs strictly on demand, then returns to a dormant state.
- **L3DL:** Targets routing-infrastructure bootstrap and requires a working IP
  stack. SLDP is pre-IP by design.

## Deployment Scenarios

Primary deployment scenarios include:

- Brownfield industrial automation
- Tactical disaster recovery networks
- Autonomous drone swarms
- Data center out-of-band management
- Substation and power-grid retrofits

In these environments, SLDP feeds newly discovered MAC-to-IP relationships
directly into higher-level translation systems such as NAT64 gateways, Proxy
ARP nodes, or orchestration tools like Ansible, Terraform, and Kubernetes.

## Usage & Compilation

Compile the C implementation on a Linux system:

```bash
gcc -O2 -Wall -Wextra -std=c11 sldp.c -o sldp
```

Note: Running the engine requires root or CAP_NET_RAW privileges to interact
directly with raw AF_PACKET sockets.

Start a listening node:

```bash
sudo ./sldp eth0 fe80::10 listen
```

Broadcast a probe from an initiator node:

```bash
sudo ./sldp eth0 192.168.1.10 probe
```

Wireshark dissector

A Lua dissector (dissector.lua) is included in this repository. Copy the file
to your Wireshark plugin folder to inspect SLDP frames on your network.

Security Architecture

For security, the CLL (Cryptographic Link Layer) Trust Oracle Protocol v2.2
will be used as a blueprint. This ensures the Layer-2 discovery process is
secured against address spoofing and manipulation during the commissioning
phase.

The current reference implementation assumes a trusted Layer-2 segment and
does not yet implement authentication, anti-replay, or rate limiting beyond
basic duplicate suppression. These are planned for a subsequent revision.

License

MIT License

