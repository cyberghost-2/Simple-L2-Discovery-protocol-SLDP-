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

### State machine

**Initiator (probe mode):**

| From | Event | Action | To |
|------|-------|--------|----|
| `IDLE` | Operator invokes probe | Build and broadcast probe; start timeout | `PROBE_SENT` |
| `PROBE_SENT` | Valid response received | Log tuple; hand to orchestration layer | `BOUND` |
| `PROBE_SENT` | Timeout, retries remain | Rebroadcast probe; reset timeout | `PROBE_SENT` |
| `PROBE_SENT` | Timeout, retries exhausted | Report failure | `SHUTDOWN` |
| Any | `SIGINT` / `SIGTERM` | Cease transmissions | `SHUTDOWN` |

**Responder (listen mode):**

| From | Event | Action | To |
|------|-------|--------|----|
| `IDLE` | Operator invokes listen | Open `AF_PACKET` socket | `LISTENING` |
| `LISTENING` | Probe received | Duplicate check; build response; unicast to sender | `LISTENING` |
| `LISTENING` | Duplicate probe within `T_recent` | Silently drop | `LISTENING` |
| `LISTENING` | `SIGINT` / `SIGTERM` | Cease transmissions | `SHUTDOWN` |

### Timers and operational parameters

| Parameter | Default | Notes |
|-----------|--------:|-------|
| Probe retry count | 3 | Total transmissions before giving up |
| Probe timeout | 2000 ms | Wait per attempt; sized for Wi-Fi broadcast |
| Duplicate suppression window | 5 s | Probes from the same MAC within this window are dropped |
| Duplicate suppression cache | 32 entries | LRU eviction on overflow |
| Listener poll interval | 1000 ms | Wake-up interval for graceful shutdown checks |

## Transport: IEEE 802 Networks

SLDP operates over any IEEE 802 link that carries Ethernet II frames with
arbitrary EtherType values. On wired Ethernet (IEEE 802.3) this is transparent
and is the primary deployment target for industrial, OT, and data-center use.

On Wi-Fi (IEEE 802.11), SLDP works in managed mode provided client isolation
is disabled and the AP passes unknown EtherTypes. It also works natively in
IBSS, 802.11s mesh, and Wi-Fi Direct, where no AP filters traffic — these modes
are the preferred fit for disaster recovery, tactical, and swarm scenarios.
SLDP does not operate before Layer 2 association; "pre-IP" refers to the IP
stack, not the link layer.

Two caveats apply on Wi-Fi. First, broadcast frames are sent at the lowest
basic rate and are neither acknowledged nor retransmitted, which is why SLDP's
default probe timeout is 2000 ms. Second, native XDP is unavailable on most
802.11 drivers, so SLDP bindings on Wi-Fi are consumed by the kernel forwarding
path or a local userspace daemon rather than an XDP-native translator.

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
directly into higher-level translation systems such as NAT64 gateways, proxy
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

