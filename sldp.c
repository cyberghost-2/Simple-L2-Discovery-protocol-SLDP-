#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define SLDP_ETHERTYPE 0x88B5
#define SLDP_VERSION   0x01
#define MIN_FRAME_SIZE 64

#define TYPE_DISCOVERY_REQ  0x01
#define TYPE_DISCOVERY_RESP 0x02

/* 30-Byte Fixed Binary SLDP Header (__attribute__((packed)) prevents padding) */
struct __attribute__((packed)) sldp_header {
    uint8_t  version;       /* 1 Byte  */
    uint8_t  msg_type;      /* 1 Byte  */
    uint16_t flags;         /* 2 Bytes */
    uint32_t session_id;    /* 4 Bytes */
    uint8_t  src_mac[6];    /* 6 Bytes */
    uint8_t  src_ip[16];    /* 16 Bytes (IPv4-mapped IPv6 or native IPv6) */
};

/* Convert IP String (IPv4 or IPv6) into 16-Byte Array */
static int ip_to_16bytes(const char *ip_str, uint8_t *out_bytes) {
    memset(out_bytes, 0, 16);
    struct in_addr v4;
    struct in6_addr v6;

    if (inet_pton(AF_INET, ip_str, &v4) == 1) {
        /* IPv4-mapped IPv6 layout: 10 zero bytes + 2 0xFF bytes + 4 IPv4 bytes */
        out_bytes[10] = 0xFF;
        out_bytes[11] = 0xFF;
        memcpy(&out_bytes[12], &v4, 4);
        return 0;
    } else if (inet_pton(AF_INET6, ip_str, &v6) == 1) {
        memcpy(out_bytes, &v6, 16);
        return 0;
    }
    return -1;
}

/* Format 16-Byte Array back to IP String */
static void bytes_to_ip(const uint8_t *in_bytes, char *out_str, size_t str_len) {
    static const uint8_t v4_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
    if (memcmp(in_bytes, v4_prefix, 12) == 0) {
        inet_ntop(AF_INET, &in_bytes[12], out_str, str_len);
    } else {
        inet_ntop(AF_INET6, in_bytes, out_str, str_len);
    }
}

/* Read local hardware MAC address */
static int get_mac_address(int sock, const char *ifname, uint8_t *mac) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("[-] Failed to retrieve MAC address");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

/* Fetch network interface index */
static int get_if_index(int sock, const char *ifname) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[-] Failed to retrieve interface index");
        return -1;
    }
    return ifr.ifr_ifindex;
}

/* Broadcast SLDP Discovery Packet */
static void send_discovery_request(int sock, int ifindex, const uint8_t *src_mac, const uint8_t *src_ip) {
    uint8_t frame[MIN_FRAME_SIZE];
    memset(frame, 0, MIN_FRAME_SIZE);

    /* 14-Byte Ethernet Header */
    memset(&frame[0], 0xFF, 6);                 /* Dst MAC: Broadcast (ff:ff:ff:ff:ff:ff) */
    memcpy(&frame[6], src_mac, 6);             /* Src MAC */
    uint16_t ethertype = htons(SLDP_ETHERTYPE);
    memcpy(&frame[12], &ethertype, 2);

    /* 30-Byte SLDP Header */
    struct sldp_header *sldp = (struct sldp_header *)&frame[14];
    sldp->version = SLDP_VERSION;
    sldp->msg_type = TYPE_DISCOVERY_REQ;
    sldp->flags = 0;
    sldp->session_id = 0;
    memcpy(sldp->src_mac, src_mac, 6);
    memcpy(sldp->src_ip, src_ip, 16);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xFF, 6);

    if (sendto(sock, frame, MIN_FRAME_SIZE, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[-] Probe send error");
    } else {
        printf("[+] Transmitted SLDP DISCOVERY_REQ Broadcast\n");
    }
}

/* Transmit Unicast Response Frame */
static void send_discovery_response(int sock, int ifindex, const uint8_t *dst_mac, const uint8_t *src_mac, const uint8_t *src_ip, uint32_t session_id) {
    uint8_t frame[MIN_FRAME_SIZE];
    memset(frame, 0, MIN_FRAME_SIZE);

    /* 14-Byte Ethernet Header */
    memcpy(&frame[0], dst_mac, 6);
    memcpy(&frame[6], src_mac, 6);
    uint16_t ethertype = htons(SLDP_ETHERTYPE);
    memcpy(&frame[12], &ethertype, 2);

    /* 30-Byte SLDP Header */
    struct sldp_header *sldp = (struct sldp_header *)&frame[14];
    sldp->version = SLDP_VERSION;
    sldp->msg_type = TYPE_DISCOVERY_RESP;
    sldp->flags = 0;
    sldp->session_id = htonl(session_id);
    memcpy(sldp->src_mac, src_mac, 6);
    memcpy(sldp->src_ip, src_ip, 16);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dst_mac, 6);

    sendto(sock, frame, MIN_FRAME_SIZE, 0, (struct sockaddr *)&sll, sizeof(sll));
    printf("    └─ [->] Transmitted Unicast DISCOVERY_RESP (Session ID: 0x%08X)\n", session_id);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: sudo %s <interface> <node_ip> <mode: probe|listen>\n", argv[0]);
        printf("Example IPv4: sudo %s wlan0 192.168.1.10 probe\n", argv[0]);
        printf("Example IPv6: sudo %s wlan0 fe80::10 listen\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *ip_str = argv[2];
    const char *mode = argv[3];

    uint8_t local_mac[6];
    uint8_t local_ip[16];

    if (ip_to_16bytes(ip_str, local_ip) != 0) {
        fprintf(stderr, "[-] Invalid IP address format: %s\n", ip_str);
        return 1;
    }

    /* Open AF_PACKET raw socket bound to EtherType 0x88B5 */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(SLDP_ETHERTYPE));
    if (sock < 0) {
        perror("[-] Socket creation failed (run as root)");
        return 1;
    }

    if (get_mac_address(sock, ifname, local_mac) < 0) return 1;
    int ifindex = get_if_index(sock, ifname);
    if (ifindex < 0) return 1;

    /* Bind raw socket to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(SLDP_ETHERTYPE);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[-] Socket bind failed");
        return 1;
    }

    printf("[*] SLDP C Engine Active on Interface: %s\n", ifname);
    printf("    ├── Local MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
    printf("    └── Local IP  : %s\n", ip_str);

    srand((unsigned int)time(NULL));

    if (strcmp(mode, "probe") == 0) {
        send_discovery_request(sock, ifindex, local_mac, local_ip);
    }

    printf("\n[*] Listening for cross-device SLDP frames...\n");
    uint8_t buffer[2048];
    char peer_ip_str[INET6_ADDRSTRLEN];

    while (1) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 44) continue; /* Minimum 14 (Eth) + 30 (SLDP) */

        uint8_t *src_mac = &buffer[6];
        if (memcmp(src_mac, local_mac, 6) == 0) continue; /* Ignore self-frames */

        struct sldp_header *sldp = (struct sldp_header *)&buffer[14];
        bytes_to_ip(sldp->src_ip, peer_ip_str, sizeof(peer_ip_str));
        uint32_t sess_id = ntohl(sldp->session_id);

        printf("\n[+] Ingress Frame Received:\n");
        printf("    ├── Peer MAC    : %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        printf("    ├── Peer IP     : %s\n", peer_ip_str);
        printf("    ├── Frame Type  : %s\n", (sldp->msg_type == TYPE_DISCOVERY_REQ) ? "DISCOVERY_REQ" : "DISCOVERY_RESP");

        if (sldp->msg_type == TYPE_DISCOVERY_REQ) {
            uint32_t assigned_session = rand();
            send_discovery_response(sock, ifindex, src_mac, local_mac, local_ip, assigned_session);
        } else if (sldp->msg_type == TYPE_DISCOVERY_RESP) {
            printf("    └── [✓] Cross-Stack Binding Established! Session ID: 0x%08X\n", sess_id);
        }
    }

    close(sock);
    return 0;
}
