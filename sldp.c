/*
 * SLDP — Simple Layer-2 Discovery Protocol
 * Control-plane prototype (AF_PACKET).
 *
 * Build:  gcc -O2 -Wall -Wextra -std=c11 -o sldp sldp.c
 * Run:    sudo ./sldp <iface> <ip> probe     (initiator)
 *         sudo ./sldp <iface> <ip> listen    (responder)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

/* ---- Protocol constants ---- */
#define SLDP_ETHERTYPE    0x88B5
#define SLDP_VERSION      0x01

#define SLDP_MSG_PROBE    0x01
#define SLDP_MSG_RESPONSE 0x02

#define TYPE_UNSET        0x00
#define TYPE_IPV4         0x04
#define TYPE_IPV6         0x06

#define SLDP_PAYLOAD_LEN  46
#define SLDP_FRAME_LEN    60    /* 14 Ethernet + 46 SLDP */

/* ---- Operational tuning ---- */
#define PROBE_RETRIES        3
#define PROBE_TIMEOUT_MS     2000
#define RECENT_TTL_SEC       5
#define RECENT_MAX           32
#define LISTEN_POLL_MS       1000

/* ---- Wire format ---- */
struct __attribute__((packed)) sldp_header {
    uint8_t  origin_mac[6];
    uint8_t  src_type;
    uint8_t  src_ip[16];
    uint8_t  tgt_type;
    uint8_t  tgt_ip[16];
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  reserved[4];
};

_Static_assert(sizeof(struct sldp_header) == SLDP_PAYLOAD_LEN,
               "SLDP header must be exactly 46 bytes");

/* ---- Graceful shutdown ---- */
static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* ---- IP encode / decode ---- */
static int ip_encode(const char *ip_str, uint8_t *out, uint8_t *out_type) {
    memset(out, 0, 16);
    struct in_addr  v4;
    struct in6_addr v6;

    if (inet_pton(AF_INET, ip_str, &v4) == 1) {
        memcpy(out, &v4, 4);
        *out_type = TYPE_IPV4;
        return 0;
    }
    if (inet_pton(AF_INET6, ip_str, &v6) == 1) {
        memcpy(out, &v6, 16);
        *out_type = TYPE_IPV6;
        return 0;
    }
    return -1;
}

static int ip_decode(const uint8_t *in, uint8_t type,
                     char *out, size_t out_len) {
    if (type == TYPE_IPV4)
        return inet_ntop(AF_INET, in, out, out_len) ? 0 : -1;
    if (type == TYPE_IPV6)
        return inet_ntop(AF_INET6, in, out, out_len) ? 0 : -1;
    return -1;
}

/* ---- Interface helpers ---- */
static int get_mac(int sock, const char *ifname, uint8_t *mac) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int get_ifindex(int sock, const char *ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        return -1;
    }
    return ifr.ifr_ifindex;
}

/* ---- Frame builders ---- */
static void build_probe(uint8_t *frame,
                        const uint8_t *src_mac, uint8_t src_type,
                        const uint8_t *src_ip) {
    memset(frame, 0, SLDP_FRAME_LEN);

    memset(frame, 0xFF, 6);                         /* broadcast */
    memcpy(frame + 6, src_mac, 6);
    uint16_t et = htons(SLDP_ETHERTYPE);
    memcpy(frame + 12, &et, 2);

    struct sldp_header *h = (struct sldp_header *)(frame + 14);
    memcpy(h->origin_mac, src_mac, 6);
    h->src_type  = src_type;
    memcpy(h->src_ip, src_ip, 16);
    h->tgt_type  = TYPE_UNSET;
    memset(h->tgt_ip, 0, 16);
    h->version   = SLDP_VERSION;
    h->msg_type  = SLDP_MSG_PROBE;
}

static void build_response(uint8_t *frame,
                           const uint8_t *dst_mac,
                           const uint8_t *src_mac, uint8_t src_type,
                           const uint8_t *src_ip,
                           uint8_t tgt_type, const uint8_t *tgt_ip) {
    memset(frame, 0, SLDP_FRAME_LEN);

    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    uint16_t et = htons(SLDP_ETHERTYPE);
    memcpy(frame + 12, &et, 2);

    struct sldp_header *h = (struct sldp_header *)(frame + 14);
    memcpy(h->origin_mac, src_mac, 6);
    h->src_type = src_type;
    memcpy(h->src_ip, src_ip, 16);
    h->tgt_type = tgt_type;
    memcpy(h->tgt_ip, tgt_ip, 16);
    h->version  = SLDP_VERSION;
    h->msg_type = SLDP_MSG_RESPONSE;
}

/* ---- Transmission ---- */
static int send_frame(int sock, int ifindex,
                      const uint8_t *frame, const uint8_t *dst_mac) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen   = 6;
    memcpy(sll.sll_addr, dst_mac, 6);

    ssize_t sent = sendto(sock, frame, SLDP_FRAME_LEN, 0,
                          (struct sockaddr *)&sll, sizeof(sll));
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    return 0;
}

/* ---- Duplicate suppression ---- */
struct recent_entry {
    uint8_t mac[6];
    time_t  last_seen;
};

static struct recent_entry g_recent[RECENT_MAX];
static int g_recent_count = 0;

static int recent_lookup(const uint8_t *mac) {
    time_t now = time(NULL);
    for (int i = 0; i < g_recent_count; i++) {
        if (memcmp(g_recent[i].mac, mac, 6) == 0) {
            if (now - g_recent[i].last_seen < RECENT_TTL_SEC)
                return 1;
            g_recent[i].last_seen = now;
            return 0;
        }
    }
    return 0;
}

static void recent_update(const uint8_t *mac) {
    time_t now = time(NULL);
    for (int i = 0; i < g_recent_count; i++) {
        if (memcmp(g_recent[i].mac, mac, 6) == 0) {
            g_recent[i].last_seen = now;
            return;
        }
    }
    if (g_recent_count < RECENT_MAX) {
        memcpy(g_recent[g_recent_count].mac, mac, 6);
        g_recent[g_recent_count].last_seen = now;
        g_recent_count++;
        return;
    }
    /* Evict oldest */
    int oldest = 0;
    for (int i = 1; i < RECENT_MAX; i++)
        if (g_recent[i].last_seen < g_recent[oldest].last_seen)
            oldest = i;
    memcpy(g_recent[oldest].mac, mac, 6);
    g_recent[oldest].last_seen = now;
}

/* ---- Frame processing ---- */
static int process_frame(const uint8_t *frame, ssize_t len,
                         const uint8_t *own_mac,
                         uint8_t own_type, const uint8_t *own_ip,
                         int sock, int ifindex,
                         char *out_peer_ip, size_t out_peer_ip_len,
                         uint8_t *out_peer_type) {
    if (len < SLDP_FRAME_LEN) return 0;

    const uint8_t *src_mac = frame + 6;
    const struct sldp_header *h = (const struct sldp_header *)(frame + 14);

    if (memcmp(src_mac, own_mac, 6) == 0) return 0;   /* self */
    if (h->version != SLDP_VERSION) return 0;

    char peer_ip[INET6_ADDRSTRLEN] = {0};
    if (ip_decode(h->src_ip, h->src_type, peer_ip, sizeof(peer_ip)) != 0)
        snprintf(peer_ip, sizeof(peer_ip), "<invalid>");

    /* Incoming probe → we respond */
    if (h->msg_type == SLDP_MSG_PROBE) {
        if (h->src_type != TYPE_IPV4 && h->src_type != TYPE_IPV6)
            return 0;

        printf("[+] Probe from %02x:%02x:%02x:%02x:%02x:%02x (%s, type 0x%02x)\n",
               src_mac[0], src_mac[1], src_mac[2],
               src_mac[3], src_mac[4], src_mac[5],
               peer_ip, h->src_type);

        if (recent_lookup(src_mac)) {
            printf("    └─ Suppressed (recent duplicate)\n");
            return 0;
        }

        uint8_t resp[SLDP_FRAME_LEN];
        build_response(resp, src_mac,
                       own_mac, own_type, own_ip,
                       h->src_type, h->src_ip);

        if (send_frame(sock, ifindex, resp, src_mac) == 0) {
            printf("    └─ Sent unicast response\n");
            recent_update(src_mac);
        }
        return 0;
    }

    /* Incoming response → verify it targets us */
    if (h->msg_type == SLDP_MSG_RESPONSE) {
        if (h->tgt_type != own_type) return 0;
        if (memcmp(h->tgt_ip, own_ip, 16) != 0) return 0;

        printf("[✓] Binding complete!\n");
        printf("    ├─ Peer MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2],
               src_mac[3], src_mac[4], src_mac[5]);
        printf("    ├─ Peer IP  : %s (type 0x%02x)\n",
               peer_ip, h->src_type);
        printf("    └─ Local IP : (type 0x%02x)\n", own_type);

        if (out_peer_ip && out_peer_ip_len > 0) {
            snprintf(out_peer_ip, out_peer_ip_len, "%s", peer_ip);
        }
        if (out_peer_type) *out_peer_type = h->src_type;
        return 1;
    }

    return 0;
}

/* ---- Main ---- */
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: sudo %s <iface> <ip> <probe|listen>\n"
            "  sudo %s eth0 192.168.1.10 probe\n"
            "  sudo %s eth0 fe80::10     listen\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *ip_str = argv[2];
    const char *mode   = argv[3];

    int mode_probe = (strcmp(mode, "probe") == 0);
    if (!mode_probe && strcmp(mode, "listen") != 0) {
        fprintf(stderr, "[-] Mode must be 'probe' or 'listen'\n");
        return 1;
    }

    uint8_t own_ip[16];
    uint8_t own_type = TYPE_UNSET;
    if (ip_encode(ip_str, own_ip, &own_type) != 0) {
        fprintf(stderr, "[-] Invalid IP: %s\n", ip_str);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(SLDP_ETHERTYPE));
    if (sock < 0) {
        perror("[-] socket (run as root?)");
        return 1;
    }

    uint8_t own_mac[6];
    if (get_mac(sock, ifname, own_mac) < 0) return 1;

    int ifindex = get_ifindex(sock, ifname);
    if (ifindex < 0) return 1;

    struct sockaddr_ll bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family   = AF_PACKET;
    bind_addr.sll_ifindex  = ifindex;
    bind_addr.sll_protocol = htons(SLDP_ETHERTYPE);
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("[-] bind");
        return 1;
    }

    printf("[*] SLDP engine up on %s\n", ifname);
    printf("    ├─ Local MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           own_mac[0], own_mac[1], own_mac[2],
           own_mac[3], own_mac[4], own_mac[5]);
    printf("    └─ Local IP  : %s (type 0x%02x)\n", ip_str, own_type);

    /* ---------- Probe mode ---------- */
    if (mode_probe) {
        uint8_t probe[SLDP_FRAME_LEN];
        build_probe(probe, own_mac, own_type, own_ip);

        uint8_t bcast[6];
        memset(bcast, 0xFF, 6);

        char    peer_ip[INET6_ADDRSTRLEN] = {0};
        uint8_t peer_type = 0;
        int     bound = 0;

        for (int attempt = 0;
             attempt < PROBE_RETRIES && !bound && g_running;
             attempt++) {

            printf("\n[*] Sending probe (attempt %d/%d)\n",
                   attempt + 1, PROBE_RETRIES);
            if (send_frame(sock, ifindex, probe, bcast) < 0) break;

            struct timespec start, now;
            clock_gettime(CLOCK_MONOTONIC, &start);

            while (g_running) {
                clock_gettime(CLOCK_MONOTONIC, &now);
                long elapsed_ms =
                    (now.tv_sec  - start.tv_sec)  * 1000L +
                    (now.tv_nsec - start.tv_nsec) / 1000000L;
                int remaining = PROBE_TIMEOUT_MS - (int)elapsed_ms;
                if (remaining <= 0) break;

                struct pollfd pfd = { .fd = sock, .events = POLLIN };
                int pr = poll(&pfd, 1, remaining);
                if (pr < 0) {
                    if (errno == EINTR) continue;
                    perror("poll");
                    break;
                }
                if (pr == 0) break;   /* timeout */

                uint8_t buf[2048];
                ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
                if (n < 0) continue;

                if (process_frame(buf, n, own_mac, own_type, own_ip,
                                  sock, ifindex,
                                  peer_ip, sizeof(peer_ip), &peer_type)) {
                    bound = 1;
                    break;
                }
            }
        }

        if (!bound) {
            fprintf(stderr, "[-] No SLDP response after %d attempts\n",
                    PROBE_RETRIES);
            close(sock);
            return 2;
        }

        printf("\n[✓] Translation tuple:\n");
        printf("    %s (0x%02x)  <==>  %s (0x%02x)\n",
               ip_str, own_type, peer_ip, peer_type);

        close(sock);
        return 0;
    }

    /* ---------- Listen mode ---------- */
    printf("\n[*] Listening for SLDP frames (Ctrl-C to quit)\n");

    while (g_running) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int pr = poll(&pfd, 1, LISTEN_POLL_MS);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (pr == 0) continue;

        uint8_t buf[2048];
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) continue;

        process_frame(buf, n, own_mac, own_type, own_ip,
                      sock, ifindex,
                      NULL, 0, NULL);
    }

    printf("\n[*] Shutting down\n");
    close(sock);
    return 0;
}
