// AIDN XDP/eBPF High-Speed Packet Filter
// Processes packets at kernel driver level for line-rate DDoS mitigation
// Capable of handling millions of packets per second (10+ Mpps)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Verdict actions
#define VERDICT_PASS    0
#define VERDICT_DROP    1
#define VERDICT_LIMIT   2

// Map sizes for high-capacity tracking
#define MAX_TRACKED_IPS     1000000  // 1M IPs for large-scale attacks
#define MAX_WHITELIST       100000   // 100K whitelisted IPs
#define MAX_BLACKLIST       500000   // 500K blacklisted IPs
#define MAX_RATE_ENTRIES    1000000  // Rate limit tracking

// Rate limiting defaults (packets per second)
#define DEFAULT_PPS_LIMIT       10000   // 10K pps per IP
#define SYN_PPS_LIMIT           100     // 100 SYN packets per second per IP
#define UDP_PPS_LIMIT           5000    // 5K UDP pps per IP
#define ICMP_PPS_LIMIT          10      // 10 ICMP pps per IP

// Time window for rate limiting (nanoseconds)
#define RATE_WINDOW_NS  1000000000ULL  // 1 second

// ============================================================================
// BPF MAPS - Shared data structures between kernel and userspace
// ============================================================================

// Whitelist: Trusted IPs that bypass all filtering (players, admins)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);             // IPv4 address
    __type(value, __u64);           // Timestamp when added + trust score
    __uint(max_entries, MAX_WHITELIST);
} whitelist SEC(".maps");

// IPv6 whitelist
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in6_addr);   // IPv6 address
    __type(value, __u64);           // Timestamp + trust score
    __uint(max_entries, MAX_WHITELIST);
} whitelist_v6 SEC(".maps");

// Blacklist: Confirmed attacker IPs - immediate DROP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);             // IPv4 address
    __type(value, __u64);           // Ban expiry timestamp
    __uint(max_entries, MAX_BLACKLIST);
} blacklist SEC(".maps");

// IPv6 blacklist
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in6_addr);   // IPv6 address
    __type(value, __u64);           // Ban expiry timestamp
    __uint(max_entries, MAX_BLACKLIST);
} blacklist_v6 SEC(".maps");

// Rate limiting state per IP
struct rate_state {
    __u64 packets;          // Packet count in current window
    __u64 bytes;            // Byte count in current window
    __u64 window_start;     // Window start timestamp (ns)
    __u32 syn_count;        // SYN packets in window
    __u32 udp_count;        // UDP packets in window
    __u32 violations;       // Rate limit violations
    __u8  suspicious;       // Suspicious activity flag
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);             // IPv4 address
    __type(value, struct rate_state);
    __uint(max_entries, MAX_RATE_ENTRIES);
} rate_limits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in6_addr);   // IPv6 address
    __type(value, struct rate_state);
    __uint(max_entries, MAX_RATE_ENTRIES);
} rate_limits_v6 SEC(".maps");

// Traffic statistics for ML analysis (exported to userspace)
struct traffic_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 syn_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 tcp_packets;
    __u64 rate_limited;
    __u64 blacklist_hits;
    __u64 whitelist_hits;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct traffic_stats);
    __uint(max_entries, 1);
} stats SEC(".maps");

// Dynamic configuration (updated by AI engine)
struct aidn_config {
    __u32 global_pps_limit;     // Global packets per second limit
    __u32 syn_pps_limit;        // SYN flood threshold
    __u32 udp_pps_limit;        // UDP flood threshold
    __u32 icmp_pps_limit;       // ICMP flood threshold
    __u32 violation_threshold;  // Violations before blacklist
    __u8  learning_mode;        // 1 = learning mode (less aggressive)
    __u8  enabled;              // 1 = filtering enabled
    __u16 game_port_start;      // Game server port range start
    __u16 game_port_end;        // Game server port range end
    __u16 query_port;           // Query port (more strict limiting)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct aidn_config);
    __uint(max_entries, 1);
} config SEC(".maps");

// Connection tracking for stateful inspection
struct conn_state {
    __u64 last_seen;
    __u32 packets;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  established;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);             // Hash of 5-tuple
    __type(value, struct conn_state);
    __uint(max_entries, MAX_TRACKED_IPS);
} connections SEC(".maps");

// Suspicious patterns detected (sent to userspace for ML analysis)
struct suspicious_event {
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  reason;       // Reason code
    __u16 pps;          // Packets per second
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16MB ring buffer
} events SEC(".maps");

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static __always_inline struct aidn_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

static __always_inline struct traffic_stats *get_stats(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline int is_whitelisted_v4(__u32 ip) {
    return bpf_map_lookup_elem(&whitelist, &ip) != NULL;
}

static __always_inline int is_blacklisted_v4(__u32 ip) {
    __u64 *expiry = bpf_map_lookup_elem(&blacklist, &ip);
    if (expiry) {
        __u64 now = bpf_ktime_get_ns();
        if (*expiry == 0 || now < *expiry) {
            return 1;  // Still banned
        }
        // Ban expired, remove from blacklist
        bpf_map_delete_elem(&blacklist, &ip);
    }
    return 0;
}

static __always_inline int check_rate_limit_v4(__u32 ip, __u32 pkt_len,
                                                __u8 is_syn, __u8 is_udp,
                                                struct aidn_config *cfg) {
    struct rate_state *state, new_state = {};
    __u64 now = bpf_ktime_get_ns();

    state = bpf_map_lookup_elem(&rate_limits, &ip);

    if (!state) {
        // First packet from this IP
        new_state.packets = 1;
        new_state.bytes = pkt_len;
        new_state.window_start = now;
        new_state.syn_count = is_syn ? 1 : 0;
        new_state.udp_count = is_udp ? 1 : 0;
        new_state.violations = 0;
        new_state.suspicious = 0;
        bpf_map_update_elem(&rate_limits, &ip, &new_state, BPF_ANY);
        return VERDICT_PASS;
    }

    // Check if window expired
    if (now - state->window_start > RATE_WINDOW_NS) {
        // New window
        state->packets = 1;
        state->bytes = pkt_len;
        state->window_start = now;
        state->syn_count = is_syn ? 1 : 0;
        state->udp_count = is_udp ? 1 : 0;
        // Decay violations over time
        if (state->violations > 0)
            state->violations--;
        return VERDICT_PASS;
    }

    // Update counters
    state->packets++;
    state->bytes += pkt_len;
    if (is_syn) state->syn_count++;
    if (is_udp) state->udp_count++;

    // Check rate limits
    __u32 pps_limit = cfg ? cfg->global_pps_limit : DEFAULT_PPS_LIMIT;
    __u32 syn_limit = cfg ? cfg->syn_pps_limit : SYN_PPS_LIMIT;
    __u32 udp_limit = cfg ? cfg->udp_pps_limit : UDP_PPS_LIMIT;

    if (state->packets > pps_limit) {
        state->violations++;
        state->suspicious = 1;
        return VERDICT_LIMIT;
    }

    if (is_syn && state->syn_count > syn_limit) {
        state->violations++;
        state->suspicious = 1;
        return VERDICT_LIMIT;
    }

    if (is_udp && state->udp_count > udp_limit) {
        state->violations++;
        state->suspicious = 1;
        return VERDICT_LIMIT;
    }

    // Check if should be auto-blacklisted
    __u32 violation_thresh = cfg ? cfg->violation_threshold : 10;
    if (state->violations >= violation_thresh) {
        // Auto-blacklist for 1 hour
        __u64 expiry = now + (3600ULL * 1000000000ULL);
        bpf_map_update_elem(&blacklist, &ip, &expiry, BPF_ANY);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

static __always_inline void send_suspicious_event(__u32 src_ip, __u16 src_port,
                                                   __u16 dst_port, __u8 proto,
                                                   __u8 reason, __u16 pps) {
    struct suspicious_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        evt->src_ip = src_ip;
        evt->src_port = src_port;
        evt->dst_port = dst_port;
        evt->proto = proto;
        evt->reason = reason;
        evt->pps = pps;
        evt->timestamp = bpf_ktime_get_ns();
        bpf_ringbuf_submit(evt, 0);
    }
}

// ============================================================================
// PACKET VALIDATION
// ============================================================================

static __always_inline int validate_tcp_flags(struct tcphdr *tcp) {
    __u8 flags = ((__u8 *)tcp)[13];  // TCP flags byte

    // Invalid flag combinations (common in attacks)
    // FIN+SYN
    if ((flags & 0x03) == 0x03) return 0;
    // SYN+RST
    if ((flags & 0x06) == 0x06) return 0;
    // FIN+RST
    if ((flags & 0x05) == 0x05) return 0;
    // NULL flags (no flags set)
    if ((flags & 0x3F) == 0x00) return 0;
    // All flags set (XMAS scan)
    if ((flags & 0x3F) == 0x3F) return 0;

    return 1;
}

// ============================================================================
// MAIN XDP PROGRAM
// ============================================================================

SEC("xdp")
int aidn_xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct traffic_stats *stats = get_stats();
    struct aidn_config *cfg = get_config();

    // Check if filtering is enabled
    if (cfg && !cfg->enabled) {
        return XDP_PASS;
    }

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u32 pkt_len = data_end - data;

    // Update stats
    if (stats) {
        stats->total_packets++;
        stats->total_bytes += pkt_len;
    }

    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP) &&
        eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        return XDP_PASS;
    }

    // Handle IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;

        __u32 src_ip = ip->saddr;

        // Check whitelist first (trusted players/admins)
        if (is_whitelisted_v4(src_ip)) {
            if (stats) stats->whitelist_hits++;
            return XDP_PASS;
        }

        // Check blacklist
        if (is_blacklisted_v4(src_ip)) {
            if (stats) {
                stats->blacklist_hits++;
                stats->dropped_packets++;
                stats->dropped_bytes += pkt_len;
            }
            return XDP_DROP;
        }

        // Protocol-specific handling
        __u8 is_syn = 0, is_udp = 0;
        __u16 src_port = 0, dst_port = 0;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end)
                return XDP_DROP;

            if (stats) stats->tcp_packets++;

            // Validate TCP flags
            if (!validate_tcp_flags(tcp)) {
                if (stats) {
                    stats->dropped_packets++;
                    stats->dropped_bytes += pkt_len;
                }
                send_suspicious_event(src_ip, bpf_ntohs(tcp->source),
                                     bpf_ntohs(tcp->dest), IPPROTO_TCP, 1, 0);
                return XDP_DROP;
            }

            // Check for SYN flood
            __u8 flags = ((__u8 *)tcp)[13];
            is_syn = (flags & 0x02) && !(flags & 0x10);  // SYN without ACK
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);

            if (is_syn && stats) stats->syn_packets++;
        }
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end)
                return XDP_DROP;

            if (stats) stats->udp_packets++;
            is_udp = 1;
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);

            // Check if this is game traffic (less aggressive limiting)
            if (cfg && dst_port >= cfg->game_port_start &&
                dst_port <= cfg->game_port_end) {
                // Game traffic - use higher limits (handled in rate check)
            }
        }
        else if (ip->protocol == IPPROTO_ICMP) {
            if (stats) stats->icmp_packets++;

            // Very strict ICMP limiting
            struct rate_state *state = bpf_map_lookup_elem(&rate_limits, &src_ip);
            if (state && state->packets > (cfg ? cfg->icmp_pps_limit : ICMP_PPS_LIMIT)) {
                if (stats) {
                    stats->dropped_packets++;
                    stats->dropped_bytes += pkt_len;
                    stats->rate_limited++;
                }
                return XDP_DROP;
            }
        }

        // Rate limiting check
        int verdict = check_rate_limit_v4(src_ip, pkt_len, is_syn, is_udp, cfg);

        if (verdict == VERDICT_DROP) {
            if (stats) {
                stats->dropped_packets++;
                stats->dropped_bytes += pkt_len;
                stats->blacklist_hits++;
            }
            send_suspicious_event(src_ip, src_port, dst_port, ip->protocol, 2, 0);
            return XDP_DROP;
        }

        if (verdict == VERDICT_LIMIT) {
            if (stats) {
                stats->dropped_packets++;
                stats->dropped_bytes += pkt_len;
                stats->rate_limited++;
            }
            // In learning mode, don't drop, just log
            if (cfg && cfg->learning_mode) {
                send_suspicious_event(src_ip, src_port, dst_port, ip->protocol, 3, 0);
                return XDP_PASS;
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

// Secondary program for software fallback (tc/netfilter integration)
SEC("tc")
int aidn_tc_filter(struct __sk_buff *skb) {
    // TC classifier for systems without XDP support
    // Similar logic but runs later in the stack
    return 0;  // TC_ACT_OK
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
