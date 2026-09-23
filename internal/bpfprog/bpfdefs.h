#pragma once

/* Minimal freestanding defs for the BPF_PROG_TYPE_SOCK_OPS program below.
 * Field layout of struct bpf_sock_ops and the helper ids/op codes are
 * copied verbatim from include/uapi/linux/bpf.h (torvalds/linux, master)
 * so this file has no dependency on host kernel headers.
 */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1

#define SOL_SOCKET 1
#define SO_MARK 36
#define SO_MAX_PACING_RATE 47

/* enum bpf_sock_ops_op, only the entries this program cares about */
#define BPF_SOCK_OPS_TCP_CONNECT_CB 3
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4
#define BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB 5

struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
};

/* bpf_map_lookup_elem, bpf_getsockopt, bpf_setsockopt helper ids, copied
 * from tools/lib/bpf's generated bpf_helper_defs.h.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_setsockopt)(void *bpf_socket, int level, int optname, void *optval, int optlen) = (void *) 49;
static long (*bpf_getsockopt)(void *bpf_socket, int level, int optname, void *optval, int optlen) = (void *) 57;
