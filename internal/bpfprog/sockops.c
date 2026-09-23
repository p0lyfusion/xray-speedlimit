#include "bpfdefs.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u32);
} rate_limits SEC(".maps");

static __attribute__((always_inline)) void apply_pacing_rate(struct bpf_sock_ops *skops)
{
	__u32 mark = 0;

	if (bpf_getsockopt(skops, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)))
		return;
	if (mark == 0)
		return;

	__u32 *rate = bpf_map_lookup_elem(&rate_limits, &mark);
	if (!rate)
		return;

	bpf_setsockopt(skops, SOL_SOCKET, SO_MAX_PACING_RATE, rate, sizeof(*rate));
}

SEC("sockops")
int limit_by_mark(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		apply_pacing_rate(skops);
		break;
	default:
		break;
	}

	return 1;
}
