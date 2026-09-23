module github.com/p0lyfusion/xray-speedlimit

go 1.26

require (
	github.com/cilium/ebpf v0.22.0
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.47.0
)

require github.com/vishvananda/netns v0.0.5 // indirect

tool github.com/cilium/ebpf/cmd/bpf2go
