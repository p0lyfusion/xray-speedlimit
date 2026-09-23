package qdisc

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var ethtoolSpeedPattern = regexp.MustCompile(`(?m)^\s*Speed:\s*(\d+)Mb/s\s*$`)

// DetectLinkSpeedMbps queries iface's link speed, in Mbit/s, via ethtool.
// It returns an error if ethtool isn't installed, the link is down, or
// the interface doesn't report a numeric speed at all — the last case is
// common for virtual interfaces (veth, tun/tap, wireguard, etc.), where
// the caller must be given an explicit rate instead.
func DetectLinkSpeedMbps(iface string) (uint64, error) {
	out, err := exec.Command("ethtool", iface).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ethtool %s: %w: %s", iface, err, strings.TrimSpace(string(out)))
	}

	m := ethtoolSpeedPattern.FindSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("could not determine link speed of %s from ethtool output (virtual interfaces often don't report one): %s", iface, strings.TrimSpace(string(out)))
	}

	mbps, err := strconv.ParseUint(string(m[1]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing ethtool speed for %s: %w", iface, err)
	}
	return mbps, nil
}
