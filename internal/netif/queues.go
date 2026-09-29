package netif

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TxQueueCount returns how many TX queues iface has in use, from
// /sys/class/net/<iface>/queues. That is the real queue count (what
// ethtool -L sets), which can be lower than the number the driver
// allocated.
func TxQueueCount(iface string) (int, error) {
	return txQueueCount(filepath.Join("/sys/class/net", iface, "queues"))
}

func txQueueCount(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tx-") {
			n++
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("no TX queues listed in %s", dir)
	}
	return n, nil
}
