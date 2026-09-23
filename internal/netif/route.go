// Package netif looks up facts about the host's network interfaces that
// the tc/HTB setup needs: which interface carries the default route, and
// how fast its link is.
package netif

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// rtfUp is RTF_UP from <linux/route.h>: the route is usable.
const rtfUp = 0x1

// DefaultRouteInterface returns the name of the interface used by the
// system's default route, read from /proc/net/route.
func DefaultRouteInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return defaultRouteInterface(f)
}

// defaultRouteInterface parses /proc/net/route content. A default route
// has both destination and mask 0.0.0.0: matching the destination alone
// would also accept a split-default route such as 0.0.0.0/1 (OpenVPN's
// def1), which isn't the default route. Among several usable default
// routes, the one with the lowest metric wins, as it does for the kernel.
func defaultRouteInterface(r io.Reader) (string, error) {
	// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
	const (
		colIface = iota
		colDest
		_
		colFlags
		_
		_
		colMetric
		colMask
	)

	var best string
	var bestMetric uint64
	scanner := bufio.NewScanner(r)
	scanner.Scan() // header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) <= colMask || fields[colDest] != "00000000" || fields[colMask] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[colFlags], 16, 32)
		if err != nil || flags&rtfUp == 0 {
			continue
		}
		metric, err := strconv.ParseUint(fields[colMetric], 10, 64)
		if err != nil {
			continue
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = fields[colIface], metric
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if best == "" {
		return "", errors.New("no default route found in /proc/net/route")
	}
	return best, nil
}
