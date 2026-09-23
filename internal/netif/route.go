// Package netif looks up facts about the host's network interfaces that
// the tc/HTB setup needs: which interface carries the default route, and
// how fast its link is.
package netif

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// DefaultRouteInterface returns the name of the interface used by the
// system's default route, read from /proc/net/route.
func DefaultRouteInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	return "", errors.New("no default route found in /proc/net/route")
}
