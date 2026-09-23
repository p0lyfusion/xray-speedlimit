// Package qdisc provides a best-effort check that the egress interface
// uses the fq qdisc, which SO_MAX_PACING_RATE needs to actually pace
// packets. Failure to determine this is never fatal, only logged.
package qdisc

import (
	"bufio"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var fqPattern = regexp.MustCompile(`\bfq\b`)

// WarnIfMissing logs a warning if the fq qdisc cannot be confirmed on the
// interface used for the default route.
func WarnIfMissing(log *slog.Logger) {
	iface, err := DefaultRouteInterface()
	if err != nil {
		log.Warn("could not determine default route interface to verify the fq qdisc; SO_MAX_PACING_RATE requires fq on the egress interface", "error", err)
		return
	}

	tcPath, err := exec.LookPath("tc")
	if err != nil {
		log.Warn("tc binary not found, cannot verify fq qdisc is configured; SO_MAX_PACING_RATE will not pace traffic without it", "iface", iface)
		return
	}

	out, err := exec.Command(tcPath, "qdisc", "show", "dev", iface).CombinedOutput()
	if err != nil {
		log.Warn("failed to run tc qdisc show; could not verify fq qdisc", "iface", iface, "error", err)
		return
	}

	if !fqPattern.Match(out) {
		log.Warn("fq qdisc not detected on the default egress interface; SO_MAX_PACING_RATE will have no pacing effect without it", "iface", iface, "tc_output", strings.TrimSpace(string(out)))
	}
}

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
