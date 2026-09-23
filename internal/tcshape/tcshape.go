// Package tcshape enforces per-mark bandwidth limits with a Linux HTB
// qdisc, classifying packets by the firewall mark that internal/conntrack
// restores onto them. It only shapes egress (server -> client) traffic;
// see the README for why ingress shaping was left out.
package tcshape

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	// defaultClassID is the catch-all bucket for traffic with no fw
	// filter match. Kept low so it can't collide with a real mark's
	// classIDFor encoding (see classIDFor).
	defaultClassID = "1:1"
	nftTable       = "xray_speedlimit"

	// minHTBBurstBytes floors the computed burst/cburst size so a very
	// low class rate (or a short burstMs) can't round down to a value tc
	// rejects as too small for the rate.
	minHTBBurstBytes = 2048
)

// classIDFor renders mark as an HTB classid. tc parses "major:minor" as
// hexadecimal and the minor part is a 16-bit kernel field (TC_H_MIN), so
// mark must fit in 16 bits and is formatted in hex to make the classid's
// numeric value equal to mark itself, matching the decimal fw filter
// handle (see SetRate) that is compared against the real (undecorated)
// skb mark.
func classIDFor(mark uint32) (string, error) {
	if mark == 0 || mark > 0xffff {
		return "", fmt.Errorf("mark %d is out of the 16-bit HTB classid range (1-65535)", mark)
	}
	return fmt.Sprintf("1:%x", mark), nil
}

// Shaper manages an HTB qdisc and one class+filter pair per mark on a
// single network interface.
type Shaper struct {
	iface           string
	defaultRateMbit uint64
	burstMs         uint64
}

// New creates a Shaper for the given interface. defaultRateMbit sets the
// rate of the default/unclassified-traffic HTB class; see the
// README for why it must reflect the interface's real link capacity.
// burstMs sets every class's burst/cburst allowance to that many
// milliseconds' worth of bytes at the class's own rate (0 leaves it at
// the kernel's own default sizing, which is normally just a couple KB —
// enough to smoothly pace traffic, not enough to avoid throttling short
// bursts like a page load or TCP slow start).
func New(iface string, defaultRateMbit, burstMs uint64) *Shaper {
	return &Shaper{iface: iface, defaultRateMbit: defaultRateMbit, burstMs: burstMs}
}

// htbBurstBytes returns the burst/cburst size, in bytes, for burstMs
// worth of tokens at rateBytesPerSec, or 0 if burstMs is 0 (caller should
// omit burst/cburst entirely and let tc pick its own default).
func htbBurstBytes(rateBytesPerSec, burstMs uint64) uint64 {
	if burstMs == 0 {
		return 0
	}
	return max(rateBytesPerSec*burstMs/1000, minHTBBurstBytes)
}

// htbRateArgs builds the "htb rate <bits>bit [burst <n> cburst <n>]" tail
// of a tc class add/replace command for rateBytesPerSec.
func htbRateArgs(rateBytesPerSec, burstMs uint64) []string {
	args := []string{"htb", "rate", fmt.Sprintf("%dbit", rateBytesPerSec*8)}
	if burst := htbBurstBytes(rateBytesPerSec, burstMs); burst > 0 {
		burstArg := fmt.Sprintf("%db", burst)
		args = append(args, "burst", burstArg, "cburst", burstArg)
	}
	return args
}

// classArgs builds a full "tc class <verb> ... classid <classID> htb rate
// ..." command line for this shaper's interface.
func (s *Shaper) classArgs(verb, classID string, rateBytesPerSec uint64) []string {
	return append([]string{"class", verb, "dev", s.iface, "parent", "1:", "classid", classID},
		htbRateArgs(rateBytesPerSec, s.burstMs)...)
}

// RootQdiscExists reports whether iface already has this package's root
// HTB qdisc, e.g. from an earlier run.
func RootQdiscExists(iface string) (bool, error) {
	out, err := runOutput("tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "htb 1:"), nil
}

// EnsureRoot creates the root HTB qdisc and its default class if they are
// not already present. rootExists should come from a fresh
// RootQdiscExists(s.iface) call — callers that already needed that answer
// for another reason (e.g. deciding whether to auto-detect a rate) pass
// it straight through instead of this re-querying it.
func (s *Shaper) EnsureRoot(rootExists bool) error {
	if rootExists {
		return nil
	}

	if err := run("tc", "qdisc", "add", "dev", s.iface, "root", "handle", "1:", "htb", "default", "1"); err != nil {
		return fmt.Errorf("creating root htb qdisc on %s: %w", s.iface, err)
	}
	defaultRateBps := s.defaultRateMbit * 1_000_000 / 8
	if err := run("tc", s.classArgs("add", defaultClassID, defaultRateBps)...); err != nil {
		return fmt.Errorf("creating default htb class on %s: %w", s.iface, err)
	}

	if err := ensureConnmarkRestore(); err != nil {
		return fmt.Errorf("setting up conntrack mark restore: %w", err)
	}
	return nil
}

// ensureConnmarkRestore installs an nftables rule that copies the
// conntrack mark onto the packet mark on the way out, which is what lets
// the "fw" tc filters classify by it. As a side effect, having any
// conntrack-aware rule loaded is also what makes the kernel track
// connections in this network namespace in the first place.
func ensureConnmarkRestore() error {
	out, err := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput()
	if err == nil && strings.Contains(string(out), "meta mark set ct mark") {
		return nil
	}

	if err := run("nft", "add", "table", "inet", nftTable); err != nil {
		return err
	}
	if err := run("nft", "add", "chain", "inet", nftTable, "postrouting",
		"{", "type", "filter", "hook", "postrouting", "priority", "mangle", ";", "}"); err != nil {
		return err
	}
	return run("nft", "add", "rule", "inet", nftTable, "postrouting", "meta", "mark", "set", "ct", "mark")
}

// SetRate creates or updates the HTB class and fw filter for mark.
func (s *Shaper) SetRate(mark uint32, rateBytesPerSec uint32) error {
	classID, err := classIDFor(mark)
	if err != nil {
		return err
	}
	if err := run("tc", s.classArgs("replace", classID, uint64(rateBytesPerSec))...); err != nil {
		return fmt.Errorf("setting htb rate for mark %d on %s: %w", mark, s.iface, err)
	}

	filterArgs := []string{"filter", "replace", "dev", s.iface, "parent", "1:", "protocol", "ip", "prio", "1", "handle", fmt.Sprintf("%d", mark), "fw", "flowid", classID}
	if err := run("tc", filterArgs...); err != nil {
		return fmt.Errorf("setting fw filter for mark %d on %s: %w", mark, s.iface, err)
	}
	return nil
}

// Remove deletes the fw filter and HTB class for mark.
func (s *Shaper) Remove(mark uint32) error {
	classID, err := classIDFor(mark)
	if err != nil {
		return err
	}

	_ = run("tc", "filter", "del", "dev", s.iface, "parent", "1:", "protocol", "ip", "prio", "1", "handle", fmt.Sprintf("%d", mark), "fw", "flowid", classID)

	out, err := exec.Command("tc", "class", "del", "dev", s.iface, "parent", "1:", "classid", classID).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file or directory") {
		return fmt.Errorf("removing htb class for mark %d on %s: %w: %s", mark, s.iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runOutput runs an external command, returning its combined output on
// success and a wrapped error (with output attached) on failure.
func runOutput(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func run(name string, args ...string) error {
	_, err := runOutput(name, args...)
	return err
}
