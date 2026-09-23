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
	// MinMark and MaxMark bound the marks a Shaper accepts. Mark 0 means
	// "no mark", mark 1 would encode to defaultClassID (see classIDFor),
	// and the HTB classid minor is a 16-bit field.
	MinMark = 2
	MaxMark = 0xffff

	// defaultClassID is the catch-all bucket for traffic with no fw
	// filter match. It is what classIDFor would return for mark 1, which
	// is why MinMark is 2.
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
	if mark < MinMark || mark > MaxMark {
		return "", fmt.Errorf("mark %d is out of the usable HTB classid range (%d-%d; 1:1 is the default class)", mark, MinMark, MaxMark)
	}
	return fmt.Sprintf("1:%x", mark), nil
}

// fwFilters lists the tc protocol and prio of each fw filter SetRate
// installs per mark. IPv4 and IPv6 need a filter each, because a tc
// filter only sees packets of its own protocol. They sit at different
// prios because the kernel refuses to mix protocols within one prio, and
// prio 1 already holds protocol ip filters on existing installs.
var fwFilters = []struct{ protocol, prio string }{
	{"ip", "1"},
	{"ipv6", "2"},
}

// fwFilterArgs builds a "tc filter <verb>" command line for mark's fw
// filter of the given protocol/prio.
func (s *Shaper) fwFilterArgs(verb, protocol, prio string, mark uint32, classID string) []string {
	return []string{"filter", verb, "dev", s.iface, "parent", "1:", "protocol", protocol, "prio", prio, "handle", fmt.Sprintf("%d", mark), "fw", "flowid", classID}
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
// not already present, and (re)installs the conntrack mark restore rule
// either way. rootExists should come from a fresh
// RootQdiscExists(s.iface) call — callers that already needed that answer
// for another reason (e.g. deciding whether to auto-detect a rate) pass
// it straight through instead of this re-querying it.
//
// The nft rule is not tied to rootExists: the qdisc can outlive it (an
// earlier start that failed at the nft step, or an nftables service
// reload that flushed the ruleset), and without it nothing is shaped.
func (s *Shaper) EnsureRoot(rootExists bool) error {
	if !rootExists {
		if err := run("tc", "qdisc", "add", "dev", s.iface, "root", "handle", "1:", "htb", "default", "1"); err != nil {
			return fmt.Errorf("creating root htb qdisc on %s: %w", s.iface, err)
		}
		defaultRateBps := s.defaultRateMbit * 1_000_000 / 8
		if err := run("tc", s.classArgs("add", defaultClassID, defaultRateBps)...); err != nil {
			return fmt.Errorf("creating default htb class on %s: %w", s.iface, err)
		}
	}

	if err := ensureConnmarkRestore(); err != nil {
		return fmt.Errorf("setting up conntrack mark restore: %w", err)
	}
	return nil
}

// connmarkRestoreRuleset recreates this package's nft table in a single
// atomic transaction (the leading "table" + "delete table" pair is the
// usual create-if-missing-then-drop idiom), so it is safe to apply on
// every start and replaces any older version of the rule.
//
// "ct mark != 0" matters: an unconditional "meta mark set ct mark" would
// zero the packet mark of every connection this service never marked,
// wiping marks other tools rely on later in postrouting (e.g. Tailscale's
// or kube-proxy's masquerade marks, which nat postrouting checks after
// this mangle-priority chain has run).
var connmarkRestoreRuleset = fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain postrouting {
		type filter hook postrouting priority mangle; policy accept;
		ct mark != 0 meta mark set ct mark
	}
}
`, nftTable)

// ensureConnmarkRestore installs an nftables rule that copies the
// conntrack mark onto the packet mark on the way out, which is what lets
// the "fw" tc filters classify by it. As a side effect, having any
// conntrack-aware rule loaded is also what makes the kernel track
// connections in this network namespace in the first place.
func ensureConnmarkRestore() error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(connmarkRestoreRuleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f -: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetRate creates or updates the HTB class and fw filters for mark.
func (s *Shaper) SetRate(mark uint32, rateBytesPerSec uint32) error {
	classID, err := classIDFor(mark)
	if err != nil {
		return err
	}
	if err := run("tc", s.classArgs("replace", classID, uint64(rateBytesPerSec))...); err != nil {
		return fmt.Errorf("setting htb rate for mark %d on %s: %w", mark, s.iface, err)
	}

	for _, f := range fwFilters {
		if err := run("tc", s.fwFilterArgs("replace", f.protocol, f.prio, mark, classID)...); err != nil {
			return fmt.Errorf("setting %s fw filter for mark %d on %s: %w", f.protocol, mark, s.iface, err)
		}
	}
	return nil
}

// Remove deletes the fw filters and HTB class for mark. A mark outside
// [MinMark, MaxMark] is a no-op: SetRate never creates anything for it,
// and mark 1 would otherwise name the default class.
func (s *Shaper) Remove(mark uint32) error {
	classID, err := classIDFor(mark)
	if err != nil {
		return nil
	}

	for _, f := range fwFilters {
		_ = run("tc", s.fwFilterArgs("del", f.protocol, f.prio, mark, classID)...)
	}

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
