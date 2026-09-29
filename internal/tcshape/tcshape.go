// Package tcshape enforces per-mark bandwidth limits with one HTB qdisc
// per TX queue, classifying packets by the firewall mark that
// internal/conntrack restores onto them. It only shapes egress (server ->
// client) traffic; see the README for why ingress shaping was left out.
//
// The layout on the interface is:
//
//	root mq 8000:
//	  8000:<q> -> htb <q>: default 1     one per TX queue q = 1..queues
//	                class <q>:1           default class, link rate
//	                class <q>:<minor>     one per user (see internal/mark)
//	                filter fw             no entries: classid = skb mark
//	clsact egress
//	  fw mark <q><<16/0xff0000 -> skbedit queue_mapping <q-1>
//
// Each queue's HTB has its own lock, so shaping scales across CPUs instead
// of serializing every packet on one root qdisc. A mark (q<<16 | minor) is
// steered onto TX queue q-1 by the clsact filter, and the filter-less fw
// classifier in htb q: then uses the mark itself as the classid q:minor.
// Traffic with no mark keeps the queue the kernel picks and lands in that
// queue's default class.
package tcshape

import (
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/p0lyfusion/xray-speedlimit/internal/mark"
)

const (
	// mqHandle is the root mq qdisc's handle. Its classes are
	// 8000:1..8000:<num_tx_queues>, one per TX queue.
	mqHandle = "8000:"

	// steerPref is the tc filter priority of this package's clsact
	// egress steering filters. A dedicated priority lets them be replaced
	// without touching filters other tools keep on the same clsact.
	steerPref = "49000"

	nftTable = "xray_speedlimit"

	// minHTBBurstBytes floors the computed burst/cburst size so a very
	// low class rate (or a short burstMs) can't round down to a value tc
	// rejects as too small for the rate.
	minHTBBurstBytes = 2048
)

// Shaper manages the per-queue HTB layout and one class per mark on a
// single network interface.
type Shaper struct {
	iface   string
	queues  int
	burstMs uint64
}

// New creates a Shaper for iface, which has queues TX queues in use
// (1..mark.MaxQueues). burstMs sets every class's burst/cburst allowance to
// that many milliseconds' worth of bytes at the class's own rate (0 leaves
// it at the kernel's own default sizing, which is normally just a couple
// KB — enough to smoothly pace traffic, not enough to avoid throttling
// short bursts like a page load or TCP slow start).
func New(iface string, queues int, burstMs uint64) *Shaper {
	return &Shaper{iface: iface, queues: queues, burstMs: burstMs}
}

// htbHandle is the handle of queue major's HTB qdisc.
func htbHandle(major uint32) string {
	return fmt.Sprintf("%x:", major)
}

// mqClass is the mq class (TX queue major-1) queue major's HTB hangs off.
func mqClass(major uint32) string {
	return fmt.Sprintf("%s%x", mqHandle, major)
}

// classIDFor renders mark as its HTB classid, major:minor in hex as tc
// expects, and returns the major too. The classid's numeric value equals
// the mark, which is what lets the filter-less fw classifier map a mark
// straight to its class.
func (s *Shaper) classIDFor(m uint32) (classID string, major uint32, err error) {
	major, minor, ok := mark.Split(m, s.queues)
	if !ok {
		return "", 0, fmt.Errorf("mark %#x is not a user mark for %d queues (want (queue 1-%d)<<16 | minor %d-65535)", m, s.queues, s.queues, mark.MinMinor)
	}
	return fmt.Sprintf("%x:%x", major, minor), major, nil
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
// ..." command line for a class under HTB major.
func (s *Shaper) classArgs(verb string, major uint32, classID string, rateBytesPerSec uint64) []string {
	return append([]string{"class", verb, "dev", s.iface, "parent", htbHandle(major), "classid", classID},
		htbRateArgs(rateBytesPerSec, s.burstMs)...)
}

// tcQdisc is one entry of "tc -j qdisc show".
type tcQdisc struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Parent string `json:"parent"`
	Root   bool   `json:"root"`
}

// LayoutExists reports whether iface already has this package's layout
// for exactly this many queues, e.g. from an earlier run. A layout for a
// different queue count (the queue count was changed with ethtool -L)
// doesn't count: every mark depends on the queue count, so it has to be
// rebuilt.
func (s *Shaper) LayoutExists() (bool, error) {
	qdiscs, err := s.qdiscs()
	if err != nil {
		return false, err
	}
	return layoutMatches(qdiscs, s.queues), nil
}

func (s *Shaper) qdiscs() ([]tcQdisc, error) {
	out, err := runJSON("tc", "-j", "qdisc", "show", "dev", s.iface)
	if err != nil {
		return nil, err
	}
	var qdiscs []tcQdisc
	if err := json.Unmarshal(out, &qdiscs); err != nil {
		return nil, fmt.Errorf("parsing tc qdisc output: %w", err)
	}
	return qdiscs, nil
}

// layoutMatches reports whether qdiscs are an mq root with an HTB child
// on each of the first queues TX queues and no HTB on any other.
func layoutMatches(qdiscs []tcQdisc, queues int) bool {
	rootOK := false
	htbs := 0
	for _, q := range qdiscs {
		switch {
		case q.Root && q.Kind == "mq" && q.Handle == mqHandle:
			rootOK = true
		case q.Kind == "htb":
			major, err := strconv.ParseUint(strings.TrimSuffix(q.Handle, ":"), 16, 32)
			if err != nil || major < 1 || major > uint64(queues) || q.Parent != mqClass(uint32(major)) {
				return false
			}
			htbs++
		}
	}
	return rootOK && htbs == queues
}

// EnsureRoot builds the layout unless layoutExists (from a fresh
// LayoutExists call) says it is already there, then (re)installs the
// steering filters and the conntrack mark restore rule.
// defaultRateMbit is the rate of each queue's default class, and is only
// used when building; see the README for why it must reflect the
// interface's real link capacity.
//
// Building replaces the root qdisc, which drops whatever tree was there
// before, including a single-HTB layout from older versions, along with
// every per-user class. Flows marked under an older layout carry marks
// no class matches, so they ride their queue's default class until a
// webhook re-marks them.
//
// The steering filters and the nft rule are not tied to layoutExists:
// the qdisc can outlive either (a clsact removed by another tool, an
// nftables service reload that flushed the ruleset), and without them
// nothing is shaped.
func (s *Shaper) EnsureRoot(layoutExists bool, defaultRateMbit uint64) error {
	if !layoutExists {
		if err := s.buildLayout(defaultRateMbit); err != nil {
			return err
		}
	}
	if err := s.ensureSteering(); err != nil {
		return err
	}
	if err := ensureConnmarkRestore(); err != nil {
		return fmt.Errorf("setting up conntrack mark restore: %w", err)
	}
	return nil
}

func (s *Shaper) buildLayout(defaultRateMbit uint64) error {
	// Delete and add rather than replace: replacing an mq 8000: root with
	// another one only changes it in place, keeping its old HTB children,
	// and then adding them again fails. Deleting fails harmlessly when
	// the device still has its default root qdisc; any real problem shows
	// up in the add.
	_ = exec.Command("tc", "qdisc", "del", "dev", s.iface, "root").Run()
	if err := run("tc", "qdisc", "add", "dev", s.iface, "root", "handle", mqHandle, "mq"); err != nil {
		return fmt.Errorf("creating root mq qdisc on %s: %w", s.iface, err)
	}
	defaultRateBps := defaultRateMbit * 1_000_000 / 8
	for q := uint32(1); q <= uint32(s.queues); q++ {
		handle := htbHandle(q)
		if err := run("tc", "qdisc", "add", "dev", s.iface, "parent", mqClass(q), "handle", handle, "htb", "default", "1"); err != nil {
			return fmt.Errorf("creating htb qdisc for TX queue %d on %s: %w", q-1, s.iface, err)
		}
		if err := run("tc", s.classArgs("add", q, handle+"1", defaultRateBps)...); err != nil {
			return fmt.Errorf("creating default htb class for TX queue %d on %s: %w", q-1, s.iface, err)
		}
		// A fw filter with no entries uses the skb mark itself as the
		// classid, for marks whose major is this qdisc's handle.
		if err := run("tc", "filter", "add", "dev", s.iface, "parent", handle, "protocol", "all", "prio", "1", "fw"); err != nil {
			return fmt.Errorf("creating fw classifier for TX queue %d on %s: %w", q-1, s.iface, err)
		}
	}
	return nil
}

// tcFilter is one entry of "tc -j filter show".
type tcFilter struct {
	Kind    string `json:"kind"`
	Pref    int    `json:"pref"`
	Options *struct {
		Fw *struct {
			Mark string `json:"mark"`
			Mask string `json:"mask"`
		} `json:"fw"`
		Actions []struct {
			Kind         string `json:"kind"`
			QueueMapping *int   `json:"queue_mapping"`
		} `json:"actions"`
	} `json:"options"`
}

// ensureSteering makes sure clsact egress holds exactly one steering
// filter per queue at steerPref, rebuilding the set if it doesn't.
func (s *Shaper) ensureSteering() error {
	qdiscs, err := s.qdiscs()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(qdiscs, func(q tcQdisc) bool { return q.Kind == "clsact" }) {
		if err := run("tc", "qdisc", "add", "dev", s.iface, "clsact"); err != nil {
			return fmt.Errorf("creating clsact qdisc on %s: %w", s.iface, err)
		}
	} else {
		out, err := runJSON("tc", "-j", "filter", "show", "dev", s.iface, "egress", "pref", steerPref)
		if err != nil {
			return err
		}
		var filters []tcFilter
		if err := json.Unmarshal(out, &filters); err != nil {
			return fmt.Errorf("parsing tc filter output: %w", err)
		}
		if steeringMatches(filters, s.queues) {
			return nil
		}
		// Deleting by priority removes only this package's filters.
		if len(filters) > 0 {
			if err := run("tc", "filter", "del", "dev", s.iface, "egress", "pref", steerPref); err != nil {
				return fmt.Errorf("removing old steering filters on %s: %w", s.iface, err)
			}
		}
	}

	for q := uint32(1); q <= uint32(s.queues); q++ {
		if err := run("tc", "filter", "add", "dev", s.iface, "egress", "protocol", "all", "pref", steerPref,
			"handle", fmt.Sprintf("%#x/%#x", mark.Join(q, 0), mark.QueueMask), "fw",
			"action", "skbedit", "queue_mapping", strconv.Itoa(int(q-1))); err != nil {
			return fmt.Errorf("creating steering filter for TX queue %d on %s: %w", q-1, s.iface, err)
		}
	}
	return nil
}

// steeringMatches reports whether filters (all at steerPref) steer each
// of queues queue fields to its TX queue and do nothing else.
func steeringMatches(filters []tcFilter, queues int) bool {
	seen := make(map[int]bool)
	for _, f := range filters {
		if f.Options == nil {
			continue // the classifier's own header entry
		}
		if f.Kind != "fw" || f.Options.Fw == nil || len(f.Options.Actions) != 1 {
			return false
		}
		markVal, err1 := strconv.ParseUint(f.Options.Fw.Mark, 0, 32)
		mask, err2 := strconv.ParseUint(f.Options.Fw.Mask, 0, 32)
		a := f.Options.Actions[0]
		if err1 != nil || err2 != nil || mask != mark.QueueMask || markVal&^mark.QueueMask != 0 ||
			a.Kind != "skbedit" || a.QueueMapping == nil {
			return false
		}
		q := int(markVal >> 16)
		if q < 1 || q > queues || *a.QueueMapping != q-1 || seen[q] {
			return false
		}
		seen[q] = true
	}
	return len(seen) == queues
}

// SetRate creates or updates mark's class with the given rate.
func (s *Shaper) SetRate(m uint32, rateBytesPerSec uint32) error {
	classID, major, err := s.classIDFor(m)
	if err != nil {
		return err
	}
	if err := run("tc", s.classArgs("replace", major, classID, uint64(rateBytesPerSec))...); err != nil {
		return fmt.Errorf("setting htb rate for mark %#x on %s: %w", m, s.iface, err)
	}
	return nil
}

// Remove deletes mark's class. A value that isn't a user mark is a no-op:
// SetRate never creates anything for it, and minor 1 would otherwise name
// a queue's default class.
func (s *Shaper) Remove(m uint32) error {
	classID, _, err := s.classIDFor(m)
	if err != nil {
		return nil
	}
	out, err := exec.Command("tc", "class", "del", "dev", s.iface, "classid", classID).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file or directory") {
		return fmt.Errorf("removing htb class for mark %#x on %s: %w: %s", m, s.iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Class is a per-user class found on the interface.
type Class struct {
	Mark            uint32
	RateBytesPerSec uint32
	// Bytes is how many bytes the class has sent since it was created.
	Bytes uint64
}

// tcClass is one entry of "tc -j -s class show".
type tcClass struct {
	Class  string `json:"class"`
	Handle string `json:"handle"`
	Rate   uint64 `json:"rate"`
	Stats  struct {
		Bytes uint64 `json:"bytes"`
	} `json:"stats"`
}

// Classes lists every per-user class on the interface, in one tc call.
func (s *Shaper) Classes() ([]Class, error) {
	out, err := runJSON("tc", "-j", "-s", "class", "show", "dev", s.iface)
	if err != nil {
		return nil, err
	}
	return parseClasses(out, s.queues)
}

func parseClasses(out []byte, queues int) ([]Class, error) {
	var raw []tcClass
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("parsing tc class output: %w", err)
	}
	var classes []Class
	for _, c := range raw {
		if c.Class != "htb" {
			continue
		}
		majorStr, minorStr, ok := strings.Cut(c.Handle, ":")
		if !ok {
			continue
		}
		major, err1 := strconv.ParseUint(majorStr, 16, 16)
		minor, err2 := strconv.ParseUint(minorStr, 16, 16)
		if err1 != nil || err2 != nil {
			continue
		}
		m := mark.Join(uint32(major), uint32(minor))
		if _, _, ok := mark.Split(m, queues); !ok {
			continue // a default class, or not ours
		}
		classes = append(classes, Class{Mark: m, RateBytesPerSec: uint32(min(c.Rate, math.MaxUint32)), Bytes: c.Stats.Bytes})
	}
	return classes, nil
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
// the steering filters and fw classifiers act on it. As a side effect,
// having any conntrack-aware rule loaded is also what makes the kernel
// track connections in this network namespace in the first place.
func ensureConnmarkRestore() error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(connmarkRestoreRuleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f -: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runJSON runs a tc command whose stdout is JSON, returning stdout alone:
// tc can print warnings to stderr even when it succeeds.
func runJSON(name string, args ...string) ([]byte, error) {
	var stderr strings.Builder
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// run runs an external command and returns a wrapped error (with output
// attached) on failure.
func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
