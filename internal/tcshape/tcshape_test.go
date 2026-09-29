package tcshape

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestHtbBurstBytes(t *testing.T) {
	if got := htbBurstBytes(0, 0); got != 0 {
		t.Fatalf("burstMs=0 should disable burst, got %d", got)
	}
	// 10 Mbit/s = 1,250,000 bytes/sec; 100ms worth = 125,000 bytes.
	if got := htbBurstBytes(1_250_000, 100); got != 125_000 {
		t.Fatalf("got %d, want 125000", got)
	}
	// A tiny rate/duration should clamp to the floor, not round to ~0
	// (tc rejects a burst too small for the configured rate).
	if got := htbBurstBytes(10, 100); got != minHTBBurstBytes {
		t.Fatalf("got %d, want floor %d", got, minHTBBurstBytes)
	}
}

func TestHtbRateArgs(t *testing.T) {
	// 1,250,000 bytes/sec = 10,000,000 bit/s.
	got := htbRateArgs(1_250_000, 100)
	want := []string{"htb", "rate", "10000000bit", "burst", "125000b", "cburst", "125000b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	noBurst := htbRateArgs(1_250_000, 0)
	want = []string{"htb", "rate", "10000000bit"}
	if !reflect.DeepEqual(noBurst, want) {
		t.Fatalf("burstMs=0 should omit burst/cburst args, got %v", noBurst)
	}
}

func TestClassIDFor(t *testing.T) {
	s := New("eth0", 48, 0)
	if got, major, err := s.classIDFor(0x3002a); err != nil || got != "3:2a" || major != 3 {
		t.Fatalf("classIDFor(0x3002a) = %q, %d, %v; want 3:2a, 3", got, major, err)
	}
	if got, major, err := s.classIDFor(0x30ffff); err != nil || got != "30:ffff" || major != 0x30 {
		t.Fatalf("classIDFor(0x30ffff) = %q, %d, %v; want 30:ffff, 48", got, major, err)
	}
	for _, m := range []uint32{0, 1, 0x2a, 0x30001, 0x31002a} {
		if got, _, err := s.classIDFor(m); err == nil {
			t.Errorf("classIDFor(%#x) = %q, want an error", m, got)
		}
	}
}

func TestRemoveIgnoresNonUserMarks(t *testing.T) {
	// Would otherwise run tc against a default class (minor 1).
	if err := New("eth0", 4, 0).Remove(0x30001); err != nil {
		t.Fatalf("Remove(default class mark) = %v, want nil", err)
	}
}

// Captured from "tc -j qdisc show" on a 4-queue veth.
const qdiscJSON = `[{"kind":"mq","handle":"8000:","root":true,"options":{}},` +
	`{"kind":"htb","handle":"4:","parent":"8000:4","options":{}},{"kind":"htb","handle":"3:","parent":"8000:3","options":{}},` +
	`{"kind":"htb","handle":"2:","parent":"8000:2","options":{}},{"kind":"htb","handle":"1:","parent":"8000:1","options":{}},` +
	`{"kind":"clsact","handle":"ffff:","parent":"ffff:fff1","options":{}}]`

func TestLayoutMatches(t *testing.T) {
	var qdiscs []tcQdisc
	if err := json.Unmarshal([]byte(qdiscJSON), &qdiscs); err != nil {
		t.Fatal(err)
	}
	if !layoutMatches(qdiscs, 4) {
		t.Fatal("expected the 4-queue layout to match 4 queues")
	}
	if layoutMatches(qdiscs, 3) || layoutMatches(qdiscs, 5) {
		t.Fatal("a layout for another queue count must not match")
	}

	oldLayout := []tcQdisc{{Kind: "htb", Handle: "1:", Root: true}}
	if layoutMatches(oldLayout, 1) {
		t.Fatal("the old single-HTB root must not match")
	}
	misplaced := []tcQdisc{{Kind: "mq", Handle: mqHandle, Root: true}, {Kind: "htb", Handle: "1:", Parent: "8000:2"}}
	if layoutMatches(misplaced, 1) {
		t.Fatal("an HTB on the wrong queue must not match")
	}
}

// Captured from "tc -j filter show dev v0 egress pref 49000".
const steeringJSON = `[{"protocol":"all","pref":49000,"kind":"fw","chain":0},` +
	`{"protocol":"all","pref":49000,"kind":"fw","chain":0,"options":{"fw":{"mark":"0x10000","mask":"0xff0000"},"actions":[{"order":1,"kind":"skbedit","queue_mapping":0,"control_action":{"type":"pipe"},"index":1,"ref":1,"bind":1}]}},` +
	`{"protocol":"all","pref":49000,"kind":"fw","chain":0,"options":{"fw":{"mark":"0x20000","mask":"0xff0000"},"actions":[{"order":1,"kind":"skbedit","queue_mapping":1,"control_action":{"type":"pipe"},"index":2,"ref":1,"bind":1}]}}]`

func TestSteeringMatches(t *testing.T) {
	var filters []tcFilter
	if err := json.Unmarshal([]byte(steeringJSON), &filters); err != nil {
		t.Fatal(err)
	}
	if !steeringMatches(filters, 2) {
		t.Fatal("expected filters for queues 1-2 to match 2 queues")
	}
	if steeringMatches(filters, 3) || steeringMatches(filters, 1) {
		t.Fatal("filters for another queue count must not match")
	}

	wrong := strings.Replace(steeringJSON, `"queue_mapping":1`, `"queue_mapping":0`, 1)
	if err := json.Unmarshal([]byte(wrong), &filters); err != nil {
		t.Fatal(err)
	}
	if steeringMatches(filters, 2) {
		t.Fatal("a filter steering to the wrong queue must not match")
	}
}

// Captured from "tc -j -s class show", trimmed.
const classJSON = `[{"class":"mq","handle":"8000:1","root":true,"leaf":"0x1","stats":{"bytes":0,"packets":0}},` +
	`{"class":"htb","handle":"2:2a","root":true,"prio":0,"rate":15000000,"ceil":15000000,"burst":15000000,"cburst":15000000,"stats":{"bytes":20840,"packets":20}},` +
	`{"class":"htb","handle":"2:1","root":true,"prio":0,"rate":125000000,"ceil":125000000,"stats":{"bytes":176,"packets":2}},` +
	`{"class":"htb","handle":"9:2a","root":true,"prio":0,"rate":15000000,"stats":{"bytes":0}}]`

func TestParseClasses(t *testing.T) {
	classes, err := parseClasses([]byte(classJSON), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []Class{{Mark: 0x2002a, RateBytesPerSec: 15_000_000, Bytes: 20840}}
	if !reflect.DeepEqual(classes, want) {
		t.Fatalf("got %+v, want %+v (default classes and other queues skipped)", classes, want)
	}
}
