package webhook

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeMarker struct {
	mu    sync.Mutex
	calls []call
	err   error
}

type call struct {
	proto            string
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	mark             uint32
}

func (f *fakeMarker) SetMark(proto string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, mark uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{proto, srcIP, dstIP, srcPort, dstPort, mark})
	return f.err
}

type fakeRateSetter struct {
	mu       sync.Mutex
	rates    map[uint32]uint32
	err      error
	setCalls int
}

func newFakeRateSetter() *fakeRateSetter {
	return &fakeRateSetter{rates: make(map[uint32]uint32)}
}

func (f *fakeRateSetter) Set(mark uint32, rateBytesPerSec uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	if f.err != nil {
		return f.err
	}
	f.rates[mark] = rateBytesPerSec
	return nil
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook/xray", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerMarksRealEvent(t *testing.T) {
	marker := &fakeMarker{}
	h := New(NewAllocator(1000, 10, nil), marker, nil, 0, nil)

	body := `{
		"email": "user-a",
		"level": null,
		"protocol": "tls",
		"network": "tcp",
		"source": "203.0.113.7:54203",
		"destination": "dns.google:443",
		"routeTarget": null,
		"originalTarget": "tcp:8.8.8.8:443",
		"inboundTag": "VLESS_TCP",
		"inboundLocal": "198.51.100.1:443",
		"outboundTag": "direct",
		"ts": 1771886901
	}`
	rec := post(t, h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	marker.mu.Lock()
	defer marker.mu.Unlock()
	if len(marker.calls) != 1 {
		t.Fatalf("expected 1 SetMark call, got %d", len(marker.calls))
	}
	c := marker.calls[0]
	if c.proto != "tcp" || c.srcPort != 54203 || c.dstPort != 443 ||
		c.srcIP.String() != "203.0.113.7" || c.dstIP.String() != "198.51.100.1" {
		t.Fatalf("unexpected call: %+v", c)
	}
}

func TestHandlerStableMarkAcrossCalls(t *testing.T) {
	marker := &fakeMarker{}
	h := New(NewAllocator(1, 10, nil), marker, nil, 0, nil)

	body := `{"email":"user-a","network":"tcp","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`
	post(t, h, body)
	post(t, h, body)

	marker.mu.Lock()
	defer marker.mu.Unlock()
	if len(marker.calls) != 2 || marker.calls[0].mark != marker.calls[1].mark {
		t.Fatalf("expected stable mark across calls, got %+v", marker.calls)
	}
}

// waitFor polls cond until it holds, failing the test after 2 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *fakeRateSetter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setCalls
}

func TestHandlerProvisionsRateOnlyOnFirstAllocation(t *testing.T) {
	marker := &fakeMarker{}
	rate := newFakeRateSetter()
	h := New(NewAllocator(1, 10, nil), marker, rate, 12_500_000, nil)

	body := `{"email":"user-a","network":"tcp","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`
	post(t, h, body)
	post(t, h, body)
	waitFor(t, "provisioning", func() bool { _, ok := h.provisioned.Load(uint32(1)); return ok })
	post(t, h, body)

	marker.mu.Lock()
	mark := marker.calls[0].mark
	marker.mu.Unlock()

	rate.mu.Lock()
	defer rate.mu.Unlock()
	if got, ok := rate.rates[mark]; !ok || got != 12_500_000 {
		t.Fatalf("expected mark %d provisioned at 12500000 bytes/sec, got %v (present=%v)", mark, got, ok)
	}
	if rate.setCalls != 1 {
		t.Fatalf("expected Set called exactly once across 3 identical requests, got %d calls", rate.setCalls)
	}
}

func TestHandlerRateSetterErrorStillMarks(t *testing.T) {
	marker := &fakeMarker{}
	rate := newFakeRateSetter()
	rate.err = errors.New("tc failed")
	h := New(NewAllocator(1, 10, nil), marker, rate, 12_500_000, nil)

	rec := post(t, h, `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200: a provisioning failure must not stop marking, got %d", rec.Code)
	}
	marker.mu.Lock()
	defer marker.mu.Unlock()
	if len(marker.calls) != 1 {
		t.Fatalf("expected 1 SetMark call, got %d", len(marker.calls))
	}
}

// blockingRateSetter blocks every Set until release is closed.
type blockingRateSetter struct {
	release chan struct{}
}

func (b *blockingRateSetter) Set(uint32, uint32) error {
	<-b.release
	return nil
}

func TestHandlerMarksWithoutWaitingForProvisioning(t *testing.T) {
	marker := &fakeMarker{}
	rate := &blockingRateSetter{release: make(chan struct{})}
	defer close(rate.release)
	h := New(NewAllocator(1, 10, nil), marker, rate, 12_500_000, nil)

	done := make(chan int, 2)
	for _, email := range []string{"user-a", "user-b"} {
		go func() {
			done <- post(t, h, `{"email":"`+email+`","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`).Code
		}()
	}
	for range 2 {
		select {
		case code := <-done:
			if code != http.StatusOK {
				t.Fatalf("expected 200, got %d", code)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("webhook blocked on provisioning")
		}
	}
	marker.mu.Lock()
	defer marker.mu.Unlock()
	if len(marker.calls) != 2 {
		t.Fatalf("expected both connections marked while provisioning is stuck, got %d", len(marker.calls))
	}
}

func TestHandlerRetriesProvisioningAfterFailure(t *testing.T) {
	rate := newFakeRateSetter()
	rate.err = errors.New("tc failed")
	h := New(NewAllocator(1, 10, nil), &fakeMarker{}, rate, 12_500_000, nil)

	body := `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`
	notQueued := func() bool { _, ok := h.queued.Load(uint32(1)); return !ok }

	// The allocator hands out the mark for user-a on this first call even
	// though provisioning then fails, so a naive "only on first allocation"
	// gate would never retry -- confirm it does.
	post(t, h, body)
	waitFor(t, "the failing attempt", func() bool { return rate.calls() == 1 && notQueued() })

	rate.mu.Lock()
	rate.err = nil
	rate.mu.Unlock()

	post(t, h, body)
	waitFor(t, "the retry", func() bool { return rate.calls() == 2 && notQueued() })
	rate.mu.Lock()
	got, ok := rate.rates[1]
	rate.mu.Unlock()
	if !ok || got != 12_500_000 {
		t.Fatalf("expected mark 1 provisioned at 12500000 bytes/sec after recovery, got %v (present=%v)", got, ok)
	}

	// A third call must not call Set again now that it succeeded once.
	post(t, h, body)
	time.Sleep(20 * time.Millisecond)
	if setCalls := rate.calls(); setCalls != 2 {
		t.Fatalf("expected Set called twice total (failing attempt + successful retry), got %d", setCalls)
	}
}

func TestHandlerNilRateSetterSkipsProvisioning(t *testing.T) {
	marker := &fakeMarker{}
	h := New(NewAllocator(1, 10, nil), marker, nil, 0, nil)

	rec := post(t, h, `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with no rate setter configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerInvalidJSON(t *testing.T) {
	h := New(NewAllocator(1, 10, nil), &fakeMarker{}, nil, 0, nil)
	rec := post(t, h, `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandlerMissingFieldsNoOp(t *testing.T) {
	marker := &fakeMarker{}
	h := New(NewAllocator(1, 10, nil), marker, nil, 0, nil)

	cases := []string{
		`{}`,
		`{"email":null,"source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`,
		`{"email":"user-a","source":null,"inboundLocal":"2.2.2.2:2"}`,
		`{"email":"user-a","source":"1.1.1.1:1","inboundLocal":null}`,
		`{"email":"user-a","network":"udp","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`,
		`{"email":"user-a","source":"not-an-address","inboundLocal":"2.2.2.2:2"}`,
	}
	for _, body := range cases {
		rec := post(t, h, body)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("body %q: expected 204, got %d", body, rec.Code)
		}
	}

	marker.mu.Lock()
	defer marker.mu.Unlock()
	if len(marker.calls) != 0 {
		t.Fatalf("expected no SetMark calls, got %d", len(marker.calls))
	}
}

func TestHandlerMarkerError(t *testing.T) {
	marker := &fakeMarker{err: errors.New("boom")}
	h := New(NewAllocator(1, 10, nil), marker, nil, 0, nil)

	rec := post(t, h, `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestParseHostPort(t *testing.T) {
	cases := []struct {
		in      string
		wantIP  string
		wantErr bool
	}{
		{"203.0.113.7:54203", "203.0.113.7", false},
		{"tcp:203.0.113.7:54203", "203.0.113.7", false},
		{"[::1]:443", "::1", false},
		{"not-an-address", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		ip, port, err := parseHostPort(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseHostPort(%q): expected error, got ip=%v port=%d", tc.in, ip, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseHostPort(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if ip.String() != tc.wantIP {
			t.Errorf("parseHostPort(%q): ip = %v, want %v", tc.in, ip, tc.wantIP)
		}
	}
}

type diagnosingMarker struct {
	fakeMarker
	diagnosed chan struct{}
}

func (d *diagnosingMarker) DiagnoseMiss(net.IP, uint16, uint16) ([]any, error) {
	d.diagnosed <- struct{}{}
	return []any{"hint", "test"}, nil
}

func TestHandlerDiagnosesMissOncePerInterval(t *testing.T) {
	marker := &diagnosingMarker{fakeMarker: fakeMarker{err: errors.New("boom")}, diagnosed: make(chan struct{}, 10)}
	h := New(NewAllocator(1, 10, nil), marker, nil, 0, nil)

	for range 5 {
		post(t, h, `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`)
	}
	select {
	case <-marker.diagnosed:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a diagnosis after a failed mark")
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(marker.diagnosed); n != 0 {
		t.Fatalf("expected one diagnosis per interval, got %d more", n)
	}

	// Once the interval has passed, the next failure diagnoses again.
	h.lastDiagnose.Add(-int64(missDiagnoseInterval))
	post(t, h, `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`)
	select {
	case <-marker.diagnosed:
	case <-time.After(2 * time.Second):
		t.Fatal("expected another diagnosis once the interval passed")
	}
}
