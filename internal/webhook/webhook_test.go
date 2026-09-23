package webhook

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
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

func TestHandlerProvisionsRateOnlyOnFirstAllocation(t *testing.T) {
	marker := &fakeMarker{}
	rate := newFakeRateSetter()
	h := New(NewAllocator(1, 10, nil), marker, rate, 12_500_000, nil)

	body := `{"email":"user-a","network":"tcp","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`
	post(t, h, body)
	post(t, h, body)
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

func TestHandlerRateSetterErrorFailsRequest(t *testing.T) {
	rate := newFakeRateSetter()
	rate.err = errors.New("tc failed")
	h := New(NewAllocator(1, 10, nil), &fakeMarker{}, rate, 12_500_000, nil)

	rec := post(t, h, `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestHandlerRetriesProvisioningAfterFailure(t *testing.T) {
	rate := newFakeRateSetter()
	rate.err = errors.New("tc failed")
	h := New(NewAllocator(1, 10, nil), &fakeMarker{}, rate, 12_500_000, nil)

	body := `{"email":"user-a","source":"1.1.1.1:1","inboundLocal":"2.2.2.2:2"}`

	// The allocator hands out the mark for user-a on this first call even
	// though provisioning then fails, so a naive "only on first allocation"
	// gate would never retry -- confirm it does.
	if rec := post(t, h, body); rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on first (failing) attempt, got %d", rec.Code)
	}

	rate.mu.Lock()
	rate.err = nil
	rate.mu.Unlock()

	rec := post(t, h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 once the rate setter recovers, got %d: %s", rec.Code, rec.Body.String())
	}
	rate.mu.Lock()
	got, ok := rate.rates[1]
	rate.mu.Unlock()
	if !ok || got != 12_500_000 {
		t.Fatalf("expected mark 1 provisioned at 12500000 bytes/sec after recovery, got %v (present=%v)", got, ok)
	}

	// A third call must not call Set again now that it succeeded once.
	rec = post(t, h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on third call, got %d", rec.Code)
	}
	rate.mu.Lock()
	setCalls := rate.setCalls
	rate.mu.Unlock()
	if setCalls != 2 {
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
