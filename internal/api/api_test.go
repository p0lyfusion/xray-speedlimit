package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
)

type memStore struct {
	mu      sync.Mutex
	entries map[uint32]uint32
}

func newMemStore() *memStore {
	return &memStore{entries: make(map[uint32]uint32)}
}

func (m *memStore) Set(mark uint32, rate uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[mark] = rate
	return nil
}

func (m *memStore) Delete(mark uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, mark)
	return nil
}

func (m *memStore) List() ([]limiter.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]limiter.Entry, 0, len(m.entries))
	for mark, rate := range m.entries {
		out = append(out, limiter.Entry{Mark: mark, RateBytesPerSec: rate})
	}
	return out, nil
}

type fakeUsers map[string]uint32

func (f fakeUsers) Marks() map[string]uint32 { return f }

func doRequest(t *testing.T, s *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	s := New(newMemStore(), fakeUsers{}, nil)
	rec := doRequest(t, s, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestSetAndListAndDelete(t *testing.T) {
	s := New(newMemStore(), fakeUsers{}, nil)

	rec := doRequest(t, s, http.MethodPut, "/marks/42", setRequest{RateBytesPerSec: 1_000_000})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, s, http.MethodGet, "/marks", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var entries []limiter.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 || entries[0].Mark != 42 || entries[0].RateBytesPerSec != 1_000_000 {
		t.Fatalf("unexpected entries: %+v", entries)
	}

	rec = doRequest(t, s, http.MethodDelete, "/marks/42", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	rec = doRequest(t, s, http.MethodGet, "/marks", nil)
	entries = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty list after delete, got %+v", entries)
	}
}

func TestSetInvalidMark(t *testing.T) {
	s := New(newMemStore(), fakeUsers{}, nil)

	cases := []string{"-1", "abc", "4294967296", ""}
	for _, mark := range cases {
		path := "/marks/" + mark
		if mark == "" {
			path = "/marks/"
		}
		rec := doRequest(t, s, http.MethodPut, path, setRequest{RateBytesPerSec: 1})
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("mark %q: expected 400 or 404, got %d: %s", mark, rec.Code, rec.Body.String())
		}
	}
}

func TestSetInvalidRate(t *testing.T) {
	s := New(newMemStore(), fakeUsers{}, nil)

	rec := doRequest(t, s, http.MethodPut, "/marks/1", setRequest{RateBytesPerSec: 0})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rate 0: expected 400, got %d", rec.Code)
	}

	rec = doRequest(t, s, http.MethodPut, "/marks/1", map[string]uint64{"rate_bytes_per_sec": 4294967296})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rate over uint32: expected 400, got %d", rec.Code)
	}
}

func TestSetUnknownField(t *testing.T) {
	s := New(newMemStore(), fakeUsers{}, nil)

	rec := doRequest(t, s, http.MethodPut, "/marks/1", map[string]any{"rate_bytes_per_sec": 1, "burst": 1})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", rec.Code)
	}
}

func TestUsers(t *testing.T) {
	store := newMemStore()
	if err := store.Set(20000, 12500000); err != nil {
		t.Fatal(err)
	}
	s := New(store, fakeUsers{"b@example.com": 20001, "a@example.com": 20000}, nil)

	rec := doRequest(t, s, http.MethodGet, "/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var users []userMark
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []userMark{
		{Email: "a@example.com", Mark: 20000, RateBytesPerSec: 12500000},
		{Email: "b@example.com", Mark: 20001},
	}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("got %+v, want %+v (sorted by mark)", users, want)
	}
	if strings.Contains(rec.Body.String(), `"mark":20001,"rate_bytes_per_sec"`) {
		t.Fatalf("unlimited user should have no rate field: %s", rec.Body.String())
	}
}

func TestUsersEmptyIsArray(t *testing.T) {
	s := New(newMemStore(), fakeUsers{}, nil)

	rec := doRequest(t, s, http.MethodGet, "/users", nil)
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Fatalf("expected [] for no users, got %q", got)
	}
}
