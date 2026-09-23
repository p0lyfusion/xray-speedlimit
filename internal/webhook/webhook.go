package webhook

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Marker marks a live connection so downstream enforcement (e.g. tc/HTB)
// can act on it. Handler passes dstIP straight through from Xray-core's
// InboundLocal (see parseHostPort below), which is unreliable for some
// inbound/transport combinations and reports the address-family wildcard
// (0.0.0.0 / ::) instead of the real local IP — see conntrack.Marker's
// implementation for why that's a known, tolerated shape of input, not
// invalid data callers need to filter out first.
type Marker interface {
	SetMark(proto string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, mark uint32) error
}

// RateSetter applies a bandwidth cap to a mark (e.g. by creating/updating
// its tc/HTB class). limiter.Store satisfies this. Handler calls it once,
// the moment a mark is newly allocated for an email — not on every
// webhook — since implementations reconfigure real kernel state on each
// call.
type RateSetter interface {
	Set(mark uint32, rateBytesPerSec uint32) error
}

// event mirrors the subset of xray-core's app/router webhook payload
// (see app/router/webhook.go, type event) that is needed to mark the
// client's inbound connection.
type event struct {
	Email        *string `json:"email"`
	Network      *string `json:"network"`
	Source       *string `json:"source"`
	InboundLocal *string `json:"inboundLocal"`
}

// Handler receives xray-core webhook POSTs and applies a conntrack mark
// to the client connection they describe.
type Handler struct {
	alloc                  *Allocator
	marker                 Marker
	rate                   RateSetter
	perUserRateBytesPerSec uint32
	log                    *slog.Logger

	// provisioned records marks whose rate.Set has succeeded (mark ->
	// struct{}). It is read without a lock on every webhook, so an
	// already-provisioned user never waits behind another user's tc call.
	provisioned sync.Map
	// provisionMu serializes rate.Set calls, so two webhooks for a new
	// mark can't provision it twice.
	provisionMu sync.Mutex
}

// New creates a webhook Handler. If rate is non-nil, every newly
// allocated mark is provisioned with a perUserRateBytesPerSec cap via
// rate.Set the moment it's assigned, so per-user limits apply uniformly
// without any external provisioning step. Pass a nil rate to manage
// rates by hand instead (e.g. via the HTTP API), as before this existed.
func New(alloc *Allocator, marker Marker, rate RateSetter, perUserRateBytesPerSec uint32, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		alloc:                  alloc,
		marker:                 marker,
		rate:                   rate,
		perUserRateBytesPerSec: perUserRateBytesPerSec,
		log:                    log,
	}
}

// tryProvision applies the per-user rate to mark if it hasn't been
// applied successfully yet. Unlike isNew from the allocator (which fires
// exactly once, whether or not provisioning then succeeds), this retries
// on every call until rate.Set actually succeeds — a transient tc/nft
// failure on a mark's first webhook would otherwise strand that email
// without a rate for the life of the process, since the allocator has
// already cached the mark by the time the caller learns Set failed.
func (h *Handler) tryProvision(mark uint32) error {
	if _, ok := h.provisioned.Load(mark); ok {
		return nil
	}
	h.provisionMu.Lock()
	defer h.provisionMu.Unlock()
	if _, ok := h.provisioned.Load(mark); ok {
		return nil
	}
	if err := h.rate.Set(mark, h.perUserRateBytesPerSec); err != nil {
		return err
	}
	h.provisioned.Store(mark, struct{}{})
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ev event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid webhook payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if ev.Network != nil && *ev.Network != "" && *ev.Network != "tcp" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ev.Email == nil || ev.Source == nil || ev.InboundLocal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	srcIP, srcPort, err := parseHostPort(*ev.Source)
	if err != nil {
		h.log.Warn("webhook: unparsable source", "source", *ev.Source, "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	dstIP, dstPort, err := parseHostPort(*ev.InboundLocal)
	if err != nil {
		h.log.Warn("webhook: unparsable inboundLocal", "inboundLocal", *ev.InboundLocal, "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	mark, _ := h.alloc.Allocate(*ev.Email)
	if mark == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.rate != nil {
		if err := h.tryProvision(mark); err != nil {
			h.log.Error("webhook: failed to provision per-user rate", "email", *ev.Email, "mark", mark, "error", err)
			http.Error(w, "failed to provision rate for mark", http.StatusInternalServerError)
			return
		}
	}

	if err := h.marker.SetMark("tcp", srcIP, srcPort, dstIP, dstPort, mark); err != nil {
		h.log.Error("webhook: failed to set conntrack mark", "email", *ev.Email, "mark", mark, "error", err)
		http.Error(w, "failed to set conntrack mark", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Email string `json:"email"`
		Mark  uint32 `json:"mark"`
	}{Email: *ev.Email, Mark: mark})
}

// parseHostPort parses xray-core's "ip:port" address fields. It also
// tolerates an optional "proto:" prefix (as used by net.Destination's
// String() elsewhere in xray-core) in case a differently-shaped address
// ends up in these fields.
func parseHostPort(s string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	var ip net.IP
	if err == nil {
		ip = net.ParseIP(host)
	}

	if ip == nil {
		if idx := strings.IndexByte(s, ':'); idx >= 0 && idx+1 < len(s) {
			if h2, p2, err2 := net.SplitHostPort(s[idx+1:]); err2 == nil {
				if ip2 := net.ParseIP(h2); ip2 != nil {
					host, portStr, ip, err = h2, p2, ip2, nil
				}
			}
		}
	}

	if ip == nil {
		if err == nil {
			err = fmt.Errorf("invalid address %q", s)
		}
		return nil, 0, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port in %q: %w", s, err)
	}
	return ip, uint16(port), nil
}
