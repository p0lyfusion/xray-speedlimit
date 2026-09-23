// Package api implements the HTTP control plane: the mark -> rate map and
// the email -> mark table.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"

	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
)

// UserMarks reports which mark each user (by email) has been given.
// webhook.Allocator satisfies this.
type UserMarks interface {
	Marks() map[string]uint32
}

type Server struct {
	store limiter.Store
	users UserMarks
	log   *slog.Logger
	mux   *http.ServeMux
}

func New(store limiter.Store, users UserMarks, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{store: store, users: users, log: log, mux: http.NewServeMux()}

	s.mux.HandleFunc("PUT /marks/{mark}", s.handleSet)
	s.mux.HandleFunc("DELETE /marks/{mark}", s.handleDelete)
	s.mux.HandleFunc("GET /marks", s.handleList)
	s.mux.HandleFunc("GET /users", s.handleUsers)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.List()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to list marks: "+err.Error())
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Mark < entries[j].Mark })
	if entries == nil {
		entries = []limiter.Entry{}
	}
	s.writeJSON(w, http.StatusOK, entries)
}

// userMark is one entry of the GET /users response. RateBytesPerSec is
// omitted when the user's mark has no limit set (0 is never a valid rate).
type userMark struct {
	Email           string `json:"email"`
	Mark            uint32 `json:"mark"`
	RateBytesPerSec uint32 `json:"rate_bytes_per_sec,omitempty"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.List()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to list marks: "+err.Error())
		return
	}
	rates := make(map[uint32]uint32, len(entries))
	for _, e := range entries {
		rates[e.Mark] = e.RateBytesPerSec
	}

	users := []userMark{}
	for email, mark := range s.users.Marks() {
		users = append(users, userMark{Email: email, Mark: mark, RateBytesPerSec: rates[mark]})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Mark < users[j].Mark })
	s.writeJSON(w, http.StatusOK, users)
}

type setRequest struct {
	RateBytesPerSec uint64 `json:"rate_bytes_per_sec"`
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	mark, err := parseMark(r.PathValue("mark"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req setRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.RateBytesPerSec == 0 {
		s.writeError(w, http.StatusBadRequest, "rate_bytes_per_sec must be greater than 0")
		return
	}
	if req.RateBytesPerSec > math.MaxUint32 {
		// Rates are stored as uint32 bytes/sec, so the cap is
		// math.MaxUint32 bytes/sec (~34.3 Gbit/s).
		s.writeError(w, http.StatusBadRequest, "rate_bytes_per_sec must not exceed 4294967295")
		return
	}

	if err := s.store.Set(mark, uint32(req.RateBytesPerSec)); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to set rate: "+err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, limiter.Entry{Mark: mark, RateBytesPerSec: uint32(req.RateBytesPerSec)})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	mark, err := parseMark(r.PathValue("mark"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.store.Delete(mark); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to delete mark: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func parseMark(raw string) (uint32, error) {
	if raw == "" {
		return 0, errors.New("mark is required")
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, errors.New("mark must be an unsigned 32-bit integer")
	}
	return uint32(v), nil
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, errorResponse{Error: msg})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("failed to encode response", "error", err)
	}
}
