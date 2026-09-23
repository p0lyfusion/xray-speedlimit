package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/p0lyfusion/xray-speedlimit/internal/api"
	"github.com/p0lyfusion/xray-speedlimit/internal/conntrack"
	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
	"github.com/p0lyfusion/xray-speedlimit/internal/netif"
	"github.com/p0lyfusion/xray-speedlimit/internal/tcshape"
	"github.com/p0lyfusion/xray-speedlimit/internal/webhook"
)

// readHeaderTimeout bounds how long either server waits for a request's
// headers, so a client that connects and stalls can't hold a connection
// (and a file descriptor) open indefinitely.
const readHeaderTimeout = 10 * time.Second

// config holds everything main's flags configure.
type config struct {
	addr                 string
	webhookAddr          string
	iface                string
	marks                markRange
	defaultClassRateMbit uint64
	htbBurstMs           uint64
	perUserRateMbit      uint64
}

func main() {
	cfg := config{marks: markRange{first: 20000, last: 39999}}

	flag.StringVar(&cfg.addr, "addr", ":7070", "HTTP API listen address")
	flag.StringVar(&cfg.webhookAddr, "webhook-addr", "@xray-speedlimit-webhook", "listen address for the Xray webhook receiver, separate from -addr since this is hit on every new connection: host:port, a filesystem Unix socket path, or a Linux abstract socket (@name, or @@name padded for HAProxy compatibility) — abstract is the default and fastest, and needs no bind mount across a --network host container boundary")
	flag.StringVar(&cfg.iface, "iface", "", "network interface for tc/HTB shaping (default: the interface used by the default route)")
	flag.Var(&cfg.marks, "mark-range", "inclusive range of marks handed out to users, as first-last; must lie within 2-65535 (the HTB classid limit, and 1:1 is the default class)")
	flag.Uint64Var(&cfg.defaultClassRateMbit, "default-class-rate-mbit", 0, "rate (Mbit/s) for the tc/HTB default class, which catches all traffic with no per-user mark (system traffic, and every user's own outbound-to-destination leg); 0 = auto-detect via ethtool on -iface")
	flag.Uint64Var(&cfg.htbBurstMs, "htb-burst-ms", 100, "burst/cburst allowance for every tc/HTB class (default and per-user), in milliseconds' worth of bytes at that class's own rate; 0 = kernel's own default sizing (normally just a couple KB)")
	flag.Uint64Var(&cfg.perUserRateMbit, "per-user-rate-mbit", 0, "if set, automatically provisions this rate (Mbit/s) for every newly allocated mark, applying it uniformly to every user with zero manual provisioning; 0 = don't auto-provision, manage rates by hand via PUT /marks/{mark}")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := run(cfg, log); err != nil {
		log.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(cfg config, log *slog.Logger) error {
	iface := cfg.iface
	if iface == "" {
		var err error
		iface, err = netif.DefaultRouteInterface()
		if err != nil {
			return fmt.Errorf("determining default route interface for tc shaping: %w", err)
		}
	}

	shaper, err := setupShaper(iface, cfg.defaultClassRateMbit, cfg.htbBurstMs, log)
	if err != nil {
		return err
	}
	store := tcshape.WrapStore(limiter.NewMemoryStore(), shaper, log)

	// A nil RateSetter tells the webhook handler not to provision rates.
	var perUserRate webhook.RateSetter
	var perUserRateBytesPerSec uint32
	if cfg.perUserRateMbit > 0 {
		// Check before multiplying: a huge value would wrap around uint64
		// and slip under the limit as a tiny rate.
		const bytesPerSecPerMbit = 1_000_000 / 8
		if cfg.perUserRateMbit > math.MaxUint32/bytesPerSecPerMbit {
			return fmt.Errorf("per-user-rate-mbit %d is too large: it must convert to at most 4294967295 bytes/sec (uint32 limit of the mark -> rate store), i.e. at most %d", cfg.perUserRateMbit, math.MaxUint32/bytesPerSecPerMbit)
		}
		perUserRate = store
		perUserRateBytesPerSec = uint32(cfg.perUserRateMbit * bytesPerSecPerMbit)
		log.Info("auto-provisioning per-user tc/HTB rate on allocation", "mbit", cfg.perUserRateMbit, "bytes_per_sec", perUserRateBytesPerSec)
	}

	alloc := webhook.NewAllocator(cfg.marks.first, cfg.marks.count(), log)

	apiSrv := &http.Server{Handler: api.New(store, alloc, log), ReadHeaderTimeout: readHeaderTimeout}

	webhookMux := http.NewServeMux()
	webhookMux.Handle("/webhook/xray", webhook.New(alloc, conntrack.NewMarker(log), perUserRate, perUserRateBytesPerSec, log))
	webhookSrv := &http.Server{Handler: webhookMux, ReadHeaderTimeout: readHeaderTimeout}

	log.Info("shaping enabled", "iface", iface, "mark_range", cfg.marks.String())

	errCh := make(chan error, 2)
	if err := serve(apiSrv, cfg.addr, "http api", errCh, log); err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.addr, err)
	}
	if err := serve(webhookSrv, cfg.webhookAddr, "webhook receiver", errCh, log); err != nil {
		return fmt.Errorf("listening for webhook on %s: %w", cfg.webhookAddr, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shut both servers down concurrently, not one after the other: they
	// share this one deadline, and sequential Shutdown calls would let the
	// first one eat into the second's budget rather than each getting the
	// full 5 seconds to drain.
	apiErrCh := make(chan error, 1)
	go func() { apiErrCh <- apiSrv.Shutdown(shutdownCtx) }()
	webhookErr := webhookSrv.Shutdown(shutdownCtx)
	if err := <-apiErrCh; err != nil {
		return err
	}
	return webhookErr
}

// setupShaper makes sure iface has the root HTB qdisc, its default class
// and the conntrack mark restore rule, and returns a Shaper for it.
func setupShaper(iface string, defaultClassRateMbit, htbBurstMs uint64, log *slog.Logger) (*tcshape.Shaper, error) {
	rootExists, err := tcshape.RootQdiscExists(iface)
	if err != nil {
		return nil, fmt.Errorf("checking existing tc/HTB state on %s: %w", iface, err)
	}

	// The default class rate only matters when the root qdisc is created
	// here; an existing one keeps whatever rate its default class already has.
	if !rootExists && defaultClassRateMbit == 0 {
		defaultClassRateMbit, err = netif.DetectLinkSpeedMbps(iface)
		if err != nil {
			return nil, fmt.Errorf("auto-detecting link speed on %s (pass -default-class-rate-mbit explicitly if this interface doesn't support ethtool speed reporting): %w", iface, err)
		}
		log.Info("auto-detected link speed for tc default class", "iface", iface, "mbit", defaultClassRateMbit)
	}

	shaper := tcshape.New(iface, defaultClassRateMbit, htbBurstMs)
	if err := shaper.EnsureRoot(rootExists); err != nil {
		return nil, fmt.Errorf("setting up tc/HTB on %s: %w", iface, err)
	}
	return shaper, nil
}

// markRange is an inclusive range of marks, set from a "first-last" flag
// value such as "20000-39999".
type markRange struct {
	first, last uint32
}

func (r *markRange) String() string {
	return fmt.Sprintf("%d-%d", r.first, r.last)
}

// Set parses and validates a "first-last" range. Every mark must fit in
// 16 bits because it doubles as an HTB classid minor number (see
// tcshape.classIDFor), mark 0 means "no mark" to the kernel, and mark 1
// would encode to the default class 1:1.
func (r *markRange) Set(s string) error {
	firstStr, lastStr, ok := strings.Cut(s, "-")
	if !ok {
		return errors.New(`must look like "first-last", e.g. 20000-39999`)
	}
	first, err := strconv.ParseUint(firstStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid first mark %q", firstStr)
	}
	last, err := strconv.ParseUint(lastStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid last mark %q", lastStr)
	}

	switch {
	case first == 0:
		return errors.New("mark 0 means \"no mark\" and can't be handed out")
	case first < tcshape.MinMark:
		return fmt.Errorf("mark %d would be the tc/HTB default class 1:1; start the range at %d or above", first, tcshape.MinMark)
	case last > tcshape.MaxMark:
		return fmt.Errorf("marks must not exceed %d (HTB classids are 16-bit)", tcshape.MaxMark)
	case first > last:
		return fmt.Errorf("first mark %d is greater than last mark %d", first, last)
	}

	r.first, r.last = uint32(first), uint32(last)
	return nil
}

// count returns how many marks the range holds.
func (r *markRange) count() uint32 {
	return r.last - r.first + 1
}

// serve starts listening on addr and runs srv on it in the background,
// logging name/addr and reporting any non-graceful-shutdown error on errCh.
func serve(srv *http.Server, addr, name string, errCh chan<- error, log *slog.Logger) error {
	listener, err := listen(addr)
	if err != nil {
		return err
	}
	go func() {
		log.Info(name+" listening", "addr", addr)
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	return nil
}

// listen creates a net.Listener for addr, which may be a "host:port" TCP
// address or a Unix socket: a filesystem path, a Linux abstract socket
// (leading '@', lock-free, no filesystem entry), or a padded abstract
// socket (leading "@@", for HAProxy compatibility) — the same three forms
// Xray-core itself accepts for its webhook URL
// (common/utils/unixsocket.go), so the identical address string works on
// both sides.
func listen(addr string) (net.Listener, error) {
	if addr == "" {
		return nil, fmt.Errorf("listen address must not be empty")
	}
	if addr[0] != '/' && addr[0] != '@' {
		return net.Listen("tcp", addr)
	}

	path := resolveUnixSocketPath(addr)
	if addr[0] == '/' {
		// A stale socket file from an unclean shutdown makes net.Listen fail
		// with "address already in use"; only remove it if it's actually a
		// socket, so an operator's typo pointing -addr at a real file doesn't
		// delete it. Abstract sockets have no filesystem entry and need no
		// such cleanup — one reason to prefer them.
		if fi, statErr := os.Lstat(path); statErr == nil && fi.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(path)
		}
	}
	return net.Listen("unix", path)
}

// resolveUnixSocketPath mirrors Xray-core's own ResolveSocketPath
// (common/utils/unixsocket.go): "@name" is used as-is (a lock-free Linux
// abstract socket), "@@name" is null-padded to the kernel's full
// sockaddr_un length first (HAProxy compatibility). Plain paths pass
// through unchanged.
func resolveUnixSocketPath(path string) string {
	if len(path) < 2 || path[0] != '@' || path[1] != '@' {
		return path
	}
	full := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
	copy(full, path[1:])
	return string(full)
}
