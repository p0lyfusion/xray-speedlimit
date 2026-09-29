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
	"syscall"
	"time"

	"github.com/p0lyfusion/xray-speedlimit/internal/api"
	"github.com/p0lyfusion/xray-speedlimit/internal/conntrack"
	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
	"github.com/p0lyfusion/xray-speedlimit/internal/mark"
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
	txQueues             int
	markRange            string
	defaultClassRateMbit uint64
	htbBurstMs           uint64
	perUserRateMbit      uint64
	classIdleTimeout     time.Duration
}

func main() {
	var cfg config

	flag.StringVar(&cfg.addr, "addr", ":7070", "HTTP API listen address")
	flag.StringVar(&cfg.webhookAddr, "webhook-addr", "@xray-speedlimit-webhook", "listen address for the Xray webhook receiver, separate from -addr since this is hit on every new connection: host:port, a filesystem Unix socket path, or a Linux abstract socket (@name, or @@name padded for HAProxy compatibility) — abstract is the default and fastest, and needs no bind mount across a --network host container boundary")
	flag.StringVar(&cfg.iface, "iface", "", "network interface for tc/HTB shaping (default: the interface used by the default route)")
	flag.IntVar(&cfg.txQueues, "tx-queues", 0, "number of TX queues to spread users over, one HTB qdisc each (at most 255); 0 = every TX queue -iface has in use. Every user's mark depends on it")
	flag.StringVar(&cfg.markRange, "mark-range", "", "no longer used: marks are computed from the email (see -tx-queues); accepted and ignored so older configs keep working")
	flag.Uint64Var(&cfg.defaultClassRateMbit, "default-class-rate-mbit", 0, "rate (Mbit/s) for the tc/HTB default class, which catches all traffic with no per-user mark (system traffic, and every user's own outbound-to-destination leg); 0 = auto-detect via ethtool on -iface")
	flag.Uint64Var(&cfg.htbBurstMs, "htb-burst-ms", 100, "burst/cburst allowance for every tc/HTB class (default and per-user), in milliseconds' worth of bytes at that class's own rate; 0 = kernel's own default sizing (normally just a couple KB)")
	flag.Uint64Var(&cfg.perUserRateMbit, "per-user-rate-mbit", 0, "if set, automatically provisions this rate (Mbit/s) for every user's mark the first time it is seen, applying it uniformly to every user with zero manual provisioning; 0 = don't auto-provision, manage rates by hand via PUT /marks/{mark}")
	flag.DurationVar(&cfg.classIdleTimeout, "class-idle-timeout", 6*time.Hour, "delete a user's tc/HTB class after it has sent nothing for this long (the user gets a new one on their next connection), and drop emails idle that long from GET /users; 0 = never delete classes, and GET /users keeps every email seen")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := run(cfg, log); err != nil {
		log.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(cfg config, log *slog.Logger) error {
	if cfg.markRange != "" {
		log.Warn("-mark-range is no longer used and is ignored: marks are computed from the email", "mark_range", cfg.markRange)
	}

	iface := cfg.iface
	if iface == "" {
		var err error
		iface, err = netif.DefaultRouteInterface()
		if err != nil {
			return fmt.Errorf("determining default route interface for tc shaping: %w", err)
		}
	}

	queues := cfg.txQueues
	if queues == 0 {
		n, err := netif.TxQueueCount(iface)
		if err != nil {
			return fmt.Errorf("counting TX queues on %s (pass -tx-queues explicitly): %w", iface, err)
		}
		queues = n
	}
	if queues < 1 {
		return fmt.Errorf("-tx-queues must be at least 1, got %d", queues)
	}
	if queues > mark.MaxQueues {
		log.Warn("more TX queues than a mark can address; using only the first ones", "tx_queues", queues, "used", mark.MaxQueues)
		queues = mark.MaxQueues
	}

	shaper, err := setupShaper(iface, queues, cfg.defaultClassRateMbit, cfg.htbBurstMs, log)
	if err != nil {
		return err
	}

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
		perUserRateBytesPerSec = uint32(cfg.perUserRateMbit * bytesPerSecPerMbit)
		log.Info("auto-provisioning per-user tc/HTB rate for every user seen", "mbit", cfg.perUserRateMbit, "bytes_per_sec", perUserRateBytesPerSec)
	}

	// Classes outlive the process, and a user's mark is the same after a
	// restart, so the classes already on the interface are adopted into
	// the store: GET /marks lists them, and the webhook handler doesn't
	// provision them again. With -per-user-rate-mbit, a class with another
	// rate (the flag changed) is left out, so it is provisioned again on
	// its user's next webhook.
	classes, err := shaper.Classes()
	if err != nil {
		return fmt.Errorf("listing existing tc/HTB classes on %s: %w", iface, err)
	}
	base := limiter.NewMemoryStore()
	for _, c := range classes {
		if cfg.perUserRateMbit == 0 || c.RateBytesPerSec == perUserRateBytesPerSec {
			if err := base.Set(c.Mark, c.RateBytesPerSec); err != nil {
				return err
			}
		}
	}
	store := tcshape.WrapStore(base, shaper, log)
	if cfg.perUserRateMbit > 0 {
		perUserRate = store
	}

	users := webhook.NewUsers(queues)
	handler := webhook.New(users, conntrack.NewMarker(log), perUserRate, perUserRateBytesPerSec, log)

	apiSrv := &http.Server{Handler: api.New(store, users, log), ReadHeaderTimeout: readHeaderTimeout}

	webhookMux := http.NewServeMux()
	webhookMux.Handle("/webhook/xray", handler)
	webhookSrv := &http.Server{Handler: webhookMux, ReadHeaderTimeout: readHeaderTimeout}

	log.Info("shaping enabled", "iface", iface, "tx_queues", queues, "existing_classes", len(classes))

	if cfg.classIdleTimeout > 0 {
		gc := tcshape.NewIdleCollector(shaper, store, cfg.classIdleTimeout, log)
		go func() {
			ticker := time.NewTicker(gcInterval(cfg.classIdleTimeout))
			defer ticker.Stop()
			for range ticker.C {
				gc.Collect()
				users.Prune(cfg.classIdleTimeout)
			}
		}()
	}

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

// setupShaper makes sure iface has the per-queue HTB layout, the
// steering filters and the conntrack mark restore rule, and returns a
// Shaper for it.
func setupShaper(iface string, queues int, defaultClassRateMbit, htbBurstMs uint64, log *slog.Logger) (*tcshape.Shaper, error) {
	shaper := tcshape.New(iface, queues, htbBurstMs)
	layoutExists, err := shaper.LayoutExists()
	if err != nil {
		return nil, fmt.Errorf("checking existing tc/HTB state on %s: %w", iface, err)
	}

	// The default class rate only matters when the layout is built here;
	// an existing one keeps whatever rate its default classes already have.
	if !layoutExists {
		if defaultClassRateMbit == 0 {
			defaultClassRateMbit, err = netif.DetectLinkSpeedMbps(iface)
			if err != nil {
				return nil, fmt.Errorf("auto-detecting link speed on %s (pass -default-class-rate-mbit explicitly if this interface doesn't support ethtool speed reporting): %w", iface, err)
			}
			log.Info("auto-detected link speed for tc default classes", "iface", iface, "mbit", defaultClassRateMbit)
		}
		log.Warn("building the per-queue tc/HTB layout; this replaces the root qdisc and every class under it", "iface", iface, "tx_queues", queues)
	}

	if err := shaper.EnsureRoot(layoutExists, defaultClassRateMbit); err != nil {
		return nil, fmt.Errorf("setting up tc/HTB on %s: %w", iface, err)
	}
	return shaper, nil
}

// gcInterval is how often idle classes are looked for: often enough that
// a class goes soon after its idle timeout, at most every 10 minutes.
func gcInterval(idle time.Duration) time.Duration {
	return max(min(idle/4, 10*time.Minute), time.Minute)
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
