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

	"github.com/cilium/ebpf/rlimit"

	"github.com/p0lyfusion/xray-speedlimit/internal/api"
	"github.com/p0lyfusion/xray-speedlimit/internal/bpfprog"
	"github.com/p0lyfusion/xray-speedlimit/internal/cgroup"
	"github.com/p0lyfusion/xray-speedlimit/internal/conntrack"
	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
	"github.com/p0lyfusion/xray-speedlimit/internal/qdisc"
	"github.com/p0lyfusion/xray-speedlimit/internal/tcshape"
	"github.com/p0lyfusion/xray-speedlimit/internal/webhook"
)

func main() {
	addr := flag.String("addr", ":7070", "HTTP API listen address")
	cgroupPath := flag.String("cgroup-path", cgroup.DefaultPath, "cgroup v2 mount point to attach the sock_ops program to")
	iface := flag.String("iface", "", "network interface for tc/HTB shaping (default: the interface used by the default route)")
	enableSockOps := flag.Bool("enable-sock-ops", true, "enable the sock_ops/SO_MAX_PACING_RATE backend (needs cgroup v2 and CAP_BPF/CAP_SYS_ADMIN)")
	enableTC := flag.Bool("enable-tc-shaping", false, "enable the webhook -> conntrack mark -> tc/HTB shaping backend; works standalone with -enable-sock-ops=false")
	webhookMarkBase := flag.Uint("webhook-mark-base", 20000, "first mark issued by the webhook email->mark allocator; keep disjoint from any SO_MARK range used elsewhere")
	webhookMarkCount := flag.Uint("webhook-mark-count", 20000, "size of the webhook mark pool")
	defaultClassRateMbit := flag.Uint64("default-class-rate-mbit", 0, "rate (Mbit/s) for the tc/HTB default class, which catches all traffic with no per-user mark (system traffic, and every user's own outbound-to-destination leg); 0 = auto-detect via ethtool on -iface")
	htbBurstMs := flag.Uint64("htb-burst-ms", 100, "burst/cburst allowance for every tc/HTB class (default and per-user), in milliseconds' worth of bytes at that class's own rate; 0 = kernel's own default sizing (normally just a couple KB)")
	perUserRateMbit := flag.Uint64("per-user-rate-mbit", 0, "if set, automatically provisions this rate (Mbit/s) for every newly allocated webhook mark, applying it uniformly to every user with zero manual provisioning; 0 = don't auto-provision, manage rates by hand via PUT /marks/{mark}")
	webhookAddr := flag.String("webhook-addr", "@ebpf-speedlimit-webhook", "listen address for the Xray webhook receiver (only used with -enable-tc-shaping), separate from -addr since this is hit on every new connection: host:port, a filesystem Unix socket path, or a Linux abstract socket (@name, or @@name padded for HAProxy compatibility) — abstract is the default and fastest, and needs no bind mount across a --network host container boundary")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := run(*addr, *cgroupPath, *iface, *enableSockOps, *enableTC, uint32(*webhookMarkBase), uint32(*webhookMarkCount), *defaultClassRateMbit, *htbBurstMs, *perUserRateMbit, *webhookAddr, log); err != nil {
		log.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(addr, cgroupPath, iface string, enableSockOps, enableTC bool, webhookMarkBase, webhookMarkCount uint32, defaultClassRateMbit, htbBurstMs, perUserRateMbit uint64, webhookAddr string, log *slog.Logger) error {
	if !enableSockOps && !enableTC {
		log.Warn("both backends disabled, the mark->rate API will be a no-op store")
	}

	var store limiter.Store = limiter.NewMemoryStore()

	if enableSockOps {
		if err := cgroup.VerifyUnified(cgroupPath); err != nil {
			return err
		}
		if err := rlimit.RemoveMemlock(); err != nil {
			return err
		}
		attachment, err := bpfprog.Load(cgroupPath)
		if err != nil {
			return err
		}
		defer attachment.Close()

		log.Info("sock_ops program attached", "cgroup_path", cgroupPath)
		qdisc.WarnIfMissing(log)
		store = attachment.Store()
	}

	mux := http.NewServeMux()
	var webhookSrv *http.Server

	if enableTC {
		var err error
		if iface == "" {
			iface, err = qdisc.DefaultRouteInterface()
			if err != nil {
				return fmt.Errorf("determining default route interface for tc shaping: %w", err)
			}
		}

		rootExists, err := tcshape.RootQdiscExists(iface)
		if err != nil {
			return fmt.Errorf("checking existing tc/HTB state on %s: %w", iface, err)
		}
		if !rootExists && defaultClassRateMbit == 0 {
			defaultClassRateMbit, err = qdisc.DetectLinkSpeedMbps(iface)
			if err != nil {
				return fmt.Errorf("auto-detecting link speed on %s (pass -default-class-rate-mbit explicitly if this interface doesn't support ethtool speed reporting): %w", iface, err)
			}
			log.Info("auto-detected link speed for tc default class", "iface", iface, "mbit", defaultClassRateMbit)
		}

		shaper := tcshape.New(iface, defaultClassRateMbit, htbBurstMs)
		if err := shaper.EnsureRoot(rootExists); err != nil {
			return fmt.Errorf("setting up tc/HTB on %s: %w", iface, err)
		}
		store = tcshape.WrapStore(store, shaper, log)

		var perUserRate webhook.RateSetter
		var perUserRateBytesPerSec uint32
		if perUserRateMbit > 0 {
			bps := perUserRateMbit * 1_000_000 / 8
			if bps > math.MaxUint32 {
				return fmt.Errorf("per-user-rate-mbit %d converts to %d bytes/sec, which must be between 1 and 4294967295 (uint32 limit of the tc/HTB rate)", perUserRateMbit, bps)
			}
			perUserRate = store
			perUserRateBytesPerSec = uint32(bps)
			log.Info("auto-provisioning per-user tc/HTB rate on allocation", "mbit", perUserRateMbit, "bytes_per_sec", perUserRateBytesPerSec)
		}

		alloc := webhook.NewAllocator(webhookMarkBase, webhookMarkCount, log)
		webhookMux := http.NewServeMux()
		webhookMux.Handle("/webhook/xray", webhook.New(alloc, conntrack.NewMarker(log), perUserRate, perUserRateBytesPerSec, log))
		webhookSrv = &http.Server{Handler: webhookMux}

		log.Info("webhook/conntrack/tc shaping backend enabled", "iface", iface, "webhook_addr", webhookAddr, "mark_base", webhookMarkBase, "mark_count", webhookMarkCount)
	}

	mux.Handle("/", api.New(store, log))
	srv := &http.Server{Handler: mux}

	errCh := make(chan error, 2)
	if err := serve(srv, addr, "http api", errCh, log); err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	if webhookSrv != nil {
		if err := serve(webhookSrv, webhookAddr, "webhook receiver", errCh, log); err != nil {
			return fmt.Errorf("listening for webhook on %s: %w", webhookAddr, err)
		}
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
	srvErrCh := make(chan error, 1)
	go func() { srvErrCh <- srv.Shutdown(shutdownCtx) }()
	var webhookShutdownErr error
	if webhookSrv != nil {
		webhookShutdownErr = webhookSrv.Shutdown(shutdownCtx)
	}
	if err := <-srvErrCh; err != nil {
		return err
	}
	return webhookShutdownErr
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
