package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestResolveUnixSocketPath(t *testing.T) {
	if got := resolveUnixSocketPath("/run/webhook.sock"); got != "/run/webhook.sock" {
		t.Fatalf("filesystem path should pass through unchanged, got %q", got)
	}
	if got := resolveUnixSocketPath("@webhook"); got != "@webhook" {
		t.Fatalf("single-@ abstract socket should pass through unchanged, got %q", got)
	}

	got := resolveUnixSocketPath("@@webhook")
	wantLen := len(syscall.RawSockaddrUnix{}.Path)
	if len(got) != wantLen {
		t.Fatalf("padded abstract socket length = %d, want %d", len(got), wantLen)
	}
	if got[:len("@webhook")] != "@webhook" {
		t.Fatalf("padded abstract socket should start with a single @ plus the name, got %q", got[:len("@webhook")])
	}
	for i := len("@webhook"); i < len(got); i++ {
		if got[i] != 0 {
			t.Fatalf("padded abstract socket should be zero-padded past the name, byte %d = %d", i, got[i])
		}
	}
}

func TestListenTCP(t *testing.T) {
	l, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	if _, ok := l.Addr().(*net.TCPAddr); !ok {
		t.Fatalf("expected a TCP listener, got %T", l.Addr())
	}
}

func TestListenAbstractUnixSocket(t *testing.T) {
	l, err := listen("@ebpf-speedlimit-test")
	if err != nil {
		t.Skipf("abstract unix sockets unavailable in this environment: %v", err)
	}
	defer l.Close()
	if _, ok := l.Addr().(*net.UnixAddr); !ok {
		t.Fatalf("expected a Unix listener, got %T", l.Addr())
	}
}

func TestListenFilesystemUnixSocketCleansUpStaleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webhook.sock")

	l1, err := listen(path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	// Simulate an unclean shutdown (kill -9, crash): the socket file survives
	// close, unlike Go's own default of unlinking it on a graceful Close().
	if ul, ok := l1.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = l1.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected stale socket file to exist before second listen: %v", err)
	}

	l2, err := listen(path)
	if err != nil {
		t.Fatalf("second listen should clean up the stale socket file, got: %v", err)
	}
	defer l2.Close()
}

func TestListenRefusesToDeleteNonSocketFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(path, []byte("important data"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if _, err := listen(path); err == nil {
		t.Fatal("expected listen to fail rather than clobber a non-socket file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("non-socket file should survive a failed listen attempt: %v", err)
	}
}
