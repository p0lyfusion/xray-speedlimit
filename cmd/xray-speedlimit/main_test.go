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
	l, err := listen("@xray-speedlimit-test")
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

func TestMarkRangeSet(t *testing.T) {
	var r markRange
	if err := r.Set("20000-39999"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if r.first != 20000 || r.last != 39999 || r.count() != 20000 {
		t.Fatalf("got first=%d last=%d count=%d", r.first, r.last, r.count())
	}
	if r.String() != "20000-39999" {
		t.Fatalf("String() = %q", r.String())
	}

	if err := r.Set("7-7"); err != nil || r.count() != 1 {
		t.Fatalf("single-mark range: err=%v count=%d", err, r.count())
	}
	if err := r.Set("1-65535"); err != nil {
		t.Fatalf("full 16-bit range should be accepted: %v", err)
	}
}

func TestMarkRangeSetRejectsInvalid(t *testing.T) {
	cases := []string{
		"",
		"20000",
		"a-b",
		"-5",
		"5-",
		"0-10",        // mark 0 means "no mark"
		"1-65536",     // past the 16-bit HTB classid limit
		"70000-80000", // entirely past it
		"10-5",        // reversed
		"-1-5",
	}
	for _, in := range cases {
		var r markRange
		if err := r.Set(in); err == nil {
			t.Errorf("Set(%q): expected error, got first=%d last=%d", in, r.first, r.last)
		}
	}
}
