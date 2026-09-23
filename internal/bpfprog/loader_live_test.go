package bpfprog_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/p0lyfusion/xray-speedlimit/internal/bpfprog"
	"github.com/p0lyfusion/xray-speedlimit/internal/cgroup"
)

// TestLiveApplyPacingRate loads the real sock_ops program into the kernel,
// attaches it to a throwaway cgroup, marks an outgoing TCP connection and
// checks that SO_MAX_PACING_RATE ends up set on the socket. It needs a
// privileged container on a cgroup v2 host with BTF, matching this repo's
// CI live-kernel job; anywhere else it skips with the reason.
func TestLiveApplyPacingRate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_BPF/CAP_NET_ADMIN (privileged container)")
	}
	if err := cgroup.VerifyUnified(cgroup.DefaultPath); err != nil {
		t.Skipf("skipping: %v", err)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("skipping: no kernel BTF available: %v", err)
	}

	subCgroup := filepath.Join(cgroup.DefaultPath, fmt.Sprintf("ebpf-speedlimit-test-%d", os.Getpid()))
	if err := os.Mkdir(subCgroup, 0o755); err != nil {
		t.Skipf("skipping: cannot create test cgroup %s: %v", subCgroup, err)
	}
	defer func() {
		_ = movePID(cgroup.DefaultPath, os.Getpid())
		_ = os.Remove(subCgroup)
	}()

	if err := movePID(subCgroup, os.Getpid()); err != nil {
		t.Skipf("skipping: cannot move test process into %s: %v", subCgroup, err)
	}

	attachment, err := bpfprog.Load(subCgroup)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("skipping: insufficient privileges to load/attach BPF (need CAP_BPF/CAP_SYS_ADMIN/CAP_NET_ADMIN): %v", err)
		}
		t.Fatalf("loading and attaching sock_ops program: %v", err)
	}
	defer attachment.Close()

	const (
		mark = uint32(4242)
		rate = uint32(1_000_000) // 1 MB/s
	)
	if err := attachment.Store().Set(mark, rate); err != nil {
		t.Fatalf("setting rate for mark: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}()

	dialer := net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}); err != nil {
				return err
			}
			return sockErr
		},
	}

	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var (
		got    int
		getErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		got, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MAX_PACING_RATE)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if getErr != nil {
		t.Fatalf("getsockopt(SO_MAX_PACING_RATE): %v", getErr)
	}

	if uint32(got) != rate {
		t.Fatalf("SO_MAX_PACING_RATE = %d, want %d", got, rate)
	}
}

func movePID(cgroupPath string, pid int) error {
	f, err := os.OpenFile(filepath.Join(cgroupPath, "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strconv.Itoa(pid))
	return err
}
