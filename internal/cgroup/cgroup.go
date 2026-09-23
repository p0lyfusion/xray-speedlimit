// Package cgroup detects whether the host runs cgroup v2 in unified mode,
// which BPF_PROG_TYPE_SOCK_OPS attachment requires.
package cgroup

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// DefaultPath is the standard cgroup v2 mount point.
const DefaultPath = "/sys/fs/cgroup"

// VerifyUnified returns an error if path is not a cgroup v2 (unified
// hierarchy) mount. On cgroup v1 or hybrid setups, path is typically a
// tmpfs, not a cgroup2 filesystem.
func VerifyUnified(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	if int64(st.Type) != int64(unix.CGROUP2_SUPER_MAGIC) {
		return fmt.Errorf("%s is not a cgroup2 mount (fs type 0x%x); sock_ops attachment requires cgroup v2 in unified mode, this host looks like cgroup v1 or hybrid", path, st.Type)
	}
	return nil
}
