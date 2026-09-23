package bpfprog

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
)

// Attachment holds the loaded BPF objects and the cgroup link they are
// attached through.
type Attachment struct {
	objs bpfObjects
	link link.Link
}

// Load loads the sock_ops program and its map, and attaches the program to
// the given cgroup v2 path.
func Load(cgroupPath string) (*Attachment, error) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.LimitByMark,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching sock_ops program to cgroup %s: %w", cgroupPath, err)
	}

	return &Attachment{objs: objs, link: l}, nil
}

// Store returns a limiter.Store backed by the rate_limits BPF map.
func (a *Attachment) Store() limiter.Store {
	return &mapStore{m: a.objs.RateLimits}
}

// Close detaches the program and releases the BPF objects.
func (a *Attachment) Close() error {
	return errors.Join(a.link.Close(), a.objs.Close())
}

type mapStore struct {
	m *ebpf.Map
}

func (s *mapStore) Set(mark uint32, rate uint32) error {
	return s.m.Put(mark, rate)
}

func (s *mapStore) Delete(mark uint32) error {
	err := s.m.Delete(mark)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (s *mapStore) List() ([]limiter.Entry, error) {
	var (
		entries []limiter.Entry
		key     uint32
		val     uint32
	)
	it := s.m.Iterate()
	for it.Next(&key, &val) {
		entries = append(entries, limiter.Entry{Mark: key, RateBytesPerSec: val})
	}
	return entries, it.Err()
}
