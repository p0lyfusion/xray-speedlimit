// Package bpfprog loads and attaches the sock_ops program that reads a
// TCP socket's SO_MARK and applies SO_MAX_PACING_RATE from a BPF map.
package bpfprog

//go:generate go tool bpf2go -tags linux bpf sockops.c
