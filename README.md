# ebpf-speedlimit

Per-flow bandwidth limiting on Linux, keyed by a firewall mark (`SO_MARK`), enforced entirely in the kernel via an eBPF `sock_ops` program and `SO_MAX_PACING_RATE`.

You mark a TCP socket however you like — `iptables`, `nftables`, a `setsockopt(SO_MARK, ...)` call from the application that owns the socket, whatever fits your setup — and this service picks up new connections carrying that mark and applies a byte-per-second cap to them by setting `SO_MAX_PACING_RATE` on the socket. Nothing else about the connection changes.

## Why this approach

The obvious alternative is a userspace proxy that reads from one socket and writes to another at a throttled pace. That works, but it forces every byte through a userspace copy, which kills `splice()`/zero-copy paths in the kernel TCP stack and burns CPU proportional to throughput.

`SO_MAX_PACING_RATE` avoids that entirely. It's a hint the kernel's own TCP stack and the `fq` (fair queue) qdisc use to pace outgoing packets — the data path (splice, sendfile, zero-copy, whatever the application already does) is untouched. Rate limiting becomes a scheduling decision made in the network stack, not a proxy in front of it. This is the same mechanism Cilium's Bandwidth Manager is built on for pod-level egress shaping.

## How it works

1. An eBPF program of type `BPF_PROG_TYPE_SOCK_OPS` is attached to the root cgroup v2 hierarchy (`cgroup/sock_ops`).
2. It runs on `BPF_SOCK_OPS_TCP_CONNECT_CB`, `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`, and `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` — i.e. whenever a TCP socket (outbound or inbound) is set up for a cgroup the program covers.
3. It reads the socket's mark with `bpf_getsockopt(SOL_SOCKET, SO_MARK, ...)`.
4. If the mark is non-zero, it looks the mark up in a `BPF_MAP_TYPE_HASH` map (`mark -> rate in bytes/sec`).
5. If there's a hit, it calls `bpf_setsockopt(SOL_SOCKET, SO_MAX_PACING_RATE, ...)` on the socket with that rate.
6. If the mark is zero, or there's no entry for it, the program does nothing — unmarked traffic is never touched.

A small HTTP API lets you manage that map at runtime.

Two things worth knowing going in:

- **The rate is applied once, at connection setup.** Changing or deleting a mark's rate through the API affects new connections; it does not retroactively adjust sockets that are already established. This mirrors how the underlying `sock_ops` hooks work — they fire on connect/accept, not continuously.
- **The kernel caps the rate to 32 bits.** `bpf_setsockopt(SOL_SOCKET, SO_MAX_PACING_RATE, ...)` only accepts a 4-byte value (verified against `net/core/filter.c` in the kernel source: `sol_socket_sockopt()` rejects any other `optlen` for this option). That's a ceiling of 4294967295 bytes/sec, roughly 34.3 Gbit/s — plenty for per-flow shaping, but the API will reject anything above it rather than silently truncating it.

### Requirements

- **cgroup v2, unified mode.** The program attaches to `/sys/fs/cgroup` (configurable) and refuses to start if that path isn't a cgroup2 mount — cgroup v1 and hybrid setups aren't supported by `sock_ops` attachment. The check is a `statfs()` against `CGROUP2_SUPER_MAGIC`.
- **The `fq` qdisc on your egress interface.** `SO_MAX_PACING_RATE` is only honored by `fq`; other qdiscs ignore it (the socket won't error, it just won't be paced). On startup the service makes a best-effort check — it looks at the interface used by your default route and runs `tc qdisc show` against it, logging a warning if `fq` isn't found or can't be determined. It never blocks startup on this, because the check itself can fail for reasons that have nothing to do with whether pacing actually works (missing `tc`, unusual routing, containers without `NET_ADMIN` on that particular check, etc).
- **A reasonably modern kernel with BTF** for reliable eBPF loading and verification. Nothing here is exotic — no CO-RE relocations against internal kernel structs are used, since the `sock_ops` context struct is stable UAPI — but BTF is what the CI's live integration test requires to run instead of skip.

## Running it

```
docker pull ebpf-speedlimit:latest

docker run -d \
  --name ebpf-speedlimit \
  --cap-add=BPF --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -p 7070:7070 \
  ebpf-speedlimit:latest
```

`SYS_ADMIN` is what actually lets the kernel attach a `sock_ops` program to a cgroup on most kernel versions; `BPF` and `NET_ADMIN` narrow that down where the kernel supports the finer-grained capabilities. If your setup is stricter about capabilities than this, `--privileged` is the fallback that's guaranteed to work while you figure out the minimal set for your kernel.

The container needs to see the host's real cgroup v2 hierarchy, hence the bind mount — sockets are grouped by whichever cgroup the process that owns them belongs to on the host, and the program has to be attached to that same hierarchy.

Flags:

```
-addr string
      HTTP API listen address (default ":7070")
-cgroup-path string
      cgroup v2 mount point to attach the sock_ops program to (default "/sys/fs/cgroup")
```

## Alternative backend: webhook + conntrack + tc/HTB

`SO_MAX_PACING_RATE` above needs a patched Xray-core (`SO_MARK` per user) and only limits egress from this host, i.e. downlink to the client. `-enable-tc-shaping` turns on a second, independent backend that needs no Xray-core patch at all:

1. Xray-core's stock `app/router` `webhook` rule action POSTs an event to `/webhook/xray` for every routed connection (see upstream `routing.rules[].webhook`, `deduplication` must be `0`).
2. This service allocates a stable mark per `email` and, using `github.com/vishvananda/netlink`'s `ConntrackUpdate`, sets that mark on the client's conntrack entry (identified by the webhook's `source`/`inboundLocal` 4-tuple).
3. An nftables rule (`meta mark set ct mark`, table `ebpf_speedlimit`) restores the conntrack mark onto the packet mark on the way out.
4. A root HTB qdisc on `-iface` gets one class + `fw` filter per mark; `PUT`/`DELETE /marks/{mark}` create/update/remove them alongside the existing rate-limit map entry — or, with `-per-user-rate-mbit`, this happens automatically (see below).

This only shapes egress from the process running this service, same directional limitation as the sock_ops backend — an ingress (uplink) path via `ifb` + the tc `connmark` action is sketched in `internal/tcshape` but not implemented, since `act_connmark` isn't available on every kernel; see the report for details.

Marks are a 16-bit HTB classid field, so `-webhook-mark-base`/`-webhook-mark-count` must stay under 65536 and disjoint from any `SO_MARK` range used by the sock_ops backend, since both ultimately set the same kernel `skb->mark`.

The two backends are independent: pass `-enable-sock-ops=false -enable-tc-shaping` to run only the webhook/conntrack/tc path, with none of the sock_ops backend's cgroup v2 or `CAP_BPF`/`CAP_SYS_ADMIN` requirements. With `-enable-sock-ops=false -enable-tc-shaping=false` (or just forgetting the flags) the service still starts and serves the `/marks` API against a plain in-memory store, but nothing enforces the limits — there's no backend attached.

**Running this backend in Docker needs `--network host`, not the default bridge network shown above.** `tc`, `nft`, and the netlink conntrack calls all operate on network-namespace-scoped kernel state — inside a bridge-networked container they'd only ever see the container's own virtual interface and its own empty conntrack table, never the host's real interface or the connections Xray actually terminates there. The sock_ops backend doesn't have this problem (BPF attaches via the bind-mounted cgroup hierarchy, which is kernel-wide and independent of network namespace), so the `docker run` example above works as shown only because it's sock_ops-only. The same namespace-sharing is also why the default `-webhook-addr` (an abstract Unix socket, see below) needs no volume mount to reach a host-side Xray process: abstract sockets are namespaced by the network namespace, not the filesystem/mount namespace.

```
docker run -d \
  --name ebpf-speedlimit \
  --network host \
  --cap-add=NET_ADMIN \
  ebpf-speedlimit:latest \
  -enable-sock-ops=false -enable-tc-shaping -per-user-rate-mbit=100
```

No `-p` flag (the container shares the host's network stack entirely under `--network host`, so `-addr :7070` is already reachable at `localhost:7070` on the host), no cgroup bind-mount, no `BPF`/`SYS_ADMIN` capabilities — none of that is needed once `-enable-sock-ops=false`.

```
-iface string
      network interface for tc/HTB shaping (default: the interface used by the default route)
-enable-sock-ops
      enable the sock_ops/SO_MAX_PACING_RATE backend (default true)
-enable-tc-shaping
      enable the webhook -> conntrack mark -> tc/HTB shaping backend
-webhook-mark-base uint
      first mark issued by the webhook email->mark allocator (default 20000)
-webhook-mark-count uint
      size of the webhook mark pool (default 20000)
-default-class-rate-mbit uint
      rate (Mbit/s) for the tc/HTB default class; 0 = auto-detect via ethtool on -iface (default 0)
-htb-burst-ms uint
      burst/cburst allowance for every tc/HTB class, in milliseconds' worth of bytes at that class's own rate; 0 = kernel's own default sizing (default 100)
-per-user-rate-mbit uint
      if set, automatically provisions this rate (Mbit/s) for every newly allocated webhook mark; 0 = don't auto-provision, manage rates by hand via PUT /marks/{mark} (default 0)
-webhook-addr string
      listen address for the Xray webhook receiver, separate from -addr (default "@ebpf-speedlimit-webhook")
```

The default class is where every packet with no per-user `fw` filter match ends up — system traffic, and notably each user's own outbound-to-destination leg, since only the client-facing conntrack entry ever gets marked. Its rate has to reflect the interface's real link capacity, or that unclassified bucket becomes an unintended shared bottleneck for all of it. Left at `0`, this service queries the link speed via `ethtool` on `-iface` at startup — but only the first time, when the root qdisc doesn't exist yet; on a restart against an already-provisioned interface it reuses whatever rate the class already has and skips the `ethtool` call entirely. It fails to start on that first-time setup if `ethtool` can't report a speed (common on virtual interfaces — veth, tun/tap, wireguard); pass the flag explicitly in that case.

Without an explicit `burst`/`cburst`, Linux's HTB sizes a class's token bucket from its rate alone — normally just a couple KB, enough to pace steady throughput but not enough to absorb a short burst (a page load, TCP slow start) without an extra bit of throttling on top of the class's own rate. `-htb-burst-ms` fixes the bucket size to a duration instead: every class, default and per-user alike, gets `rate * htb-burst-ms / 8000` bytes of burst (floored at a couple KB so a very low rate or a short duration can't round down to a value `tc` rejects as too small).

By default, a mark newly allocated by the webhook handler gets no rate at all — it rides the default class until an operator calls `PUT /marks/{mark}`, and nothing in this service tells you which mark landed on which email to make that call. `-per-user-rate-mbit` closes that gap for the common case where every user gets the same cap: the moment `internal/webhook`'s allocator hands out a *new* mark for an email, the webhook handler itself calls `Set` on the same store `PUT /marks/{mark}` would use, provisioning that one mark's HTB class right then, before the connection's packets even get marked. It only ever touches marks it allocates — mark `0` (no mark, unmatched/system traffic and anything before its first webhook lands) and the default class are never affected, so unmarked traffic keeps riding at `-default-class-rate-mbit` regardless of this flag. It fires once per email (checked via the allocator, not on every webhook), so an already-provisioned user's repeat connections don't re-run `tc`/`nft` each time. Left at `0` (the default), rates are managed entirely by hand as before, including the pre-seeding approach of `PUT`-ing every mark in the pool ahead of time if you'd rather not rely on this.

The webhook receiver runs on its own listener (`-webhook-addr`), separate from `-addr`, because it's hit on every single new connection Xray routes — unlike `/marks`/`/healthz`, which are hit rarely. `-webhook-addr` accepts anything Xray-core's own `webhook.url` accepts as a Unix socket: a filesystem path (`/run/webhook.sock`), a Linux abstract socket (`@name` — no filesystem entry, lock-free), or a padded abstract socket (`@@name`, for HAProxy compatibility) — as well as a plain `host:port`. It defaults to `@ebpf-speedlimit-webhook`, an abstract socket, which is both the cheapest transport of the options (confirmed by benchmarking all three against a real webhook load: TCP costs ~470µs/connection more than baseline, a filesystem socket ~350µs, an abstract socket ~310µs — see the design notes) and, in a `--network host` container, needs no bind mount to be reachable from a host-side Xray process: abstract sockets are namespaced by the network namespace, not the mount namespace, so sharing the host's network namespace is all that's required. Point Xray's routing rule at the same address, with the request path appended after a `:` — e.g. `"webhook": {"url": "@ebpf-speedlimit-webhook:/webhook/xray", "deduplication": 0}`.

## HTTP API

### `PUT /marks/{mark}` — set or update a limit

```
curl -X PUT localhost:7070/marks/42 \
  -d '{"rate_bytes_per_sec": 1000000}'
```

`{"mark":42,"rate_bytes_per_sec":1000000}` on success. `mark` must fit in a `uint32`; `rate_bytes_per_sec` must be between 1 and 4294967295.

### `DELETE /marks/{mark}` — remove a limit

```
curl -X DELETE localhost:7070/marks/42
```

`204 No Content`, whether or not the mark had an entry.

### `GET /marks` — list current limits

```
curl localhost:7070/marks
```

```json
[{"mark":42,"rate_bytes_per_sec":1000000}]
```

### `POST /webhook/xray` — Xray-core webhook receiver (only with `-enable-tc-shaping`)

Served on `-webhook-addr`, not `-addr` — see above. Not meant to be called by hand; point Xray-core's `routing.rules[].webhook.url` at it.

### `GET /healthz` — liveness check

```
curl localhost:7070/healthz
```

## Building from source

```
go generate ./...   # requires clang + llvm, regenerates the bpf2go bindings
go build ./...
```

`docker build .` does both steps in the builder stage; the resulting image ships a single static-ish binary with the compiled BPF object embedded in it — no `.o` file, no `libbpf.so`, no CO-RE toolchain needed at runtime.

## Testing

```
go test ./...
```

Most of the test suite is plain Go unit tests against the HTTP API (CRUD validation, bad input, etc.) and needs nothing special.

One test actually loads the real `sock_ops` program into the kernel, attaches it to a throwaway cgroup, dials a marked TCP connection, and reads `SO_MAX_PACING_RATE` back off the socket to confirm it was set. It needs root plus the capabilities above and a cgroup v2 host with BTF; anywhere that isn't available, it skips itself with a clear reason instead of failing.
