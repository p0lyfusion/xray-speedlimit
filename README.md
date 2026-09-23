# xray-speedlimit

Per-user bandwidth limits for [Xray-core](https://github.com/XTLS/Xray-core), enforced in the Linux kernel with conntrack marks and a tc/HTB qdisc. Works with stock Xray-core: no patches, no eBPF.

## How it works

Xray-core only learns which user owns a connection after it has decrypted and parsed the handshake, so nothing at L3/L4 can tell users apart on its own. This service connects the two sides:

1. Xray-core's stock routing `webhook` action POSTs an event to `/webhook/xray` for every routed connection. The event carries the user's `email` and the client-facing 4-tuple (`source`, `inboundLocal`).
2. The service gives each `email` its own mark from `-mark-range`. The mark stays the same for as long as the process runs.
3. It sets that mark on the client connection's conntrack entry over netlink (`ConntrackUpdate`).
4. An nftables rule (`meta mark set ct mark`, in table `inet xray_speedlimit`) copies the conntrack mark onto each outgoing packet.
5. A root HTB qdisc on `-iface` has one class plus one `fw` filter per mark, so each user's packets land in their own rate-limited class.

```
Xray webhook POST ─→ allocator (email → mark) ─→ conntrack mark (netlink)
                                                        │
                    nft "meta mark set ct mark" ←───────┘
                                │
                    tc fw filter ─→ HTB class for that mark (rate cap)
```

A rate lives on a user's HTB class, not on individual connections. All of that user's connections share it, so opening parallel connections doesn't multiply the cap.

Only **egress** is shaped, meaning server → client, which is the client's download. Shaping upload as well would need `ifb` plus the tc `connmark` action, and `act_connmark` isn't available on every kernel. It is deliberately not implemented.

### Rates

Every user needs an HTB class. There are two ways to get one:

- **Automatic**: with `-per-user-rate-mbit`, the webhook handler creates the class with that rate the first time it gives an email a mark, before marking the connection. If that fails (for example `tc` errors), the handler retries on the user's next webhook.
- **Manual**: `PUT /marks/{mark}` sets or changes any mark's rate. Use `GET /users` to find which mark belongs to which email.

A mark with no class rides the default class (`1:1`). So do unmarked traffic, system traffic, and each user's own server → destination leg, since only the client-facing conntrack entry is ever marked. The default class's rate therefore has to match the interface's real link capacity, or it turns into a shared bottleneck:

- Left at `0`, `-default-class-rate-mbit` is detected with `ethtool` on `-iface`.
- Detection only happens the first time, while the root qdisc doesn't exist yet. On a restart against an already-set-up interface, the existing class keeps its rate and `ethtool` isn't run.
- Startup fails if `ethtool` can't report a speed, which is common on virtual interfaces (veth, tun/tap, wireguard). Pass the flag explicitly in that case.

Without an explicit burst, HTB sizes a class's token bucket from its rate alone. That is usually a couple of KB, too small to absorb a page load or TCP slow start without extra throttling. `-htb-burst-ms` sets the bucket size as a duration instead: every class gets `rate * htb-burst-ms / 8000` bytes of burst, floored at 2 KB so `tc` never rejects it as too small.

### Marks

`-mark-range` is inclusive on both ends, and startup checks it:

- It must lie within `1-65535`, because each mark is also an HTB classid minor number, which is 16 bits.
- Mark `0` means "no mark" and is never handed out.
- Keep the range disjoint from any other marks used on the host. Everything ends up in the same `skb->mark`.

When the range is used up, the service logs one warning. Later new users go unmarked and ride the default class.

The email → mark table lives in memory only. After a restart, marks are handed out again in whatever order users reconnect, so an email may get a different mark than before. Existing HTB classes survive the restart, and they're keyed by mark, not email. Tools that read `GET /users` should re-read it after a restart rather than cache it.

### The webhook listener

The webhook receiver has its own listener, `-webhook-addr`, separate from `-addr`, because it's hit on every new connection Xray routes.

It accepts every address form Xray-core's own `webhook.url` does for a Unix socket, so the same string works on both sides:

- a filesystem path, such as `/run/webhook.sock`;
- a Linux abstract socket, `@name`, which has no filesystem entry;
- a padded abstract socket, `@@name`, for HAProxy compatibility;
- a plain `host:port`.

The default is `@xray-speedlimit-webhook`. An abstract socket is the cheapest of these transports. Benchmarked against a real webhook load, the extra Xray CPU per connection was about 470µs over TCP, about 350µs over a filesystem socket, and about 310µs over an abstract socket. Abstract sockets belong to the network namespace, so a `--network host` container reaches a host-side Xray process with no bind mount.

## Configuring Xray-core

Add a routing rule with a `webhook` that matches the traffic you want to limit:

```json
{
  "routing": {
    "rules": [
      {
        "inboundTag": ["VLESS_TCP"],
        "outboundTag": "direct",
        "webhook": {
          "url": "@xray-speedlimit-webhook:/webhook/xray",
          "deduplication": 0
        }
      }
    ]
  }
}
```

- Put the request path after a `:` when the URL is a Unix socket.
- `deduplication` must be `0`. Xray deduplicates per `email`, so any other value means only a user's first connection in each window gets marked.
- Xray delivers webhooks fire-and-forget, with no retry. If a POST is lost, that connection runs uncapped for its whole life.

## Running it

```
docker run -d \
  --name xray-speedlimit \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/p0lyfusion/xray-speedlimit:latest \
  -per-user-rate-mbit=100
```

`--network host` is required. `tc`, `nft` and the netlink conntrack calls all act on the network namespace they run in. In a bridge-networked container they would only see the container's own virtual interface and its own empty conntrack table. With host networking, `-addr :7070` is reachable on the host directly, with no `-p`.

The image includes `iproute2` (`tc`), `nftables` and `ethtool`, which the service runs at runtime. Outside Docker, those need to be on `PATH`, and the process needs `CAP_NET_ADMIN`.

### Flags

```
-addr string
      HTTP API listen address (default ":7070")
-webhook-addr string
      listen address for the Xray webhook receiver, separate from -addr
      (default "@xray-speedlimit-webhook")
-iface string
      network interface for tc/HTB shaping (default: the interface used by the default route)
-mark-range value
      inclusive range of marks handed out to users, as first-last; must lie within
      1-65535 (default 20000-39999)
-default-class-rate-mbit uint
      rate (Mbit/s) for the tc/HTB default class; 0 = auto-detect via ethtool on -iface
-htb-burst-ms uint
      burst/cburst for every tc/HTB class, in milliseconds' worth of bytes at that
      class's own rate; 0 = kernel's default sizing (default 100)
-per-user-rate-mbit uint
      if set, automatically provisions this rate (Mbit/s) for every newly allocated
      mark; 0 = manage rates by hand via PUT /marks/{mark}
```

## HTTP API

Served on `-addr`.

### `PUT /marks/{mark}`: set or update a limit

```
curl -X PUT localhost:7070/marks/20000 \
  -d '{"rate_bytes_per_sec": 1000000}'
```

Returns `{"mark":20000,"rate_bytes_per_sec":1000000}` on success. `mark` must fit in a `uint32`, and `rate_bytes_per_sec` must be between 1 and 4294967295. Setting a rate needs a mark in `1-65535`, because it creates an HTB class, so any other mark gets a 500.

### `DELETE /marks/{mark}`: remove a limit

```
curl -X DELETE localhost:7070/marks/20000
```

Returns `204 No Content` whether or not the mark had an entry. The mark's traffic falls back to the default class.

### `GET /marks`: list current limits

```
curl localhost:7070/marks
```

```json
[{"mark":20000,"rate_bytes_per_sec":1000000}]
```

### `GET /users`: list the email → mark table

```
curl localhost:7070/users
```

```json
[{"email":"alice@example.com","mark":20000},{"email":"bob@example.com","mark":20001}]
```

Sorted by mark, and `[]` when no user has connected yet. See [Marks](#marks) for what happens to this table on restart.

### `GET /healthz`: liveness check

```
curl localhost:7070/healthz
```

### `POST /webhook/xray`: Xray-core webhook receiver

Served on `-webhook-addr`, not `-addr`. It isn't meant to be called by hand; point Xray-core's `routing.rules[].webhook.url` at it.

## Building from source

```
go build ./cmd/xray-speedlimit
```

## Testing

```
go test ./... -p 1
```

Most tests are plain unit tests and need nothing special.

`internal/conntrack/conntrack_live_test.go` marks real conntrack entries. It needs root, `CAP_NET_ADMIN` and `nft`, and skips itself with a reason when those aren't available. `-p 1` stops it from racing other packages over shared kernel state.
