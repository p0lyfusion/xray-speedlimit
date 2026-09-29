# xray-speedlimit

Per-user bandwidth limits for [Xray-core](https://github.com/XTLS/Xray-core), enforced in the Linux kernel with conntrack marks and a tc/HTB qdisc. Works with stock Xray-core: no patches, no eBPF.

## How it works

Xray-core only learns which user owns a connection after it has decrypted and parsed the handshake, so nothing at L3/L4 can tell users apart on its own. This service connects the two sides:

1. Xray-core's stock routing `webhook` action POSTs an event to `/webhook/xray` for every routed connection. The event carries the user's `email` and the client-facing 4-tuple (`source`, `inboundLocal`).
2. The service computes the user's mark from their `email` (see [Marks](#marks)). The same email always gets the same mark, across restarts too.
3. It sets that mark on the client connection's conntrack entry over netlink, with one `IPCTNL_MSG_CT_NEW` update keyed by the connection's exact tuple. The kernel finds the entry with a hash lookup, so the cost doesn't grow with the size of the conntrack table. When Xray reports the local address as `0.0.0.0` or `::`, the service tries each address assigned to a local interface in the client's address family and marks every entry it finds. All of those updates go to the kernel in one system call, on a netlink socket kept open between webhooks. A connection whose local address isn't assigned to an interface (AnyIP routes, TPROXY) can't be marked.
4. An nftables rule (`ct mark != 0 meta mark set ct mark`, in table `inet xray_speedlimit`) copies the conntrack mark onto each outgoing packet of a marked connection. Packets of unmarked connections keep whatever mark they already had. The service re-applies this table on every start.
5. On `-iface`, an `mq` root qdisc gives every TX queue its own HTB qdisc. A clsact egress filter moves each marked packet onto the TX queue its mark names, and that queue's HTB puts it in the user's rate-limited class.

```
Xray webhook POST ─→ hash(email) → mark ─→ conntrack mark (netlink)
                                                  │
                  nft "meta mark set ct mark" ←───┘
                              │
          clsact egress: skbedit queue_mapping (from the mark's queue field)
                              │
          mq ─→ HTB of that TX queue ─→ fw (classid = mark) ─→ user's class
```

The layout on the interface:

```
root mq 8000:
  8000:<q> → htb <q>: default 1        one per TX queue, q = 1..queues
                class <q>:1            default class, at link rate
                class <q>:<minor>      one per user
                filter fw              no entries: uses the mark as the classid
clsact egress, pref 49000
  fw mark <q><<16/0xff0000 → skbedit queue_mapping <q-1>
```

A single HTB qdisc has one lock that every packet on the interface takes, which on a many-core, many-queue NIC turns into softirq contention. With one HTB per TX queue, each queue has its own lock. A user always maps to one queue, so all of their connections still share one class.

A rate lives on a user's HTB class, not on individual connections. All of that user's connections share it, so opening parallel connections doesn't multiply the cap.

Only **egress** is shaped, meaning server → client, which is the client's download. Shaping upload as well would need `ifb` plus the tc `connmark` action, and `act_connmark` isn't available on every kernel. It is deliberately not implemented.

### Step by step: one user, one packet

This follows one user through the whole path. The example host has 48 TX queues on `eth0`, runs with `-per-user-rate-mbit 120 -htb-burst-ms 1000`, and the user's email is `alice@example.com`.

#### 1. The email becomes a mark

The mark is computed from the email alone (`internal/mark`); nothing is looked up or stored.

```
email          "alice@example.com"
                        │
                        │  FNV-1a, 64-bit
                        ▼
sum            0x67023fc4a7ff2a46
                        │
         ┌──────────────┴──────────────────────┐
         │ sum mod 48                          │ (sum div 48) mod 65534, + 2
         ▼                                     ▼
queue index    22                     minor   6409 = 0x1909
major          23 = 0x17  (queue index + 1)
                        │
                        ▼
mark = major << 16 | minor = 0x00171909 = 1513737
```

The 32-bit mark is laid out like this:

```
 31        24 23        16 15                        0
┌────────────┬────────────┬───────────────────────────┐
│  00000000  │  00010111  │     0001100100001001      │
│   unused   │ major 0x17 │       minor 0x1909        │
└────────────┴────────────┴───────────────────────────┘
              queue field     class inside the queue
              (mask 0xff0000)
```

- `major` (1..48 here) names both the TX queue (`major - 1`, so queue 22) and the HTB qdisc on it (handle `17:`, since tc handles are hex).
- `minor` (2..65535) names the user's class inside that HTB. Minor 1 is the queue's default class, and 0 isn't a valid class, so hashes never land there.
- The same email gives the same mark every time, on every start, as long as the queue count stays 48.

#### 2. What the user has in the kernel

The service builds this tree once. Only the user's own class is per-user:

```
eth0
├─ root  qdisc mq 8000:
│   ├─ class 8000:1  (TX queue 0)  ─→ qdisc htb 1:  ─┬─ class 1:1    default, 10 Gbit
│   │                                                ├─ class 1:…    other users
│   │                                                └─ filter fw    (no entries)
│   ├─ …
│   ├─ class 8000:17 (TX queue 22) ─→ qdisc htb 17: ─┬─ class 17:1     default, 10 Gbit
│   │                                                ├─ class 17:1909  ← this user, 120 Mbit
│   │                                                ├─ class 17:…     other users on queue 22
│   │                                                └─ filter fw      (no entries)
│   ├─ …
│   └─ class 8000:30 (TX queue 47) ─→ qdisc htb 30: ─ …
│
└─ clsact  (egress hook, runs before a TX queue is picked)
    ├─ filter fw handle 0x10000/0xff0000  → skbedit queue_mapping 0
    ├─ …
    ├─ filter fw handle 0x170000/0xff0000 → skbedit queue_mapping 22
    ├─ …
    └─ filter fw handle 0x300000/0xff0000 → skbedit queue_mapping 47
```

The user's class is created the first time the service sees them:

```
tc class replace dev eth0 parent 17: classid 17:1909 \
    htb rate 120000000bit burst 15000000b cburst 15000000b
```

`burst` is 1000 ms of the class's own rate: 15 MB/s × 1 s.

#### 3. A connection gets marked

The user connects, and Xray POSTs:

```json
{"email": "alice@example.com", "network": "tcp",
 "source": "203.0.113.7:20416", "inboundLocal": "[::]:443", ...}
```

The service then:

1. Computes the mark `0x171909` (step 1).
2. Checks the store for a rate on `0x171909`. If there is none, it queues the mark for the background provisioning worker, which runs the `tc class replace` above. The webhook doesn't wait for it.
3. Skips the rest if it marked this same connection (`203.0.113.7:20416` → `[::]:443`, mark `0x171909`) less than `-remark-after` ago. See [Repeated webhooks](#repeated-webhooks).
4. Writes `mark=0x171909` onto the connection's conntrack entry. `inboundLocal` is `[::]`, which says nothing about the local address, so it sends one exact-tuple lookup per IPv4 address assigned to the host, all in one system call, and one of them hits the entry for `203.0.113.7:20416 → 198.51.100.1:443`.

#### 4. A packet goes out

The server sends the user a packet on that connection:

```
Xray writes to the socket
        │
        ▼
nft postrouting   ct mark != 0 → meta mark set ct mark
        │         skb->mark = 0x171909
        ▼
clsact egress     fw: 0x171909 & 0xff0000 = 0x170000 → matches the queue-22 filter
        │         skbedit queue_mapping 22
        ▼
TX queue 22       the kernel skips its own queue choice (XPS/hash)
        │
        ▼
mq 8000:17 → htb 17:
        │         fw (no entries): the mark's major 0x17 is this qdisc's handle,
        │         so classid = mark = 17:1909
        ▼
class 17:1909     120 Mbit token bucket: sent now, or queued until tokens refill
        │
        ▼
NIC TX ring 22 ─→ wire
```

Only CPUs sending on queue 22 contend for `htb 17:`'s lock. The other 47 queues have their own.

A packet with no mark, such as the same user's server → destination leg, or system traffic, takes the other branch:

```
skb->mark = 0 ─→ clsact: no filter matches ─→ the kernel picks a TX queue as usual, say 7
             ─→ htb 8: ─→ fw: mark 0 gives no class ─→ default class 8:1 (link rate)
```

#### 5. The class over time

```
first webhook   no rate in the store → tc class replace … 17:1909   (background)
later webhooks  rate in the store → nothing to do; only the conntrack mark is written
restart         layout found → adopted as-is; class 17:1909 found → rate put in the store
6h no traffic   the idle collector deletes class 17:1909 and its store entry
comes back      no rate in the store → class 17:1909 is created again
```

Between the first webhook and the class existing (usually milliseconds, longer after a rebuild), the user's packets ride `17:1`, queue 22's default class, unshaped.

#### 6. When two users collide

Two emails whose hashes agree on both `sum mod 48` and `(sum div 48) mod 65534` get the same mark, and so the same class. Their connections then share one 120 Mbit bucket: each still gets the full rate while the other is idle, and they split it when both are busy. With 48 × 65534 ≈ 3.1 million marks, that happens to about 0.2% of users at 7,000 concurrent users.

### Rates

Every user needs an HTB class. There are two ways to get one:

- **Automatic**: with `-per-user-rate-mbit`, the webhook handler creates the class with that rate the first time it sees the user's mark. A single background worker does this, so marking a connection never waits for `tc`. Until the class exists, the user's traffic rides their queue's default class. If creating it fails (for example `tc` errors), the handler retries on the user's next webhook.
- **Manual**: `PUT /marks/{mark}` sets or changes any mark's rate. Use `GET /users` to find which mark belongs to which email.

Classes live in the kernel, so they survive a restart of the service. On startup the service adopts the classes it finds: `GET /marks` lists them, and they aren't provisioned again. With `-per-user-rate-mbit`, a mark is provisioned whenever it has no rate: after `DELETE /marks`, or after its idle class was deleted, its user's next connection gives it the per-user rate again.

Classes of users who have gone away are deleted after `-class-idle-timeout` (6 hours by default) without traffic, since otherwise every email ever seen would keep a class. A returning user gets a new one on their next connection. A rate set by hand through `PUT /marks` is deleted the same way.

A mark with no class rides its queue's default class (`<q>:1`). So do unmarked traffic, system traffic, and each user's own server → destination leg, since only the client-facing conntrack entry is ever marked. Each queue's default class gets the interface's full link rate, so it never becomes a bottleneck of its own:

- Left at `0`, `-default-class-rate-mbit` is detected with `ethtool` on `-iface`.
- Detection only happens when the layout is built. On a restart against an already-set-up interface, the existing classes keep their rates and `ethtool` isn't run.
- Startup fails if `ethtool` can't report a speed, which is common on virtual interfaces (veth, tun/tap, wireguard). Pass the flag explicitly in that case.

Without an explicit burst, HTB sizes a class's token bucket from its rate alone. That is usually a couple of KB, too small to absorb a page load or TCP slow start without extra throttling. `-htb-burst-ms` sets the bucket size as a duration instead: every class gets `rate * htb-burst-ms / 8000` bytes of burst, floored at 2 KB so `tc` never rejects it as too small.

### Marks

A mark is `(q << 16) | minor`: `q` (1 to the queue count) picks the TX queue and its HTB, and `minor` (2-65535) picks the class inside it. Both come from an FNV-1a hash of the email, so:

- The same email always gets the same mark. Nothing is stored, a restart changes nothing, and marks never run out.
- Users spread evenly over the TX queues.
- Two emails can hash to the same mark, and then share one class and its rate. With `Q` queues there are `Q × 65534` marks, so on 48 queues about 0.2% of 7,000 concurrent users share a class with someone.

Every mark depends on the queue count, which is every TX queue `-iface` has in use unless `-tx-queues` says otherwise (at most 255). If it changes, for example with `ethtool -L`, the next start rebuilds the layout and every user gets a new mark.

Marks use bits 16-23 of the packet mark. Nothing else on the host may use those bits: the steering filters and the fw classifiers act on the whole `skb->mark`.

Building the layout replaces the root qdisc, dropping whatever tree was there, including the single root HTB older versions of this service built. Connections marked under that old layout carry marks that match no class, so they ride their queue's default class until a webhook re-marks them.

`GET /users` lists the emails seen in the last `-class-idle-timeout`.

With `-per-user-rate-mbit`, a class the service finds at startup is only adopted if it already has that rate. Change the flag and every user's class is updated on their next connection. Changing `-htb-burst-ms` doesn't touch existing classes: it applies to classes created after it (existing ones pick it up once they go idle and are recreated).

To roll back to a version from before this layout, delete the root qdisc first (`tc qdisc del dev <iface> root`). Those versions decide whether their tree exists by looking for an `htb 1:` qdisc, which this layout also contains (under TX queue 0), and would otherwise put every class under that one queue.

### Repeated webhooks

Xray sends a webhook for every *routed* connection. With a plain TCP transport (raw, REALITY, TLS over TCP) that is one per client TCP connection. Transports that multiplex (XHTTP, mux) route every sub-request separately, so one client TCP connection produces a stream of webhooks, all with the same `source` and `inboundLocal`. The conntrack entry already carries the mark after the first one, so the service remembers each connection it marked (source, local address, mark) for `-remark-after` (10 seconds by default) and answers repeats without touching the kernel.

Measured on an XHTTP server (about 5,000 users, 2,450 webhooks a second, two minutes of traffic replayed against different windows):

| `-remark-after` | 1s | 5s | 10s | 30s | 60s |
|---|---|---|---|---|---|
| webhooks that skip the kernel | 63% | 78% | 83% | 88% | 91% |

The gain flattens after about 10 seconds, while the risk below grows with the window, hence the default.

The risk: if the same user opens a new connection from the same client IP:port within the window, the new conntrack entry starts unmarked and the cache skips it, so it runs unshaped (above the limit, never blocked).

- **XHTTP / mux:** that connection keeps sending webhooks, so it is marked at the latest one window later. Most webhooks are repeats, so this is where the cache pays off.
- **Plain TCP transports (raw, REALITY, TLS over TCP):** a connection sends one webhook, so a connection skipped this way stays unshaped for its whole life, and the cache rarely hits anyway. **Use `-remark-after 0` on these hosts.**

Reuse of a port by a *different* user is harmless: the mark is part of the key. A failed mark is never remembered, so the next webhook for that connection tries again.

To size the window for another host, replay its Xray access log (one `accepted` line per webhook): group lines by source IP:port and email, and count how many arrive less than the window after the last one that would have been marked.

### Relays and HAProxy

The service marks the conntrack entry whose tuple is the webhook's `source` → `inboundLocal`. That only works if Xray reports the addresses of a real TCP connection on this host, and that connection carries one user's traffic out of `-iface`. With a proxy in front of Xray:

| Setup | Xray's `source` | Result |
|---|---|---|
| HAProxy on the same host, TCP mode, PROXY protocol (`acceptProxyProtocol`) | client IP:port, `inboundLocal` = host:443 | Works. That tuple is the client → HAProxy connection, whose packets to the client are the ones to shape. |
| HAProxy on the same host, TCP mode, no PROXY protocol | `127.0.0.1:port` | Doesn't shape: the loopback connection is marked, and loopback traffic never leaves through `-iface`. |
| HAProxy on the same host, to Xray over a Unix socket | no IP | Nothing is marked. |
| Relay on another host, TCP mode, no PROXY protocol | relay IP:port | Works: one relay → backend connection per client, shaped on the backend's egress towards the relay. |
| Relay on another host, PROXY protocol | client IP:port | Every mark fails: the backend's conntrack only knows the relay's address. |
| HTTP mode with `X-Forwarded-For` (`trustedXForwardedFor`) | client IP, port 0 | Every mark fails: Xray drops the port, so no connection matches. |
| HTTP mode, relay reuses backend connections (`http-reuse`) | relay IP:port | Wrong: one backend connection carries several users, and its mark follows whichever user's webhook came last. |

So: keep HAProxy in TCP mode with one backend connection per client. With HAProxy on the same host, enable PROXY protocol on both sides; with a relay on another host, leave it off. Set `-iface` to the interface the relay's traffic arrives on if that isn't the default route's (a private network, WireGuard). A relay reuses its own ports far more often than a client does, so on relay backends keep `-remark-after` to a few seconds, or 0.

A failed mark is never remembered, so the next webhook for that connection tries again.

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
- `deduplication` must be `0`. Xray deduplicates per `email`, so any other value means only a user's first connection in each window gets marked. The service does its own per-connection deduplication instead; see [Repeated webhooks](#repeated-webhooks).
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
-tx-queues int
      number of TX queues to spread users over, one HTB qdisc each (at most 255);
      0 = every TX queue -iface has in use
-default-class-rate-mbit uint
      rate (Mbit/s) for each queue's tc/HTB default class; 0 = auto-detect via
      ethtool on -iface
-htb-burst-ms uint
      burst/cburst for every tc/HTB class, in milliseconds' worth of bytes at that
      class's own rate; 0 = kernel's default sizing (default 100)
-per-user-rate-mbit uint
      if set, automatically provisions this rate (Mbit/s) for every user's mark the
      first time it is seen; 0 = manage rates by hand via PUT /marks/{mark}
-class-idle-timeout duration
      delete a user's class after it has sent nothing for this long, and drop
      emails idle that long from GET /users; 0 = never, and GET /users keeps
      every email seen (default 6h0m0s)
-remark-after duration
      don't mark a connection again when another webhook for it arrives within
      this long; see Repeated webhooks; 0 = mark on every webhook (default 10s)
```

## HTTP API

Served on `-addr`.

### `PUT /marks/{mark}`: set or update a limit

```
curl -X PUT localhost:7070/marks/2349593 \
  -d '{"rate_bytes_per_sec": 1000000}'
```

Returns `{"mark":2349593,"rate_bytes_per_sec":1000000}` on success. `mark` must fit in a `uint32`, and `rate_bytes_per_sec` must be between 1 and 4294967295. Setting a rate creates an HTB class, so the mark has to be one a user can get (see [Marks](#marks)); any other mark gets a 500.

### `DELETE /marks/{mark}`: remove a limit

```
curl -X DELETE localhost:7070/marks/2349593
```

Returns `204 No Content` whether or not the mark had an entry. The mark's traffic falls back to its queue's default class.

### `GET /marks`: list current limits

```
curl localhost:7070/marks
```

```json
[{"mark":2349593,"rate_bytes_per_sec":1000000}]
```

### `GET /users`: list the email → mark table with each user's limit

```
curl localhost:7070/users
```

```json
[{"email":"alice@example.com","mark":2349593,"rate_bytes_per_sec":12500000},{"email":"bob@example.com","mark":1903858}]
```

`rate_bytes_per_sec` is the mark's current limit, as in `GET /marks`. It's omitted when the mark has no limit, so that user rides the default class. Sorted by mark, and `[]` when no user has connected yet. See [Marks](#marks) for what happens to this table on restart.

### `GET /healthz`: liveness check

```
curl localhost:7070/healthz
```

### `POST /webhook/xray`: Xray-core webhook receiver

Served on `-webhook-addr`, not `-addr`. It isn't meant to be called by hand; point Xray-core's `routing.rules[].webhook.url` at it. It answers `204 No Content` when the connection is marked, or when the event is one it ignores (no email, not TCP); `400` for a body that isn't JSON; and `500` when the connection couldn't be marked.

## Building from source

```
go build ./cmd/xray-speedlimit
```

## Testing

```
go test ./... -p 1
```

Most tests are plain unit tests and need nothing special.

Two live tests touch real kernel state and skip themselves with a reason when they can't run:

- `internal/conntrack/conntrack_live_test.go` marks real conntrack entries. It needs root, `CAP_NET_ADMIN`, `nft` and `ip`.
- `internal/tcshape/tcshape_live_test.go` builds the layout on a 4-queue veth and checks that marked IPv4 and IPv6 packets reach their class. It needs root, `CAP_NET_ADMIN`, `tc`, `ip` and `nft`.

`unshare -rn` runs both without real root or touching the host: build the test binary with `go test -c`, then run it under `unshare -rn` after `ip link set lo up`. `-p 1` stops the live tests from racing each other over shared kernel state.
