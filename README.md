# WebTransport Echo

A public WebTransport echo server, live at
**[echo.semantic-ui.com](https://echo.semantic-ui.com/)**.

Point a client at it and your datagrams and streams come straight back. It
serves a real Let's Encrypt certificate, so there is no `serverCertificateHashes`
pinning, no local CA, and nothing to install.

```js
const wt = new WebTransport('https://echo.semantic-ui.com:4436/echo');
await wt.ready;

const writer = wt.datagrams.writable.getWriter();
await writer.write(new TextEncoder().encode('hello'));

const reader = wt.datagrams.readable.getReader();
const { value } = await reader.read();       // -> "hello"
```

Safari exposes those two streams as `createWritable()` and `createReadable()`
factories rather than the accessors above, so reach for them if `writable` and
`readable` come back undefined.

The page at <https://echo.semantic-ui.com/> is a test client you can point at any
WebTransport URL, and a set of live interop exhibits for two iOS Safari
session-establishment findings.

## Endpoints

Several servers run side by side. They share one echo handler and one
certificate, and differ by exactly one thing each, which is what makes them
useful as exhibits. For ordinary use, take the first row.

| Endpoint | Stack | Certificate | Role |
|---|---|---|---|
| `:4436/echo` | webtransport-go v0.11.0 · quic-go v0.60.0 | Let's Encrypt | **General use.** Binds on every browser tested, including iOS Safari |
| `/echo` (443/udp) | webtransport-go v0.12.0 · quic-go v0.61.0 | Let's Encrypt | Default-port echo. Exhibit 1a′ — refused by iOS 27 |
| `:4433/echo` | webtransport-go v0.12.0 · quic-go v0.61.0 | Let's Encrypt | Library defaults. Exhibit 1a — refused by iOS 27 |
| `:4440/echo` | webtransport-go v0.12.0 · quic-go v0.61.0 | Let's Encrypt | Defaults plus flow-control settings. Exhibit 1b — refused by iOS 27 |
| `:4438/echo` | wtransport 0.7.1 over quinn | Let's Encrypt | Independent stack, no code shared with the Go servers |
| `:4437/echo` | webtransport-go v0.11.0 · quic-go v0.60.0 | self-signed, hash-pinned | Isolates `serverCertificateHashes` |
| `:4439/echo` | webtransport-go v0.11.0 · quic-go v0.60.0 | self-signed + `CertSign`, pinned | Isolates leaf shape |
| `:6443/echo` | webtransport-go v0.11.0 · quic-go v0.60.0 | self-signed, hash-pinned | Isolates the port number |

Use `:4436` unless you specifically want one of the exhibit cases. The three
v0.12.0 ports are deliberately left in a state iOS 27 refuses, because that
refusal is the thing being demonstrated.

The self-signed leaves are P-256, minted fresh at boot, and live ten days —
inside the fourteen-day ceiling that certificate pinning allows. Each pinned
listener publishes its leaf hash at `/hash<port>`, so `/hash4437` returns the
base64 SHA-256 the page pins for `:4437`.

## Findings

**The flow-control conditional.** `draft-ietf-webtrans-http3` (draft-13 onward)
makes the `WT_INITIAL_MAX_DATA` / `WT_INITIAL_MAX_STREAMS_UNI` /
`WT_INITIAL_MAX_STREAMS_BIDI` settings mandatory whenever a server advertises
`WT_MAX_SESSIONS` greater than 1. iOS 27 enforces this: `:4433` advertises
`WT_MAX_SESSIONS = 2^62−1` and omits the three settings, and Safari refuses it.
Filed as: *[issue link pending]*.

**The library generation.** Satisfying that conditional is not sufficient.
`:4440` is the same v0.12.0 server configured to send all three settings, and
iOS 27 still refuses it — while `:4436` binds, running webtransport-go v0.11.0
on quic-go v0.60.0. Those two ports advertise byte-identical h3 SETTINGS and
byte-identical QUIC transport parameters, so the difference lies in wire
behaviour that neither party advertises. `:4438` binds as well, which rules out
WebTransport itself. Filed as: *[issue link pending]*.

Refusals share a signature: the client sees a `WebTransportError` with an empty
message about 50 ms after construction, and server-side the peer opens the
extended-CONNECT stream, writes zero bytes, sends
`stop_sending(stream 0, 0x10C)` and closes with `0x100`.

## Using the page

**Echo tool.** Enter any WebTransport URL, connect, and send a datagram or open
a bidirectional stream. It takes an optional base64 SHA-256 certificate hash, so
it can dial a foreign origin whose certificate it has no other way to trust, and
an optional protocol list.

**Exhibits.** Every case has a `Run` button, and `Run all exhibits` executes the
lot and fills in a results table. The *expected* column reports what iOS 27 beta
does — every case binds on Chrome, which is the point of listing them separately.

**Query parameters.** The manual sweep at the foot of the page drives the
constructor directly:

| | |
|---|---|
| `url=` | dial a different endpoint |
| `ru=0` | omit `requireUnreliable` |
| `pool=1` | set `allowPooling` |
| `protos=a,b` | send a non-empty protocol list |
| `uni=N` `bidi=N` | anticipated incoming stream counts |
| `hash=<base64>` | pin an externally supplied leaf hash |
| `hashport=N` | pin the leaf published by the listener on port N |
| `nohash=1` | skip pinning entirely |
| `maxage=N` | set datagram `incomingMaxAge` and `outgoingMaxAge` after construction, before `ready` |

The same page is served at `/auth/` behind HTTP Basic auth (`retro` / `retro`),
which reproduces a Basic-auth browsing context. The `/hash` endpoints stay
unauthenticated so the page's own fetches keep working from there.

Datagram plumbing is feature-detected: Safari exposes the streams as
`createWritable()` / `createReadable()` factories rather than the `writable` and
`readable` accessors the specification settled on, and a runtime with neither
still reports its session as established rather than throwing.

## Running locally

Requires the Go toolchain named in `go.mod`, and Rust for the wtransport rung.

```sh
go build -o wt-lab . && ./wt-lab
```

That serves the page on `https://localhost:4434/` and WebTransport on
`localhost:4433`. `-wtcert` chooses how the certificate is trusted:

- `hash` (default) — self-signed leaf; `/hash` hands the page a SHA-256 to pin.
  Nothing to install, but the leaf must live under fourteen days to be pinnable.
- `ca` — mints a local CA (`ca.pem`) and signs both leaves with it. Install the
  CA on a device once, and `?nohash=1` then exercises real PKI validation.
- `le` — loads a real chain from `-cert` and `-key`. `/hash` returns empty, so
  the page skips pinning. This is what production runs.

Other flags: `-port`, `-pageport`, `-trioport`, `-san`, `-qlog`, `-hashdir`, and
`-bind` (set to `fly-global-services` on Fly, the only interface public UDP
arrives on).

The other two binaries want a real chain on disk:

```sh
cd legacy && go build -o wt-legacy . && ./wt-legacy -cert fullchain.pem -key privkey.pem
cd rust   && cargo build --release && ./target/release/wt-rust "" 4438
```

`wt-legacy` raises all four of its ports at once (`-port`, `-pinnedport`,
`-certsignport`, `-altport`) and writes each pinned leaf hash into `-hashdir`,
`/tmp` by default, for the page server to serve. `wt-rust` takes its bind host
and port as positional arguments, where an empty host means all interfaces, and
reads `/cert.pem` and `/key.pem`.

Every endpoint echoes datagrams and bidirectional streams. The Go servers write
a qlog per connection under `/tmp/qlog` and `/tmp/qlog-legacy`, and all three
tag their stdout, so logs separate by the `legacy`, `pinned`, `certsign`,
`altport` and `rust` prefixes.

## Abuse budgets

The echo is public, so egress is capped. Every server enforces the same four
numbers, each far above what an interop or development test needs — the heaviest
exhibit here moves well under 10 KiB.

- **1 MiB echoed per session**, datagrams and streams counted together. Past it
  the session closes with the reason `echo budget reached`.
- **120 seconds per session**, then `session lifetime reached`.
- **4 concurrent sessions per address.** Further upgrades are declined, and a
  slot frees the moment its session ends.
- **2 GiB echoed per process per day.** Past it the process refuses new sessions
  and stops echoing on existing ones, and says so once in the log.

Counters live in memory and reset when a process restarts. That suits their
purpose, which is putting a floor under the worst-case bandwidth bill rather
than resisting a determined attacker.

## Operating

Deployed to [Fly](https://fly.io) as app `semanticui-echo`, region `iad`, on a
dedicated IPv4.

**Run exactly one machine.** Fly routes UDP per packet, so a second instance can
split a single QUIC connection across two servers and produce handshake failures
that look exactly like the client bugs this host exists to diagnose. `flyctl
deploy` adds a second machine for high availability by default:

```sh
flyctl deploy && flyctl scale count 1
```

UDP needs a dedicated address, and each external port must equal its internal
port, because Fly does not rewrite UDP destination ports. The app has no IPv6
address on purpose: Fly routes no public UDP over v6. Port 443 maps to the app's
4434 as raw TCP, so the page needs no port in its URL while the app still owns
the TLS handshake.

The machine auto-stops when idle. A TCP request to port 443 wakes it, so loading
the page before dialing is the normal entry path — a UDP packet alone will not
start a stopped machine.

The certificate reaches the machine as secrets, which `start.sh` writes to disk
before launching all three servers:

```sh
flyctl secrets set -a semanticui-echo \
  WT_CERT_PEM="$(cat fullchain.pem)" WT_KEY_PEM="$(cat privkey.pem)"
```

### Certificate renewal

Let's Encrypt certificates expire after 90 days. Renewal is DNS-01 against
`_acme-challenge.echo.semantic-ui.com`, since ports 80 and 443 are not served
for HTTP here:

```sh
certbot certonly --manual --preferred-challenges dns -d echo.semantic-ui.com
```

Add the TXT record it prints, let it validate, then push the new `fullchain.pem`
and `privkey.pem` as secrets and redeploy.

## License

MIT. See [LICENSE](LICENSE).
