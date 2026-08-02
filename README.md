# echo.semantic-ui.com

A standing WebTransport interop smoke. It answers one question: does a given
browser build establish a WebTransport session against a stock server over a
real WebPKI certificate, with no certificate pinning anywhere in the path?

Everything here is deliberately vanilla. The control server is
[webtransport-go](https://github.com/quic-go/webtransport-go) v0.12.0 with no
`Config`, no `AdditionalSettings`, and no vendored patches — whatever SETTINGS
the library's defaults produce is the wire under test. When a client fails
against this, the client is the variable.

Alongside it run three more listeners on their own ports. They share one echo
shape and vary one thing each, so a client that binds against one and refuses
another has named its requirement rather than merely failed.

## Taps

| | |
|---|---|
| Probe page | <https://echo.semantic-ui.com/> |
| Control, webtransport-go v0.12.0 | `https://echo.semantic-ui.com:4433/echo` |
| …the same server on the default port | `https://echo.semantic-ui.com/echo` (443/udp) |
| webtransport-go v0.11.0 on quic-go v0.60.0 | `https://echo.semantic-ui.com:4436/echo` |
| …the same server, self-signed leaf, pinned | `https://echo.semantic-ui.com:4437/echo` |
| rust `wtransport` over quinn | `https://echo.semantic-ui.com:4438/echo` |
| Certificate | Let's Encrypt everywhere except 4437 |

Pinning the older library pins its whole wire image, QUIC transport parameters
as well as h3 SETTINGS, which reproducing the SETTINGS alone on a newer core
cannot do. Notably v0.11.0 sends the `WT_INITIAL_MAX_DATA` /
`WT_INITIAL_MAX_STREAMS_UNI` / `WT_INITIAL_MAX_STREAMS_BIDI` trio that v0.12.0
omits, which draft-13 makes mandatory whenever `WT_MAX_SESSIONS` exceeds 1.

The Rust rung shares no code with either Go server, so it separates "this client
dislikes quic-go" from "this client dislikes WebTransport".

Ports 4436 and 4437 are one listener function called twice, differing only in
the certificate handed to it: 4436 serves the real chain, 4437 serves a
self-signed P-256 leaf minted at boot and pinned by hash. Their SETTINGS are
byte-identical, so a client that binds 4436 and refuses 4437 has isolated
`serverCertificateHashes` itself as the blocker, with nothing else to blame.
The leaf lives ten days, inside the fourteen-day ceiling pinning allows.

The page sweeps `WebTransport` constructor options via query params, one preset
per link, and logs every stage with millisecond stamps. Presets cover
`requireUnreliable` on and off, a non-empty `protocols` list, tight
anticipated-stream counts, and one link per rung. `?url=` retargets it at any
other server, which makes the page a portable client harness rather than a
fixture for this host alone. `?hashport=N` pins the leaf that the listener on
port N published, which is how the 4437 tap gets its hash; without it a tap runs
pure PKI validation.

Datagram plumbing is feature-detected. Safari exposes the streams as
`createWritable()` / `createReadable()` factories rather than the `writable` and
`readable` accessors the specification settled on, and a runtime with neither
still reports its session as established instead of throwing.

Every endpoint echoes datagrams and bidirectional streams straight back. The Go
servers write a qlog per connection under `/tmp/qlog` and `/tmp/qlog-legacy`;
all three log session requests to stdout, so `flyctl logs` separates them by
their `legacy`, `pinned` and `rust` prefixes. The pinned listener publishes its
leaf hash to `/tmp/hash4437`, which the page server hands back at `/hash4437`.

## Running locally

```sh
go build -o wt-lab . && ./wt-lab
```

Serves the page on `https://localhost:4434/` and WebTransport on
`localhost:4433`. `-wtcert` picks how the certificate is trusted:

- `hash` (default) — self-signed leaf, `/hash` hands the page a SHA-256 to pin.
  Nothing to install, but the leaf must live under 14 days for pinning to be legal.
- `ca` — mints a local CA (`ca.pem`) and signs both leaves with it. Install the
  CA on the device once and `?nohash=1` exercises real PKI validation.
- `le` — loads a real chain from `-cert`/`-key`. `/hash` returns empty, so the
  page skips pinning entirely. This is what production runs.

Useful flags: `-port`, `-pageport`, `-san`, `-qlog`, and `-bind` (set to
`fly-global-services` on Fly, which is the only interface public UDP arrives on).

The other rungs want a real chain on disk, so point them at any PEM pair:

```sh
cd legacy && go build -o wt-legacy . && ./wt-legacy -cert fullchain.pem -key privkey.pem
cd rust   && cargo build --release && ./target/release/wt-rust "" 4438
```

`wt-legacy` raises both 4436 and its pinned twin on 4437, and writes the pinned
leaf hash into `-hashdir` (`/tmp` by default) for the page server to serve.
`wt-rust` takes its bind host and port as positional arguments; an empty host
means all interfaces, and it reads `/cert.pem` and `/key.pem`.

## Deployment

Fly app `semanticui-echo`, region `iad`, on a dedicated IPv4. UDP needs a
dedicated address and the external port must equal the internal one — Fly does
not rewrite UDP destination ports. There is no IPv6 address on this app on
purpose: Fly routes no public UDP over v6.

Port 443 maps to the app's 4434 as raw TCP, so the page needs no port in its
URL while the app still owns the TLS handshake.

The machine auto-stops when idle. Any TCP request to port 443 wakes it, so
loading the page before tapping is the normal entry path — a UDP packet alone
will not start a stopped machine.

Keep this app at exactly one machine. Fly routes UDP per packet, so a second
instance can split a single QUIC connection across two servers and produce
handshake failures that look exactly like the client bugs this host exists to
diagnose. `flyctl deploy` adds an HA second machine by default:

```sh
flyctl deploy && flyctl scale count 1
```

The chain reaches the machine as secrets, which `start.sh` writes to disk before
launching all three servers:

```sh
flyctl secrets set -a semanticui-echo \
  WT_CERT_PEM="$(cat fullchain.pem)" WT_KEY_PEM="$(cat privkey.pem)"
```

## Certificate renewal

Let's Encrypt certificates expire after 90 days. Renewal is DNS-01 against
`_acme-challenge.echo.semantic-ui.com`, since ports 80 and 443 are not served
here:

```sh
certbot certonly --manual --preferred-challenges dns -d echo.semantic-ui.com
```

Add the TXT record it prints, let it validate, then push the new
`fullchain.pem` and `privkey.pem` as secrets and redeploy.
