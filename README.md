# WebTransport Echo

A public WebTransport echo server, live at
**[echo.semantic-ui.com](https://echo.semantic-ui.com/)**. Datagrams and streams come
straight back.

```js
const wt = new WebTransport('https://echo.semantic-ui.com/echo');
await wt.ready;

const writer = wt.datagrams.writable.getWriter();
await writer.write(new TextEncoder().encode('hello'));

const reader = wt.datagrams.readable.getReader();
const { value } = await reader.read();       // "hello"
```

The specification replaced `datagrams.writable` with `createWritable()` in 2025. Safari
ships the current shape and Chrome still ships the old attribute, so feature-detect the
writer. `readable` is an accessor on every engine.

The page dials any WebTransport URL, reports which endpoints your browser will establish
a session against, and shows what the server observed during the attempt. That last part
matters because a failed handshake reaches the client as one `WebTransportError` with an
empty message, on every engine, for every cause.

## What you can test

Every endpoint runs the same echo handler behind the same Let's Encrypt certificate.
They differ in what they advertise during the handshake.

| Endpoint | Advertises |
|---|---|
| `/echo` (443/udp) | `WT_MAX_SESSIONS`, no flow-control settings |
| `:4433/echo` | the same, on a non-default port |
| `:4440/echo` | `WT_MAX_SESSIONS` and all three `WT_INITIAL_MAX_*` settings |
| `:4436/echo` | the same SETTINGS as `:4440`, older server build |
| `:4438/echo` | `WT_MAX_SESSIONS = 1` at the legacy codepoint, independent implementation |

Three more serve the same echo behind a self-signed P-256 leaf pinned by hash, so
`serverCertificateHashes` can be exercised without installing anything: `:4437`,
`:4439` whose leaf also carries `CertSign`, and `:6443` which is the same leaf on a
different port. Each publishes its base64 SHA-256 at `/hash<port>`. The leaves are
minted at boot and live ten days, inside the fourteen-day ceiling pinning allows.

## Safari and iOS

Safari is strictest about the handshake and quietest about failing it. A server that
serves Chrome and Firefox is not thereby a server that serves Safari.

It requires `WT_MAX_SESSIONS`. Omit it and `ready` never resolves and never rejects, so
keep a client-side timeout or the page hangs forever.

Send the three `WT_INITIAL_MAX_*` settings alongside it whenever it exceeds 1. The draft
does not require this, but advertising `WT_MAX_SESSIONS` above 1 switches flow control on
while all three settings default to 0, so the session opens with no credit. Other engines
tolerate that; Safari refuses before CONNECT.

Meeting both is still not sufficient. Matching every advertised value is not a guarantee
of matching behavior: two endpoints here send the same SETTINGS and transport parameters
from different generations of one Go library, and Safari accepts one while refusing the
other. What it reacts to has not been identified.

Every `WebTransportError` carries an empty message. Invalid settings, TLS rejection and
wire-level refusal are indistinguishable from the client, so put your diagnostics
server-side or you will not have any.

User-installed root CAs are ignored. TLS rejects with `certificate_unknown` even at full
trust, so a local CA that works for page loads fails here. Develop against hash pinning
or real WebPKI, nothing between. This one was measured rather than read from a source, and
WebKit's own trust path would honor a user root, which places the rejection inside
Network.framework.

Flow-control credit is never released on FIN or RESET
([319818](https://bugs.webkit.org/show_bug.cgi?id=319818)), so the connection deadlocks
at 16 MB or 7,600 streams, whichever comes first.

The floor is iOS and macOS 26.4 rather than Safari 26.4, because the operating system
version decides this and not the browser version. The wire implementation lives in Network.framework, so an OS point release can
change SETTINGS handling with nothing appearing in Safari release notes. Re-test on OS
updates, not browser updates. WKWebView is unconfirmed either way.

Safari also falls back to HTTP/2 over TCP when QUIC cannot get through, behind the same
API, which no other engine does. Streams keep working and datagrams disappear. Read
`reliability` after connecting, or pass `requireUnreliable: true` to refuse the downgrade.

The [compatibility page](https://echo.semantic-ui.com/compat) carries the same notes for
Chrome and Firefox, plus a live read of whatever runtime you open it in, and
[references](https://echo.semantic-ui.com/references) lists the source behind each one.

## Certificates

`serverCertificateHashes` replaces chain validation rather than adding to it, and the
rules are narrow:

- SHA-256 over the **leaf DER**. Hashing the SPKI is the other convention in
  circulation and it fails with no diagnostic.
- Total validity **at most 14 days**, the whole `notBefore` to `notAfter` span rather than the
  remaining time.
- ECDSA P-256, the one curve every engine must accept. RSA is excluded by the
  specification.
- Incompatible with `allowPooling`; Safari throws `NotSupportedError` if both are set.
- Certificate names are never checked on this path.

Chrome requires a *known* root rather than merely a trusted one, so mkcert and every
private CA fail with `ERR_QUIC_CERT_ROOT_NOT_KNOWN`. Pin instead, or run Chrome with
`--webtransport-developer-mode`.

## Running locally

Requires the Go toolchain named in `go.mod`, and Rust for the wtransport endpoint.

```sh
go build -o wt-lab . && ./wt-lab
```

That serves the page on `https://localhost:4434/` and WebTransport on `localhost:4433`.
`-wtcert` chooses how the certificate is trusted:

- `hash` (default) — self-signed leaf; `/hash` hands the page a SHA-256 to pin.
- `ca` — mints a local CA and signs both leaves with it. Safari will not accept this for
  WebTransport even once installed.
- `le` — loads a real chain from `-cert` and `-key`. This is what production runs.

The other two binaries want a real chain on disk:

```sh
cd legacy && go build -o wt-legacy . && ./wt-legacy -cert fullchain.pem -key privkey.pem
cd rust   && cargo build --release && ./target/release/wt-rust "" 4438
```

`wt-legacy` raises its four ports at once and publishes each pinned leaf hash into
`-hashdir`. Every process also appends what it observed per client address there, which
is what the page reads back.

## Budgets

The echo is public, so egress is capped: **1 MiB per session**, **120 seconds per
session**, **4 concurrent sessions per address**, and **2 GiB per process per day**.
Each is far above what an interop or development test needs. Counters live in memory
and reset on restart, which suits their purpose: putting a floor under the worst-case
bandwidth bill rather than resisting a determined attacker.

## Deploying

See [DEPLOY.md](DEPLOY.md).

## License

MIT. See [LICENSE](LICENSE).

---

The one-variable comparisons behind the Safari notes, with server-side captures:
[WebKit](https://echo.semantic-ui.com/exhibits/apple) ·
[quic-go and webtransport-go](https://echo.semantic-ui.com/exhibits/quic-go).
