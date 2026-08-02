# echo.semantic-ui.com

A standing WebTransport interop smoke. It answers one question: does a given
browser build establish a WebTransport session against a stock server over a
real WebPKI certificate, with no certificate pinning anywhere in the path?

Everything here is deliberately vanilla. The server is
[webtransport-go](https://github.com/quic-go/webtransport-go) v0.12.0 with no
`Config`, no `AdditionalSettings`, and no vendored patches — whatever SETTINGS
the library's defaults produce is the wire under test. When a client fails
against this, the client is the variable.

## Taps

| | |
|---|---|
| Probe page | <https://echo.semantic-ui.com/> |
| WebTransport endpoint | `https://echo.semantic-ui.com:4433/echo` |
| …also on the default port | `https://echo.semantic-ui.com/echo` (443/udp) |
| Certificate | Let's Encrypt, served on both ports, no `serverCertificateHashes` |

The page sweeps `WebTransport` constructor options via query params, one preset
per link, and logs every stage with millisecond stamps. Presets cover
`requireUnreliable` on and off, a non-empty `protocols` list, and tight
anticipated-stream counts. `?url=` retargets it at another server, which makes
the page a portable client harness rather than a fixture for this host alone.

The endpoint echoes datagrams and bidirectional streams straight back, and
answers identically on 4433/udp and 443/udp — a client that dials only the
default port still finds it. Each connection writes a qlog to `/tmp/qlog` on
the machine.

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

## Deployment

Fly app `semanticui-echo`, region `iad`, on a dedicated IPv4. UDP needs a
dedicated address and the external port must equal the internal one — Fly does
not rewrite UDP destination ports. There is no IPv6 address on this app on
purpose: Fly routes no public UDP over v6.

Port 443 maps to the app's 4434 as raw TCP, so the page needs no port in its
URL while the app still owns the TLS handshake.

The machine auto-stops when idle. Any TCP request to port 443 wakes it, so
loading the page before tapping is the normal entry path.

```sh
flyctl deploy
```

The chain reaches the machine as secrets, which the container writes to disk at
boot:

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
