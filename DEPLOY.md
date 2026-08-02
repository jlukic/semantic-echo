# Deploying

Deployed to [Fly](https://fly.io) as app `semanticui-echo`, region `iad`, on a dedicated
IPv4 address.

## Run exactly one machine

Fly routes UDP per packet, so a second instance can split one QUIC connection across two
servers and produce handshake failures indistinguishable from the client bugs this host
exists to diagnose. `flyctl deploy` adds a second machine for high availability by
default:

```sh
flyctl deploy && flyctl scale count 1
```

## UDP constraints

- UDP needs a dedicated address, and each external port must equal its internal port,
  because Fly does not rewrite UDP destination ports.
- The app has no IPv6 address on purpose: Fly routes no public UDP over v6.
- Port 443 maps to the app's 4434 as raw TCP, so the page needs no port in its URL while
  the app still owns the TLS handshake.
- The machine auto-stops when idle and a TCP request to port 443 wakes it. A UDP packet
  alone will not start a stopped machine, so loading the page before dialing is the
  normal entry path.

## Certificates

The chain reaches the machine as secrets, which `start.sh` writes to disk before
launching all three servers:

```sh
flyctl secrets set -a semanticui-echo \
  WT_CERT_PEM="$(cat fullchain.pem)" WT_KEY_PEM="$(cat privkey.pem)"
```

Let's Encrypt certificates expire after 90 days. Renewal is DNS-01 against
`_acme-challenge.echo.semantic-ui.com`, since ports 80 and 443 are not served for HTTP:

```sh
certbot certonly --manual --preferred-challenges dns -d echo.semantic-ui.com
```

Add the TXT record it prints, let it validate, then push the new `fullchain.pem` and
`privkey.pem` as secrets and redeploy.

## Vendored assets

The page is self-contained: no request leaves the app's own origin, because a tool for
diagnosing broken networks cannot depend on a second host being reachable. The Semantic
UI stylesheet, the Lucide icon masks and the Lato faces under `web/assets/` are vendored
copies. Refresh them with:

```sh
scripts/vendor-assets.sh
```
