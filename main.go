// wt-lab: a WebTransport interop smoke, deliberately vanilla.
//
// A stock webtransport-go v0.12.0 server with NOTHING customised on the wire:
// no Config, no AdditionalSettings, no vendored patches. Whatever SETTINGS the
// library's defaults produce is the point, so a client that fails against this
// is the variable.
//
// Riders that do not touch the WT wire: a TCP https page server on -pageport
// serving the constructor-sweep probe page, and qlog written to files per
// connection under -qlog.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/webtransport-go"
)

//go:embed web/pages/*.html
var pagesFS embed.FS

//go:embed web/assets
var assetsFS embed.FS

// what the page reports about this listener, and what every listener writes
// down about the clients that reach it
var watch *observer

// the /auth/ fixture credentials. deliberately trivial and deliberately public:
// the route exists to reproduce a Basic-auth browsing context, not to protect
// anything, and the same page is served unauthenticated at /
const (
	authUser = "retro"
	authPass = "retro"
)

// egress is the only unbounded axis on a public echo, so a session carries a
// byte budget and a deadline, one address may hold only a few at once, and the
// process stops echoing entirely past a daily ceiling. sized far above honest
// use: the heaviest exhibit moves well under 10 KiB
const (
	sessionEchoBudget  = 1 << 20
	sessionLifetime    = 120 * time.Second
	perAddressSessions = 4
	dailyEgressCeiling = 2 << 30
)

// the flow-control probe's budget. WebKit 319818 deadlocks a connection near 16 MiB of
// cumulative stream data or 7,600 streams because credit is never returned on FIN, so a
// probe that can reach the line needs a session budget past it and time to get there.
// sized to cross both lines once with margin, on one port, one session per address
const (
	probeEchoBudget = 64 << 20
	probeLifetime   = 10 * time.Minute
	probeSessions   = 1
)

type budgets struct {
	mu       sync.Mutex
	sessions map[string]int
	echoed   int64
	windowAt time.Time
	warned   bool
}

var limits = &budgets{sessions: map[string]int{}, windowAt: time.Now()}

// the window restarts 24h after it opened, which is all a bill guard needs
func (b *budgets) roll() {
	if time.Since(b.windowAt) >= 24*time.Hour {
		b.echoed = 0
		b.windowAt = time.Now()
		b.warned = false
	}
}

func (b *budgets) acquire(address string, probe bool) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	if b.echoed >= dailyEgressCeiling {
		return false, "daily egress ceiling"
	}
	cap := perAddressSessions
	if probe {
		cap = probeSessions
	}
	if b.sessions[address] >= cap {
		return false, "per-address session cap"
	}
	b.sessions[address]++
	return true, ""
}

func (b *budgets) release(address string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions[address] <= 1 {
		delete(b.sessions, address)
		return
	}
	b.sessions[address]--
}

// spend reports whether the process may keep echoing once n more bytes are counted
func (b *budgets) spend(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	b.echoed += int64(n)
	if b.echoed < dailyEgressCeiling {
		return true
	}
	if !b.warned {
		b.warned = true
		log.Printf("EGRESS CEILING: %d bytes echoed in 24h, refusing new sessions and halting echo", b.echoed)
	}
	return false
}

func addressOf(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return normalizeAddress(remote)
	}
	return normalizeAddress(host)
}

// io.Copy with a budget attached, so a public echo cannot become free bandwidth
func echoStream(stream io.ReadWriter, spend func(int) bool) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			if !spend(n) {
				return
			}
			if _, err := stream.Write(buffer[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// the echo loops, bounded. both directions share one session budget, and
// whichever limit bites first closes the session with a readable reason
func serveEcho(session *webtransport.Session, address string, budget int64, lifetime time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	stopped := make(chan string, 1)
	stop := func(why string) {
		select {
		case stopped <- why:
		default:
		}
	}

	var echoed atomic.Int64
	spend := func(n int) bool {
		if echoed.Add(int64(n)) > budget {
			stop("echo budget reached")
			return false
		}
		if !limits.spend(n) {
			stop("daily egress ceiling reached")
			return false
		}
		return true
	}

	go func() {
		defer limits.release(address)
		defer cancel()
		select {
		case why := <-stopped:
			session.CloseWithError(0, why)
		case <-ctx.Done():
			session.CloseWithError(0, "session lifetime reached")
		case <-session.Context().Done():
			// the peer left on its own, so free the slot immediately rather than
			// holding it for the rest of the lifetime window
		}
	}()

	go func() {
		for {
			data, err := session.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if !spend(len(data)) {
				return
			}
			session.SendDatagram(data)
		}
	}()
	go func() {
		for {
			stream, err := session.AcceptStream(ctx)
			if err != nil {
				return
			}
			go echoStream(stream, spend)
		}
	}()
}

func newTemplate(cn string, days int) x509.Certificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
}

// the WT cert: self-signed, maximally conventional leaf — DigitalSignature
// only, serverAuth, explicitly not a CA. unlike the lane's mint (which
// carries CertSign) so it doubles as a cert-shape control. verified by hash
// pinning, so names are irrelevant to the WT path.
func mintWTCert(hosts []string) (tls.Certificate, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := newTemplate("wt-lab", 10)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	addHosts(&template, hosts)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(der)
	hash := base64.StdEncoding.EncodeToString(sum[:])
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hash
}

// the CA persists across restarts — the device's installed profile must
// keep matching, so mint once and reload from disk ever after
func loadOrMintCA() (*ecdsa.PrivateKey, []byte) {
	keyPEM, keyErr := os.ReadFile("ca.key")
	certPEM, certErr := os.ReadFile("ca.pem")
	if keyErr == nil && certErr == nil {
		keyBlock, _ := pem.Decode(keyPEM)
		certBlock, _ := pem.Decode(certPEM)
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		return key, certBlock.Bytes
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	caTemplate := newTemplate("wt-lab local CA", 30)
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	os.WriteFile("ca.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	os.WriteFile("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	return caKey, caDER
}

// the page cert chain: a local CA the iPad installs as a trusted profile
// once, plus a page leaf signed by it. iOS beta's proceed-anyway flow does
// not stick, so exception-based access is a dead end — trust must be real.
func mintPageChain(hosts []string) (tls.Certificate, []byte) {
	caKey, caDER := loadOrMintCA()
	caCert, _ := x509.ParseCertificate(caDER)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := newTemplate("wt-lab page", 10)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	addHosts(&template, hosts)
	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, caDER
}

func addHosts(template *x509.Certificate, hosts []string) {
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
}

func main() {
	port := flag.Int("port", 4433, "WebTransport UDP port")
	pagePort := flag.Int("pageport", 4434, "probe page TCP https port")
	qlogDir := flag.String("qlog", "qlog", "qlog output directory")
	sans := flag.String("san", "localhost,127.0.0.1,::1", "comma-joined cert SANs (hash path ignores names; these are for the page)")
	flag.String("wtcert", "hash", "WT cert mode: hash (self-signed, pin by hash), ca (local CA), or le (real chain from -cert/-key)")
	certFile := flag.String("cert", "", "fullchain PEM path (le mode)")
	keyFile := flag.String("key", "", "private key PEM path (le mode)")
	bindHost := flag.String("bind", "", "UDP bind host (fly-global-services on Fly; empty = all interfaces)")
	hashDir := flag.String("hashdir", "/tmp", "directory sibling listeners publish their leaf hashes into")
	trioPort := flag.Int("trioport", 4440, "WebTransport UDP port that also sends the flow-control trio")
	probePort := flag.Int("probeport", 4441, "WebTransport UDP port for the flow-control probe (a 64 MiB session budget, one session per address)")
	flag.Parse()

	if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
		log.Fatal(err)
	}
	os.Setenv("QLOGDIR", *qlogDir)

	parsePages()
	watch = newObserver(*hashDir, "lab")

	wtCertMode := flag.Lookup("wtcert").Value.String()
	hosts := splitComma(*sans)
	cert, hash := mintWTCert(hosts)
	pageCert, caDER := mintPageChain(hosts)
	switch wtCertMode {
	case "ca":
		// serve the CA-signed page chain on the WT port too: the device
		// trusts the CA, so a ?nohash=1 tap exercises pure PKI validation —
		// the one cert path the hash-pinned lane can never test. the pinned
		// hash tracks the served leaf so hash presets stay valid in this mode
		cert = pageCert
		sum := sha256.Sum256(pageCert.Certificate[0])
		hash = base64.StdEncoding.EncodeToString(sum[:])
	case "le":
		// a real WebPKI chain on both ports: no profiles, no pinning, any
		// device. /hash goes empty so the page runs pure-PKI taps by default
		// (the chain outlives the 14-day pinning window, so pinning is off
		// the table here by spec anyway)
		loaded, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("le mode: %v", err)
		}
		cert = loaded
		pageCert = loaded
		hash = ""
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
	tlsConf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("hello    sni=%q alpn=%v ciphers=%d curves=%v", hello.ServerName, hello.SupportedProtos, len(hello.CipherSuites), hello.SupportedCurves)
		return nil, nil
	}

	// one server and one mux per port. Upgrade is a method on a specific
	// webtransport.Server, so the two ports cannot share a handler — the
	// default mux would route both to whichever server registered last
	startWT := func(port int, config *webtransport.Config, probe bool) {
		budget, lifetime := int64(sessionEchoBudget), sessionLifetime
		if probe {
			budget, lifetime = probeEchoBudget, probeLifetime
		}
		server := &webtransport.Server{
			H3: &http3.Server{
				Addr:      fmt.Sprintf("%s:%d", *bindHost, port),
				TLSConfig: tlsConf,
				QUICConfig: &quic.Config{
					Tracer: qlog.DefaultConnectionTracer,
				},
				// fires once the QUIC handshake completes and before this server
				// sends its SETTINGS. it is the only place to learn that a client
				// arrived and then left without ever asking for a session, which
				// is what a refusal looks like from this side
				ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
					address := addressOf(conn.RemoteAddr().String())
					watch.record(address, port, kindQUIC, "")
					go func() {
						<-conn.Context().Done()
						watch.record(address, port, kindClosed, closeReason(conn.Context()))
					}()
					return ctx
				},
			},
			// nil leaves the library's defaults alone, which is the control
			Config: config,
			// the page and the endpoint are always different origins
			CheckOrigin: func(*http.Request) bool { return true },
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
			log.Printf("connect  port=%d origin=%q wt-available-protocols=%q", port, r.Header.Get("Origin"), r.Header.Get("Wt-Available-Protocols"))
			address := addressOf(r.RemoteAddr)
			watch.record(address, port, kindConnect, "origin="+r.Header.Get("Origin"))
			if ok, why := limits.acquire(address, probe); !ok {
				log.Printf("upgrade declined port=%d remote=%s (%s)", port, r.RemoteAddr, why)
				watch.record(address, port, kindDeclined, why)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			session, err := server.Upgrade(w, r)
			if err != nil {
				limits.release(address)
				log.Printf("upgrade REFUSED: %v", err)
				watch.record(address, port, kindRefused, err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			log.Printf("session  accepted port=%d remote=%s", port, r.RemoteAddr)
			watch.record(address, port, kindSession, "")
			serveEcho(session, address, budget, lifetime)
		})
		server.H3.Handler = mux

		go func() {
			// one port failing to bind must not take the other down: 443 needs
			// root, which the container has and a dev machine usually does not
			if err := server.ListenAndServe(); err != nil {
				log.Printf("wt :%d stopped: %v", port, err)
			}
		}()
	}

	// embedded under web/, served from /assets/
	assetRoot, err := fs.Sub(assetsFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	assets := http.FileServer(http.FS(assetRoot))

	page := &http.Server{
		Addr:      fmt.Sprintf(":%d", *pagePort),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pageCert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// /auth/ serves the echo page from behind Basic auth, reproducing a
			// Basic-auth browsing context. the /hash and /observed endpoints stay
			// open so the page's own fetches keep working from here, and nothing
			// behind this guards anything
			if r.URL.Path == "/auth" || strings.HasPrefix(r.URL.Path, "/auth/") {
				user, pass, ok := r.BasicAuth()
				if !ok || user != authUser || pass != authPass {
					w.Header().Set("WWW-Authenticate", `Basic realm="echo"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				renderPage(w, "/")
				return
			}

			if strings.HasPrefix(r.URL.Path, "/assets/") {
				// a versioned URL names one immutable body, so it can be held
				// forever. font files are named per face and are referenced from
				// inside a stylesheet that cannot carry the version, so they are
				// held on the same terms: a different face would be a different
				// file. anything else might be anything, and is held briefly
				immutable := r.URL.Query().Get("v") != "" ||
					strings.HasSuffix(r.URL.Path, ".woff2")
				if immutable {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "public, max-age=300")
				}
				assets.ServeHTTP(w, r)
				return
			}

			switch r.URL.Path {
			case "/hash":
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, hash)
				return
			case "/observed":
				// what every listener here saw from this address just now. the
				// window is short because the page asks immediately after an
				// attempt and stale rows would read as this one
				address := clientAddress(r)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				json.NewEncoder(w).Encode(map[string]any{
					// echoed back so the page can say which address it asked
					// about, and so a mismatch is legible rather than silent
					"address": address,
					"events":  readObservations(*hashDir, address, 30*time.Second),
				})
				return
			}

			// /hash<port> hands back the leaf hash a sibling listener published
			// to disk, so the page can pin a rung this process does not serve
			if suffix, ok := strings.CutPrefix(r.URL.Path, "/hash"); ok {
				if p, err := strconv.ParseUint(suffix, 10, 16); err == nil {
					// rebuilt from the parsed number, never from the raw path
					published, _ := os.ReadFile(fmt.Sprintf("%s/hash%d", *hashDir, p))
					w.Header().Set("Content-Type", "text/plain")
					w.Write(published)
					return
				}
			}

			route := strings.TrimSuffix(r.URL.Path, "/")
			if route == "" {
				route = "/"
			}
			if _, ok := pageSpecs[route]; !ok {
				route = "/"
			}
			renderPage(w, route)
		}),
	}

	// plain-http CA download: the https page is unreachable until the CA is
	// trusted, so the profile has to come in over a door with no cert at all
	caServer := &http.Server{
		Addr: fmt.Sprintf(":%d", *pagePort+1),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Header().Set("Content-Disposition", `attachment; filename="wt-lab-ca.crt"`)
			w.Write(caDER)
		}),
	}
	go func() { log.Fatal(caServer.ListenAndServe()) }()

	log.Printf("wt-lab boot wt=:%d,:443 trio=:%d probe=:%d page=:%d qlog=%s", *port, *trioPort, *probePort, *pagePort, *qlogDir)
	log.Printf("certHash=%s notAfter=%s sans=%v keyUsage=DigitalSignature isCA=false", hash, time.Now().Add(10*24*time.Hour).Format(time.RFC3339), hosts)
	log.Printf("one-time iPad setup: http://<host-lan-ip>:%d/ downloads the CA profile — install in Settings, then enable full trust in General > About > Certificate Trust Settings", *pagePort+1)
	log.Printf("tap: https://<host-lan-ip>:%d/", *pagePort)

	startWT(*port, nil, false)
	// clients that only ever try the default port are a live hypothesis, so
	// the endpoint answers on 443/udp too
	startWT(443, nil, false)
	// the flow-control probe: the same echo with a budget past WebKit 319818's lines
	startWT(*probePort, nil, true)
	// v0.12 does not send the WebTransport flow-control trio unless asked. these
	// are the values v0.11 hardcodes, so this port differs from the v0.11 rung
	// by library version and nothing else. 1<<60 is exactly where the stream
	// limits clip, so they arrive on the wire unrounded
	startWT(*trioPort, &webtransport.Config{
		MaxIncomingStreams:    1 << 60,
		MaxIncomingUniStreams: 1 << 60,
		MaxIncomingData:       1 << 60,
	}, false)
	// wrapped so a PROXY header, when Fly is configured to send one, restores the
	// client's own address. without it the page server only ever sees the proxy,
	// and the observation lookup cannot match a session to the page that asked
	// about it
	pageListener, err := net.Listen("tcp", page.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(page.ServeTLS(proxyListener{pageListener}, "", ""))
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
