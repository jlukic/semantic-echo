// wt-legacy: the validated-era rung, and its pinned A/B twin.
//
// webtransport-go v0.11.0 on quic-go v0.60.0, the pairing a client was last
// seen to accept. Pinning the library pins the whole wire image — QUIC
// transport parameters as well as h3 SETTINGS — which reproducing the SETTINGS
// alone on a newer core cannot do.
//
// Two listeners, one serveWT: :4436 serves the real WebPKI chain, :4437 serves
// a self-signed leaf the page pins by hash. They share every line of setup, so
// the certificate is the only variable between them and a client that binds one
// while refusing the other has named its blocker.
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
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/webtransport-go"
)

func main() {
	port := flag.Int("port", 4436, "WebTransport UDP port serving the real chain")
	pinnedPort := flag.Int("pinnedport", 4437, "WebTransport UDP port serving the self-signed, hash-pinned leaf")
	certSignPort := flag.Int("certsignport", 4439, "WebTransport UDP port serving a pinned leaf that also carries CertSign")
	altPort := flag.Int("altport", 6443, "WebTransport UDP port serving the same pinned leaf, so the port number is the only variable")
	certFile := flag.String("cert", "/cert.pem", "fullchain PEM path")
	keyFile := flag.String("key", "/key.pem", "private key PEM path")
	qlogDir := flag.String("qlog", "qlog-legacy", "qlog output directory")
	hashDir := flag.String("hashdir", "/tmp", "directory to publish the pinned leaf hash into")
	sans := flag.String("san", "echo.semantic-ui.com,localhost,127.0.0.1,::1", "comma-joined SANs for the self-signed leaf")
	bindHost := flag.String("bind", "", "UDP bind host (fly-global-services on Fly; empty = all interfaces)")
	flag.Parse()

	if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
		log.Fatal(err)
	}
	os.Setenv("QLOGDIR", *qlogDir)

	watch = newObserver(*hashDir, "legacy")

	chain, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("legacy: %v", err)
	}

	hosts := splitComma(*sans)
	pinned, pinnedHash := mintLeaf(hosts, x509.KeyUsageDigitalSignature)
	// the same leaf shape the production lane mints: CertSign set on something
	// that is still explicitly not a CA
	certSign, certSignHash := mintLeaf(hosts, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign)

	// the page server lives in the other binary, so hashes travel by file
	publish := func(port int, hash string) {
		if err := os.WriteFile(fmt.Sprintf("%s/hash%d", *hashDir, port), []byte(hash), 0o644); err != nil {
			log.Fatalf("legacy: publishing hash for :%d: %v", port, err)
		}
	}
	publish(*pinnedPort, pinnedHash)
	publish(*certSignPort, certSignHash)
	// altport serves the very same certificate object as pinnedPort, so nothing
	// but the port number separates the two
	publish(*altPort, pinnedHash)

	log.Printf("wt-legacy boot wt=:%d pinned=:%d certsign=:%d alt=:%d qlog=%s webtransport-go=v0.11.0 quic-go=v0.60.0",
		*port, *pinnedPort, *certSignPort, *altPort, *qlogDir)
	// int() is load-bearing: x509.KeyUsage is a Stringer, so %x on the bare
	// value hex-encodes its name instead of the bit field
	log.Printf("pinned   certHash=%s keyUsage=0x%02x isCA=false sans=%v", pinnedHash, int(x509.KeyUsageDigitalSignature), hosts)
	log.Printf("certsign certHash=%s keyUsage=0x%02x isCA=false", certSignHash, int(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign))
	log.Printf("altport  :%d serves the pinned leaf unchanged", *altPort)

	// either listener dying takes the process with it, so a half-served machine
	// restarts instead of quietly answering on some ports
	errs := make(chan error, 4)
	go func() { errs <- serveWT(*bindHost, *port, chain, "legacy") }()
	go func() { errs <- serveWT(*bindHost, *pinnedPort, pinned, "pinned") }()
	go func() { errs <- serveWT(*bindHost, *certSignPort, certSign, "certsign") }()
	go func() { errs <- serveWT(*bindHost, *altPort, pinned, "altport") }()
	log.Fatal(<-errs)
}

func serveWT(bindHost string, port int, cert tls.Certificate, tag string) error {
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
	tlsConf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("%s hello    sni=%q alpn=%v ciphers=%d curves=%v", tag, hello.ServerName, hello.SupportedProtos, len(hello.CipherSuites), hello.SupportedCurves)
		return nil, nil
	}

	h3 := &http3.Server{
		Addr:      fmt.Sprintf("%s:%d", bindHost, port),
		TLSConfig: tlsConf,
		QUICConfig: &quic.Config{
			Tracer: qlog.DefaultConnectionTracer,
		},
		// fires once the QUIC handshake completes and before SETTINGS go out, so
		// a client that arrives and then leaves without asking for a session is
		// still visible here
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			address := addressOf(conn.RemoteAddr().String())
			watch.record(address, port, kindQUIC, "")
			go func() {
				<-conn.Context().Done()
				watch.record(address, port, kindClosed, closeReason(conn.Context()))
			}()
			return ctx
		},
	}
	// v0.11.0 leaves this to the caller — v0.12 moved it inside init(). without
	// it the server advertises no WebTransport SETTINGS at all and every
	// upgrade fails, so it is stock usage rather than a customisation
	webtransport.ConfigureHTTP3Server(h3)

	server := &webtransport.Server{
		H3:          h3,
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s connect  origin=%q wt-available-protocols=%q", tag, r.Header.Get("Origin"), r.Header.Get("Wt-Available-Protocols"))
		address := addressOf(r.RemoteAddr)
		watch.record(address, port, kindConnect, "origin="+r.Header.Get("Origin"))
		if ok, why := limits.acquire(address); !ok {
			log.Printf("%s upgrade declined remote=%s (%s)", tag, r.RemoteAddr, why)
			watch.record(address, port, kindDeclined, why)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		session, err := server.Upgrade(w, r)
		if err != nil {
			limits.release(address)
			log.Printf("%s upgrade REFUSED: %v", tag, err)
			watch.record(address, port, kindRefused, err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf("%s session  accepted remote=%s", tag, r.RemoteAddr)
		watch.record(address, port, kindSession, "")
		serveEcho(session, address)
	})
	h3.Handler = mux

	return server.ListenAndServe()
}

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

func (b *budgets) acquire(address string) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	if b.echoed >= dailyEgressCeiling {
		return false, "daily egress ceiling"
	}
	if b.sessions[address] >= perAddressSessions {
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
func serveEcho(session *webtransport.Session, address string) {
	ctx, cancel := context.WithTimeout(context.Background(), sessionLifetime)
	stopped := make(chan string, 1)
	stop := func(why string) {
		select {
		case stopped <- why:
		default:
		}
	}

	var echoed atomic.Int64
	spend := func(n int) bool {
		if echoed.Add(int64(n)) > sessionEchoBudget {
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

// a pinned rung's leaf: self-signed P-256 with serverAuth, explicitly not a CA,
// and whatever KeyUsage the caller wants to put on trial. ten days keeps it
// inside the fourteen-day window serverCertificateHashes allows, and it is
// minted fresh on every boot
func mintLeaf(hosts []string, usage x509.KeyUsage) (tls.Certificate, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wt-pinned"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, base64.StdEncoding.EncodeToString(sum[:])
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
