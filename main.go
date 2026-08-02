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
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/webtransport-go"
)

//go:embed page.html
var pageHTML []byte

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
	flag.Parse()

	if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
		log.Fatal(err)
	}
	os.Setenv("QLOGDIR", *qlogDir)

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
	startWT := func(port int) {
		server := &webtransport.Server{
			H3: &http3.Server{
				Addr:      fmt.Sprintf("%s:%d", *bindHost, port),
				TLSConfig: tlsConf,
				QUICConfig: &quic.Config{
					Tracer: qlog.DefaultConnectionTracer,
				},
			},
			// the page and the endpoint are always different origins
			CheckOrigin: func(*http.Request) bool { return true },
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
			log.Printf("connect  port=%d origin=%q wt-available-protocols=%q", port, r.Header.Get("Origin"), r.Header.Get("Wt-Available-Protocols"))
			session, err := server.Upgrade(w, r)
			if err != nil {
				log.Printf("upgrade REFUSED: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			log.Printf("session  accepted port=%d remote=%s", port, r.RemoteAddr)
			ctx := context.Background()
			go func() {
				for {
					data, err := session.ReceiveDatagram(ctx)
					if err != nil {
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
					go io.Copy(stream, stream)
				}
			}()
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

	page := &http.Server{
		Addr:      fmt.Sprintf(":%d", *pagePort),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pageCert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/hash":
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, hash)
			default:
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
				w.Header().Set("Content-Type", "text/html")
				w.Write(pageHTML)
			}
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

	log.Printf("wt-lab boot wt=:%d,:443 page=:%d qlog=%s", *port, *pagePort, *qlogDir)
	log.Printf("certHash=%s notAfter=%s sans=%v keyUsage=DigitalSignature isCA=false", hash, time.Now().Add(10*24*time.Hour).Format(time.RFC3339), hosts)
	log.Printf("one-time iPad setup: http://<host-lan-ip>:%d/ downloads the CA profile — install in Settings, then enable full trust in General > About > Certificate Trust Settings", *pagePort+1)
	log.Printf("tap: https://<host-lan-ip>:%d/", *pagePort)

	startWT(*port)
	// clients that only ever try the default port are a live hypothesis, so
	// the endpoint answers on 443/udp too
	startWT(443)
	log.Fatal(page.ListenAndServeTLS("", ""))
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
