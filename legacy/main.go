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
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/webtransport-go"
)

func main() {
	port := flag.Int("port", 4436, "WebTransport UDP port serving the real chain")
	pinnedPort := flag.Int("pinnedport", 4437, "WebTransport UDP port serving the self-signed, hash-pinned leaf")
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

	chain, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("legacy: %v", err)
	}

	hosts := splitComma(*sans)
	pinned, hash := mintLeaf(hosts)
	// the page server lives in the other binary, so the hash travels by file
	hashPath := fmt.Sprintf("%s/hash%d", *hashDir, *pinnedPort)
	if err := os.WriteFile(hashPath, []byte(hash), 0o644); err != nil {
		log.Fatalf("legacy: publishing pinned hash: %v", err)
	}

	log.Printf("wt-legacy boot wt=:%d pinned=:%d qlog=%s webtransport-go=v0.11.0 quic-go=v0.60.0", *port, *pinnedPort, *qlogDir)
	log.Printf("pinned certHash=%s published=%s sans=%v", hash, hashPath, hosts)

	// either listener dying takes the process with it, so a half-served machine
	// restarts instead of quietly answering on one port
	errs := make(chan error, 2)
	go func() { errs <- serveWT(*bindHost, *port, chain, "legacy") }()
	go func() { errs <- serveWT(*bindHost, *pinnedPort, pinned, "pinned") }()
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
		session, err := server.Upgrade(w, r)
		if err != nil {
			log.Printf("%s upgrade REFUSED: %v", tag, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf("%s session  accepted remote=%s", tag, r.RemoteAddr)
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
	h3.Handler = mux

	return server.ListenAndServe()
}

// the pinned rung's leaf: self-signed P-256, DigitalSignature and serverAuth
// only, explicitly not a CA. ten days keeps it inside the fourteen-day window
// serverCertificateHashes allows, and it is minted fresh on every boot
func mintLeaf(hosts []string) (tls.Certificate, string) {
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
		KeyUsage:              x509.KeyUsageDigitalSignature,
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
