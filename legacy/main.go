// wt-legacy: the validated-era rung.
//
// webtransport-go v0.11.0 on quic-go v0.60.0, the pairing a client was last
// seen to accept. Pinning the library pins the whole wire image — QUIC
// transport parameters as well as h3 SETTINGS — which reproducing the SETTINGS
// alone on a newer core cannot do. Stock config, same echo shape as the v0.12
// server next door, so a bind here against a refusal there isolates the
// difference to what changed between the two releases.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/webtransport-go"
)

func main() {
	port := flag.Int("port", 4436, "WebTransport UDP port")
	certFile := flag.String("cert", "/cert.pem", "fullchain PEM path")
	keyFile := flag.String("key", "/key.pem", "private key PEM path")
	qlogDir := flag.String("qlog", "qlog-legacy", "qlog output directory")
	bindHost := flag.String("bind", "", "UDP bind host (fly-global-services on Fly; empty = all interfaces)")
	flag.Parse()

	if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
		log.Fatal(err)
	}
	os.Setenv("QLOGDIR", *qlogDir)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("legacy: %v", err)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
	tlsConf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("legacy hello    sni=%q alpn=%v ciphers=%d curves=%v", hello.ServerName, hello.SupportedProtos, len(hello.CipherSuites), hello.SupportedCurves)
		return nil, nil
	}

	h3 := &http3.Server{
		Addr:      fmt.Sprintf("%s:%d", *bindHost, *port),
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
		log.Printf("legacy connect  origin=%q wt-available-protocols=%q", r.Header.Get("Origin"), r.Header.Get("Wt-Available-Protocols"))
		session, err := server.Upgrade(w, r)
		if err != nil {
			log.Printf("legacy upgrade REFUSED: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf("legacy session  accepted remote=%s", r.RemoteAddr)
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

	log.Printf("wt-legacy boot wt=:%d qlog=%s webtransport-go=v0.11.0 quic-go=v0.60.0", *port, *qlogDir)
	log.Fatal(server.ListenAndServe())
}
