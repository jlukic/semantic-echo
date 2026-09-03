package main

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"io/fs"
	"net/http"
)

// bump when the claims change, not when the code does. readers of a page about a
// moving target need to know how old the reading is
const contentUpdated = "08-02-2026"

type page struct {
	Title       string
	Description string
	Nav         string
	Updated     string
	Version     string
}

// A correction to a claim is worthless if a returning reader keeps the previous
// script for an hour. Asset URLs carry a version derived from the asset bytes,
// so a deploy that changes them changes the URL and is picked up at once, while
// a deploy that does not leaves the cache intact.
var assetVersion = hashAssets()

func hashAssets() string {
	sum := sha256.New()
	fs.WalkDir(assetsFS, "web/assets", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := assetsFS.ReadFile(path)
		if err != nil {
			return err
		}
		sum.Write([]byte(path))
		sum.Write(data)
		return nil
	})
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))[:10]
}

// every route this host serves as HTML. the exhibits are deliberately absent
// from the navigation: they exist so a bug report can link to a live
// reproduction, not to be browsed
var pageSpecs = map[string]struct {
	file string
	page page
}{
	"/": {"echo.html", page{
		Title:       "WebTransport Echo",
		Description: "A public WebTransport echo server and test client. Send datagrams and streams and get them straight back, and see which endpoints your own browser will establish a session against.",
		Nav:         "echo",
	}},
	"/compat": {"compat.html", page{
		Title:       "WebTransport compatibility — Safari, iOS, Chrome and Firefox",
		Description: "What each engine requires of a WebTransport server, what it silently discards, and what breaks. Safari and iOS in detail, tested live against a public echo.",
		Nav:         "compat",
	}},
	"/probe": {"probe.html", page{
		Title:       "WebTransport flow-control probe",
		Description: "Push one connection past the byte and stream counts where WebKit stops returning flow-control credit, and see where your browser stalls. A live reproduction of WebKit bug 319818.",
		Nav:         "probe",
	}},
	"/references": {"references.html", page{
		Title:       "WebTransport references and sources",
		Description: "Primary sources for every claim on this site: specifications and drafts, WebKit and Chromium bug reports, and the measurements taken against this host.",
		Nav:         "references",
	}},
	"/exhibits/apple": {"exhibit-apple.html", page{
		Title:       "Exhibit — iOS 27 refuses valid WebTransport handshakes",
		Description: "Two servers whose advertised h3 SETTINGS and QUIC transport parameters match on every value compared. Safari on iOS 27 establishes a session against one and refuses the other.",
	}},
	"/exhibits/quic-go": {"exhibit-quicgo.html", page{
		Title:       "Exhibit — quic-go and webtransport-go",
		Description: "Three reproducible findings against webtransport-go and quic-go, each testable live against a public echo.",
	}},
}

var templates = map[string]*template.Template{}

func parsePages() {
	for route, spec := range pageSpecs {
		templates[route] = template.Must(template.ParseFS(pagesFS,
			"web/pages/layout.html", "web/pages/"+spec.file))
	}
}

func renderPage(w http.ResponseWriter, route string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := pageSpecs[route].page
	data.Updated = contentUpdated
	data.Version = assetVersion
	if err := templates[route].ExecuteTemplate(w, "layout", data); err != nil {
		// the response is already partly written by the time a template can
		// fail, so there is nothing useful to say to the client
		return
	}
}
